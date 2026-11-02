#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================================
# tools/broker/broker.py —— 受管服务发号 API（与 vpn-server 同机部署）
#
# 职责（docs/受管服务与试用授权方案.md）：
#   GET /trial/register?fp=&os=&cpu=&ram=&mac=   申请/换发试用（3 天 / 2GB）
#   GET /trial/status?fp=                        查询凭据状态（客户端每次启动同步）
#   GET /svc/server-list.ini(.sig)               服务器列表（静态签名文件）
#
# 响应可信性：个人凭据 INI 由 service.key 的 Ed25519 签名，放在
# `X-Service-Signature` 响应头（base64），客户端验签通过才可使用。
#
# 所有 SQL 在 db.py；签名复用 scripts/sign-update-policy.py 的密钥格式
# （PKCS8 Ed25519 PEM，gen-keys 用它生成到独立目录即成 service.key）。
# ============================================================================

import argparse
import base64
import datetime
import hashlib
import os
import secrets
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import db   # noqa: E402  —— SQL 只在 db.py

from cryptography.hazmat.primitives import serialization          # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (   # noqa: E402
    Ed25519PrivateKey,
)

# ---------------------------------------------------------------- 配置 ----

BIND = os.environ.get("SERVICE_BIND", "127.0.0.1")
PORT = int(os.environ.get("SERVICE_PORT", "18082"))
KEY_PATH = os.environ.get("SERVICE_KEY", "")          # service.key（PKCS8 PEM）
LIST_DIR = os.environ.get("SERVICE_LIST_DIR", "")     # server-list.ini 所在目录
TOKENS_FILE = os.environ.get("SERVICE_TOKENS_FILE", "")   # register_tokens.txt
IP_LIMIT = int(os.environ.get("SERVICE_IP_LIMIT", "3"))   # 同 IP 24h 最多申请数
TRIAL_DAYS = int(os.environ.get("SERVICE_TRIAL_DAYS", "3"))
TRIAL_QUOTA = int(os.environ.get("SERVICE_TRIAL_QUOTA", str(2 * 1024 ** 3)))


def log(msg: str) -> None:
    print(f"[{datetime.datetime.now().isoformat(timespec='seconds')}] {msg}",
          flush=True)


# ---------------------------------------------------------------- 签名 ----

def load_private_key(path: str) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(open(path, "rb").read(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit(f"{path} 不是 Ed25519 私钥")
    return key


def sign_b64(key: Ed25519PrivateKey, data: bytes) -> str:
    return base64.b64encode(key.sign(data)).decode("ascii")


# ---------------------------------------------------------------- 令牌 ----

def append_token_to_server(tokens_path: str, token: str) -> None:
    """追加进现有 register_tokens.txt（与 server --gen-token 同 flock 语义）。"""
    if not tokens_path:
        return
    os.makedirs(os.path.dirname(os.path.abspath(tokens_path)), exist_ok=True)
    lock = None
    try:
        import fcntl   # POSIX；Windows 开发环境无此模块，跳过锁
        lock = open(tokens_path + ".lock", "w")
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
    except (ImportError, OSError):
        lock = None
    try:
        with open(tokens_path, "a", encoding="utf-8") as f:
            f.write(token + "\n")
    finally:
        if lock is not None:
            import fcntl
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            lock.close()


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


# ---------------------------------------------------------------- 凭据 ----

def render_credentials(row, token: str = "") -> str:
    """个人凭据 INI。token 仅注册响应携带；status 接口不带（库里只有哈希）。"""
    lines = [
        "# ScholarVPN service credentials",
        f"# generated: {datetime.datetime.now().isoformat(timespec='seconds')}",
        f"fp          = {row['fp']}",
        f"client_id   = {row['client_id']}",
    ]
    if token:
        lines.append(f"token       = {token}")
    lines += [
        f"status      = {row['status']}",
        f"expire_at   = {row['expire_at']}",
        f"quota_bytes = {row['quota_bytes']}",
        f"used_bytes  = {row['used_bytes']}",
        f"issued      = {int(time.time())}",
    ]
    # 服务器为该用户选定一种限制并算好剩余量（客户端只收这一种）：
    # 比较两个限制的已用比例，更先触达的那个被选中下发。
    kind = "none"
    remaining = 0
    now = int(time.time())
    exp_ratio = None
    qta_ratio = None
    if row["expire_at"]:
        span = max(1, row["expire_at"] - row["created_at"])
        exp_ratio = max(0.0, min(1.0, (now - row["created_at"]) / span))
    if row["quota_bytes"]:
        qta_ratio = max(0.0, min(1.0, row["used_bytes"] / row["quota_bytes"]))
    if exp_ratio is not None and (qta_ratio is None or exp_ratio >= qta_ratio):
        kind = "days"
        remaining = max(0, (row["expire_at"] - now + 86399) // 86400)
    elif qta_ratio is not None:
        kind = "bytes"
        remaining = max(0, row["quota_bytes"] - row["used_bytes"])
    lines += [
        f"limit_kind  = {kind}",
        f"remaining   = {remaining}",
    ]
    return "\n".join(lines) + "\n"


def new_client_id() -> str:
    return "trial-" + secrets.token_hex(4)


def new_token() -> str:
    return secrets.token_hex(32)


# ---------------------------------------------------------------- HTTP ----

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ScholarVPN-Broker/1.0"
    key: Ed25519PrivateKey = None       # 由 serve() 注入
    db_path: str = None

    # ---- 基础设施 ----
    def log_message(self, fmt, *args):   # 默认日志太吵且带查询串
        pass

    def _send(self, status: int, body: bytes, ctype: str = "text/plain; charset=utf-8",
              extra: dict = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_signed(self, status: int, text: str) -> None:
        body = text.encode("utf-8")
        self._send(status, body, extra={
            "X-Service-Signature": sign_b64(self.key, body)})

    def _error(self, status: int, msg: str) -> None:
        self._send(status, f'{{"error":"{msg}"}}\n'.encode("utf-8"),
                   "application/json")

    # ---- 业务 ----
    def do_GET(self) -> None:
        parts = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parts.query)
        peer_ip = self.client_address[0]

        if parts.path == "/trial/register":
            self._handle_register(qs, peer_ip)
        elif parts.path == "/trial/status":
            self._handle_status(qs, peer_ip)
        elif parts.path.startswith("/svc/"):
            self._handle_static(parts.path, qs)
        else:
            self._error(404, "not found")

    def _handle_register(self, qs: dict, peer_ip: str) -> None:
        fp = (qs.get("fp", [""])[0] or "").strip().lower()
        if len(fp) != 64 or any(c not in "0123456789abcdef" for c in fp):
            self._error(400, "invalid fp")
            return
        # 设备品牌/型号（2026-11-02）：仅后台展示核对，不参与指纹与鉴权
        brand = (qs.get("brand", [""])[0] or "").strip()[:64]
        model = (qs.get("model", [""])[0] or "").strip()[:64]
        conn = db.connect(self.db_path)
        try:
            row = db.get_trial(conn, fp)
            now = int(time.time())
            if row is None:
                # 新设备：按后台「发号模式」开关走 auto / manual
                mode = db.get_setting(conn, "issue_mode", "auto")
                if mode == "manual":
                    # 人工审批模式：进入 pending，等后台通过后才有配额
                    if not db.register_allowed(conn, peer_ip, IP_LIMIT):
                        log(f"register DENIED (ip limit) {peer_ip}")
                        self._error(429, "too many registrations from this ip")
                        return
                    client_id = new_client_id()
                    db.log_register_ip(conn, peer_ip, now)
                    db.create_trial(
                        conn, fp=fp, client_id=client_id,
                        token_hash="",
                        os_name=qs.get("os", [""])[0][:64],
                        cpu=qs.get("cpu", [""])[0][:128],
                        ram_mb=_to_int(qs.get("ram", ["0"])[0]),
                        mac_hash=qs.get("mac", [""])[0][:64],
                        ip=peer_ip, created_at=now,
                        expire_at=0, quota_bytes=0,
                        brand=brand, model=model, status="pending")
                    log(f"register PENDING (manual) {fp[:12]}.. -> {client_id}")
                    row = db.get_trial(conn, fp)
                    self._send_signed(200, render_credentials(row))
                    return
                # 自动发号模式（默认）：同 IP 限频（已有 fp 的换发不占额度）
                if not db.register_allowed(conn, peer_ip, IP_LIMIT):
                    log(f"register DENIED (ip limit) {peer_ip}")
                    self._error(429, "too many registrations from this ip")
                    return
                now = int(time.time())
                client_id = new_client_id()
                token = new_token()
                db.log_register_ip(conn, peer_ip, now)   # 限频计数先落库
                db.create_trial(
                    conn, fp=fp, client_id=client_id,
                    token_hash=token_hash(token),
                    os_name=qs.get("os", [""])[0][:64],
                    cpu=qs.get("cpu", [""])[0][:128],
                    ram_mb=_to_int(qs.get("ram", ["0"])[0]),
                    mac_hash=qs.get("mac", [""])[0][:64],
                    ip=peer_ip, created_at=now,
                    expire_at=now + TRIAL_DAYS * 86400,
                    quota_bytes=TRIAL_QUOTA,
                    brand=brand, model=model, status="trial")
                append_token_to_server(TOKENS_FILE, token)
                log(f"register NEW {fp[:12]}.. -> {client_id} from {peer_ip}")
                row = db.get_trial(conn, fp)
                self._send_signed(200, render_credentials(row, token))
                return

            # 已有记录：按状态分流（2026-11-02 授权规则收紧）
            status = row["status"]
            expired = row["expire_at"] != 0 and now >= row["expire_at"]
            if status == "rejected" or status == "revoked":
                # 被拒绝/已取消的设备锁死申请：不换发令牌，等后台人工处理
                db.touch_last_ip(conn, fp, peer_ip)
                log(f"register LOCKED ({status}) {fp[:12]}.. from {peer_ip}")
                self._send_signed(200, render_credentials(row))
                return
            if status == "trial" and expired:
                # 试用过期后的重申 = 「后续申请」：转 pending 等人工确认
                db.set_status(conn, fp, "pending")
                db.touch_last_ip(conn, fp, peer_ip)
                row = db.get_trial(conn, fp)
                log(f"register EXPIRED->PENDING {fp[:12]}.. from {peer_ip}")
                self._send_signed(200, render_credentials(row))
                return
            if status == "pending":
                # 仍在等后台审批：返回现有凭据（无配额，连不上）
                db.touch_last_ip(conn, fp, peer_ip)
                self._send_signed(200, render_credentials(row))
                return

            # trial 未过期 / approved：换发新令牌（client_id 不变），不限频不重建
            token = new_token()
            db.reissue_token(conn, fp, token_hash(token))
            db.touch_last_ip(conn, fp, peer_ip)
            append_token_to_server(TOKENS_FILE, token)
            log(f"register REISSUE {fp[:12]}.. from {peer_ip}")
            row = db.get_trial(conn, fp)
            self._send_signed(200, render_credentials(row, token))
        finally:
            conn.close()

    def _handle_status(self, qs: dict, peer_ip: str) -> None:
        fp = (qs.get("fp", [""])[0] or "").strip().lower()
        brand = (qs.get("brand", [""])[0] or "").strip()[:64]
        model = (qs.get("model", [""])[0] or "").strip()[:64]
        conn = db.connect(self.db_path)
        try:
            row = db.get_trial(conn, fp) if len(fp) == 64 else None
            if row is None:
                self._error(404, "unknown fp")
                return
            db.touch_last_ip(conn, fp, peer_ip)
            db.update_device_info(conn, fp, brand, model)   # 存量设备重连即补齐
            self._send_signed(200, render_credentials(row))
        finally:
            conn.close()

    def _handle_static(self, path: str, qs: dict) -> None:
        if not LIST_DIR:
            self._error(404, "server list not configured")
            return
        name = os.path.basename(path)          # 只允许单层文件名，防目录穿越
        full = os.path.join(LIST_DIR, name)
        # 受控下发：服务器列表只对已登记（申请过试用/已授权）的设备可见。
        # 客户端以 ?fp=<64hex> 请求；未登记一律 403——"只给试用者"从申请这一步开始。
        fp = (qs.get("fp", [""])[0] or "").strip().lower()
        conn = db.connect(self.db_path)
        try:
            known = len(fp) == 64 and db.get_trial(conn, fp) is not None
        finally:
            conn.close()
        if not known:
            self._error(403, "unknown device")
            return

        # 2026-11-01：服务器列表改为「后台勾选 → 实时生成 → 签名下发」。
        # 库里配过条目就以库为准；一条都没配过（老部署）才回退到静态文件。
        if name in ("server-list.ini", "server-list.ini.sig"):
            body = self._render_server_list()
            if body is not None:
                if name.endswith(".sig"):
                    sig = sign_b64(Handler.key, body.encode("utf-8"))
                    self._send(200, sig.encode("ascii"))
                else:
                    self._send(200, body.encode("utf-8"))
                return

        if not os.path.isfile(full):
            self._error(404, "not found")
            return
        with open(full, "rb") as f:
            self._send(200, f.read())

    @staticmethod
    def _render_server_list():
        """按数据库里 enabled=1 的条目生成列表正文；未配置过返回 None（走静态文件）。

        全部停用时返回"只有表头"的空列表——这是运营主动暂停下发的合法状态，
        客户端拿到空列表就撤掉受管卡片，不应退回静态文件把旧服务器又发出去。
        """
        conn = db.connect(Handler.db_path)
        try:
            if db.count_vpn_servers(conn) == 0:
                return None
            rows = db.list_enabled_vpn_servers(conn)
        finally:
            conn.close()

        lines = ["# ScholarVPN managed server list",
                 "# generated: " + datetime.datetime.now().isoformat(timespec="seconds")]
        for i, r in enumerate(rows, start=1):
            lines.append("server%d = %s" % (i, r["addr"]))
            lines.append("pubkey%d = %s" % (i, r["pubkey"]))
            lines.append("remark%d = %s" % (i, r["remark"] or ""))
        return "\n".join(lines) + "\n"


def _to_int(text: str) -> int:
    try:
        return max(0, int(text))
    except (TypeError, ValueError):
        return 0


# ---------------------------------------------------------------- CLI ----

def cmd_init_db(args) -> int:
    conn = db.connect(args.db)
    db.init_db(conn)
    conn.close()
    print(f"数据库已初始化: {args.db}")
    return 0


def cmd_serve(args) -> int:
    global LIST_DIR
    if not args.key:
        raise SystemExit("需要 --key service.key（或环境变量 SERVICE_KEY）")
    LIST_DIR = args.list_dir
    Handler.key = load_private_key(args.key)
    Handler.db_path = args.db
    conn = db.connect(args.db)
    db.init_db(conn)
    conn.close()
    httpd = ThreadingHTTPServer((args.bind, args.port), Handler)
    # 可选 TLS：生产部署直接对外提供 HTTPS（复用同域证书，独立端口，不动现有服务）
    tls_cert = os.environ.get("SERVICE_TLS_CERT", "")
    tls_key = os.environ.get("SERVICE_TLS_KEY", "")
    if tls_cert and tls_key:
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(tls_cert, tls_key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        log(f"TLS enabled (cert={tls_cert})")
    log(f"broker listening on {args.bind}:{args.port} (db={args.db})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log("bye")
    return 0


def cmd_approve(args) -> int:
    conn = db.connect(args.db)
    row = db.get_trial(conn, args.fp)
    if row is None:
        print(f"未找到 fp={args.fp}", file=sys.stderr)
        return 1
    db.set_status(conn, args.fp, args.status)
    print(f"{args.fp[:16]}.. -> {args.status}")
    return 0


def cmd_clear_iplog(args) -> int:
    conn = db.connect(args.db)
    if args.ip:
        cur = conn.execute("DELETE FROM register_ip_log WHERE ip=?", (args.ip,))
    else:
        cur = conn.execute("DELETE FROM register_ip_log")
    conn.commit()
    conn.close()
    print(f"已清除 {cur.rowcount} 条限频记录" + (f" (ip={args.ip})" if args.ip else ""))
    return 0


def cmd_list(args) -> int:
    conn = db.connect(args.db)
    for r in db.list_trials(conn):
        print(f"{r['fp'][:16]}.. {r['client_id']:<18} {r['status']:<9}"
              f" expire={r['expire_at']} used={r['used_bytes']}/{r['quota_bytes']}"
              f" ip={r['last_ip']}")
    return 0


def cmd_server_list(args) -> int:
    """生成 server-list.ini + .sig。pubkey 为 SPKI DER 的 base64（客户端 config.ini
    ServerPubKey 同格式）。数据全部来自命令行参数，禁止手写哈希类字段。"""
    lines = ["# ScholarVPN managed server list",
             f"# generated: {datetime.datetime.now().isoformat(timespec='seconds')}"]
    for i, (addr, pub, remark) in enumerate(
            zip(args.server, args.pubkey, args.remark), start=1):
        lines.append(f"server{i} = {addr}")
        lines.append(f"pubkey{i} = {pub}")
        lines.append(f"remark{i} = {remark}")
    body = "\n".join(lines) + "\n"
    os.makedirs(args.out_dir, exist_ok=True)
    ini = os.path.join(args.out_dir, "server-list.ini")
    with open(ini, "w", encoding="utf-8", newline="\n") as f:
        f.write(body)
    key = load_private_key(args.key)
    with open(ini + ".sig", "w", encoding="ascii", newline="\n") as f:
        f.write(sign_b64(key, body.encode("utf-8")))
    print(f"已生成: {ini} (+.sig)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="ScholarVPN 受管服务 broker")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def shared(p) -> None:
        """共享参数挂在每个子命令上：允许 `broker.py serve --db x` 的写法。"""
        p.add_argument("--db", default=db.DEFAULT_DB_PATH)
        p.add_argument("--bind", default=BIND)
        p.add_argument("--port", type=int, default=PORT)
        p.add_argument("--key", default=KEY_PATH)

    p = sub.add_parser("init-db", help="建库建表")
    shared(p)
    p = sub.add_parser("serve", help="启动发号 HTTP 服务")
    shared(p)
    p.add_argument("--list-dir", default=LIST_DIR, help="server-list.ini 目录")
    p = sub.add_parser("list", help="列出试用/授权记录")
    shared(p)
    p = sub.add_parser("clear-iplog", help="清空 IP 限频计数（解除限频）")
    shared(p)
    p.add_argument("--ip", default="", help="只清指定 IP；缺省清全部")
    p = sub.add_parser("approve", help="转正式（解除配额与到期）")
    shared(p)
    p.add_argument("--fp", required=True)
    p = sub.add_parser("reject", help="拒绝/停用")
    shared(p)
    p.add_argument("--fp", required=True)
    p = sub.add_parser("server-list", help="生成并签名服务器列表")
    shared(p)
    p.add_argument("--out-dir", required=True)
    p.add_argument("--server", action="append", required=True,
                   help="ip:port，可重复")
    p.add_argument("--pubkey", action="append", required=True,
                   help="服务器签名公钥（SPKI DER base64），与 --server 一一对应")
    p.add_argument("--remark", action="append", default=[],
                   help="展示名，与 --server 一一对应")

    args = ap.parse_args()
    if args.cmd == "init-db":
        return cmd_init_db(args)
    if args.cmd == "serve":
        return cmd_serve(args)
    if args.cmd == "list":
        return cmd_list(args)
    if args.cmd == "clear-iplog":
        return cmd_clear_iplog(args)
    if args.cmd == "approve":
        args.status = "approved"
        return cmd_approve(args)
    if args.cmd == "reject":
        args.status = "rejected"
        return cmd_approve(args)
    if args.cmd == "server-list":
        # remark 与 server 数量对齐（缺省给空串）
        while len(args.remark) < len(args.server):
            args.remark.append("")
        return cmd_server_list(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
