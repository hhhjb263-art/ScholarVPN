#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================================
# app.py —— ScholarVPN 后台管理 Web 客户端（带管理员登录）
# ----------------------------------------------------------------------------
# 浏览器 ──HTTPS──▶ app.py ──HTTP 127.0.0.1:18081──▶ vpn_controller
#
# 安全模型：
#   · 管理员账号存 SQLite（tools/webadmin/data/webadmin.db），密码 scrypt 哈希；
#   · 会话存服务端，Cookie HttpOnly/Secure/SameSite=Strict；数据库只存令牌哈希；
#   · 所有写请求要求 X-CSRF-Token；
#   · 登录限速，错误提示不区分用户名是否存在；
#   · 不开放注册：首个管理员由服务器 root 用 manage.py create-admin 创建，
#     后续账号由已登录管理员添加；
#   · 中转管理令牌只保存在服务端，用于访问 127.0.0.1:18081，浏览器永远拿不到。
#
# 零第三方依赖：只用 Python 3 标准库 + OpenSSL（ssl/sqlite3/hashlib）。
# ============================================================================
from __future__ import annotations

import argparse
import base64
import hmac
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import auth

# ---- 受管服务库（broker 的 trials / audit / blacklist）----
# SQL 唯一所在是 tools/broker/db.py（迁移约束，见 docs/受管服务与试用授权方案.md 8.2）；
# webadmin 只调用它的函数，不写任何 SQL。库路径：环境变量 SVC_DB >
# /opt/scholarvpn-broker/service.db（服务器部署）> 仓库相对路径（本地开发）。
def _svc_broker_dir() -> str:
    env = os.environ.get("SVC_BROKER_DIR")
    if env:
        return env
    here = os.path.dirname(os.path.abspath(__file__))
    local = os.path.join(os.path.dirname(here), "broker")
    if os.path.isdir(local):
        return local
    return "/opt/scholarvpn-broker"

BROKER_DIR = _svc_broker_dir()
sys.path.insert(0, BROKER_DIR)
import db as svc_db  # noqa: E402

SVC_DB_PATH = os.environ.get("SVC_DB") or (
    "/opt/scholarvpn-broker/service.db"
    if os.path.isdir("/opt/scholarvpn-broker")
    else os.path.join(BROKER_DIR, "service.db"))


def svc_connect():
    """打开受管服务库；不可用时抛 RuntimeError（handler 转 503）。"""
    if not os.path.exists(SVC_DB_PATH):
        raise RuntimeError("受管服务库不存在: " + SVC_DB_PATH)
    return svc_db.connect(SVC_DB_PATH)


_SAFE_ID_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                     "0123456789-_.")
import ipaddress  # noqa: E402  —— 黑名单 ip 类型校验用（stdlib）


def _valid_domain(d: str) -> bool:
    if not d or len(d) > 255:
        return False
    if d.startswith("*."):
        d = d[2:]
    if not d or d[0] in "-." or d[-1] in "-." or "." not in d:
        return False
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789.-")
    return all(c in allowed for c in d)

MAX_BODY = 8 * 1024
UPSTREAM_TIMEOUT = 15.0
COOKIE_NAME = "sv_admin_session"

# ---------------------------------------------------------------- 服务器清单校验 ----
# 客户端用 ServerPubKey 校验该服务器的 Ed25519 签名，格式是 SPKI DER 的 base64
# （44 字节，固定前缀 302a300506032b6570032100）。
# ⚠️ 这里必须严格校验：历史上曾把 broker 的 service 签名公钥误填进 pubkey 字段，
# 导致客户端验签失败、卡在"连接中"（2026-11-01 事故）。填错的公钥一律拒绝入库。
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def _valid_server_pubkey(b64: str) -> bool:
    if not b64 or len(b64) > 200:
        return False
    try:
        raw = base64.b64decode(b64, validate=True)
    except Exception:
        return False
    return len(raw) == 44 and raw[:12] == _ED25519_SPKI_PREFIX


def _valid_server_addr(addr: str) -> bool:
    """"host:port"，host 允许 IPv4 或域名，port 1-65535。"""
    if not addr or len(addr) > 255 or addr.count(":") != 1:
        return False
    host, _, port = addr.rpartition(":")
    if not host or not port.isdigit():
        return False
    p = int(port)
    if p < 1 or p > 65535:
        return False
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789.-_")
    return all(c in allowed for c in host.lower())


def _local_server_pubkey() -> str:
    """读本机 VPN 服务器的 server_sig.pub，直接给出 SPKI DER base64。

    存在的意义：让运营"点一下就填对"，而不是手工去 openssl 转换再粘贴——
    这一步出错就会把服务端公钥填成 broker 的 service 钥。
    """
    path = os.environ.get("VPN_SIG_PUB", "/root/ScholarVPN/server/keys/server_sig.pub")
    if not os.path.isfile(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            body = "".join(ln.strip() for ln in f
                           if ln.strip() and not ln.startswith("-----"))
    except OSError:
        return ""
    return body if _valid_server_pubkey(body) else ""


def _service_pubkey_b64() -> str:
    """broker 的 service 签名公钥（用于防止误填进 pubkey 字段）。"""
    path = os.environ.get("SERVICE_PUB",
                          "/opt/scholarvpn-broker/keys/release_pub.pem")
    if not os.path.isfile(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return "".join(ln.strip() for ln in f
                           if ln.strip() and not ln.startswith("-----"))
    except OSError:
        return ""


HERE = os.path.dirname(os.path.abspath(__file__))

# 访问中转站时显式禁用系统代理（避免 http_proxy 把 127.0.0.1 请求劫持成 502）
def _build_opener(ca_file: str = ""):
    handlers = [urllib.request.ProxyHandler({})]
    if ca_file:
        ctx = ssl.create_default_context(cafile=ca_file)
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


_OPENER = _build_opener()
_RATE = auth.RateLimiter()


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


class Config:
    controller = "http://127.0.0.1:18081"
    controller_ca = ""
    token = ""              # 中转管理令牌：只在服务端使用
    bind = "127.0.0.1"
    port = 8080
    tls_cert = ""
    tls_key = ""
    tls = False
    cookie_secure = False
    db_path = os.path.join(HERE, "data", "webadmin.db")
    # VPN 服务器对外可达地址（域名或公网 IP），仅用于页面展示，供复制到客户端配置。
    # 留空则启动后首次访问 /api/meta 时自动探测出口 IP。
    vpn_public_ip = ""
    vpn_public_port = 51820


# ---- VPN 对外地址 ----
# 为什么要单独配：后台与 VPN 同机时，agent 上报给 controller 的源地址是 127.0.0.1，
# 对客户端毫无用处。页面要展示的是**从外网能连上的地址**，只能显式配置或探测出口 IP。
_PUBLIC_IP_CACHE: dict = {"value": "", "ts": 0.0}
_PUBLIC_IP_TTL = 600.0


def _looks_like_ip(text: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _detect_public_ip() -> str:
    """向多个公共回显服务询问出口 IP，任一成功即返回；全失败返回空串（静默）。"""
    for url in ("https://api.ipify.org",
                "https://icanhazip.com",
                "https://ifconfig.me/ip"):
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "ScholarVPN-WebAdmin/2.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                text = resp.read(64).decode("ascii", "ignore").strip()
            if _looks_like_ip(text):
                return text
        except Exception:
            continue          # 网络不通/被墙/返回非 IP：换下一个源
    return ""


def public_ip() -> str:
    """显式配置 > 缓存 > 探测。探测结果缓存 10 分钟，避免每次刷新页面都打外网。"""
    if Config.vpn_public_ip:
        return Config.vpn_public_ip
    now = time.time()
    if _PUBLIC_IP_CACHE["value"] and now - float(_PUBLIC_IP_CACHE["ts"]) < _PUBLIC_IP_TTL:
        return str(_PUBLIC_IP_CACHE["value"])
    ip = _detect_public_ip()
    _PUBLIC_IP_CACHE["value"] = ip
    _PUBLIC_IP_CACHE["ts"] = now
    return ip


def _json_bytes(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False).encode("utf-8")


class TimeoutThreadingHTTPServer(ThreadingHTTPServer):
    """TLS 握手放到工作线程里做，主线程只负责 accept。

    为什么需要（2026-10-19 生产事故）：按常规写法
    `srv.socket = ctx.wrap_socket(srv.socket, server_side=True)`，
    `serve_forever()` 调 `accept()` 时会在 SSLSocket 内部同步完成 TLS 握手，
    而**握手不吃监听 socket 上的 settimeout**（实测设 10s 无效）。
    只要有一个客户端建立 TCP 连接却不发 ClientHello（端口扫描、浏览器预连接、
    中途断开的 curl），主线程就永久阻塞，后续连接全堆在 backlog 里
    （`ss` 看到 Recv-Q 持续增长），整站表现为"响应时间太长"，直到重启进程。

    只把握手挪到 get_request 里也治标不治本——accept 仍是串行的，
    一个半开连接会让后面的连接干等满一个 handshake_timeout。

    最终做法：accept 保持纯 TCP（毫秒级），握手放进 ThreadingMixIn 的工作线程，
    半开连接最多占住一个线程，其他人完全不受影响。
    """

    handshake_timeout = 10.0
    request_timeout = 30.0
    ssl_context = None      # 非 None 时由工作线程完成握手

    def get_request(self):
        sock, addr = super().get_request()   # 纯 TCP accept，立即返回
        sock.settimeout(self.request_timeout)
        return sock, addr

    def process_request_thread(self, request, client_address):
        ctx = self.ssl_context
        if ctx is not None:
            request.settimeout(self.handshake_timeout)
            try:
                request = ctx.wrap_socket(request, server_side=True)
            except Exception:
                # 握手失败/超时：关掉这条连接，其他线程照常工作
                try:
                    request.close()
                except OSError:
                    pass
                return
            request.settimeout(self.request_timeout)
        super().process_request_thread(request, client_address)


class Handler(BaseHTTPRequestHandler):
    server_version = "ScholarVPN-WebAdmin/2.0"
    protocol_version = "HTTP/1.1"
    # keep-alive 空闲超时：连接闲置超过这个时间就回收，
    # 否则每个浏览器连接会一直占着一个工作线程（ThreadingHTTPServer 每连接一线程）。
    timeout = 30

    # ---------------------------------------------------------------- 输出
    def _security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        # 页面是原生内联 JS/CSS；限制来源，禁止被 iframe 嵌入。
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
            "form-action 'self'",
        )
        if Config.tls:
            self.send_header("Strict-Transport-Security", "max-age=31536000")

    def _send(self, status: int, body: bytes, ctype: str,
              headers: dict | None = None, set_cookie: str | None = None,
              location: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._security_headers()
        if location:
            self.send_header("Location", location)
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        # 只有错误响应才关闭连接：错误路径可能没读完请求体，继续复用会让
        # 下一个请求从错误的偏移开始解析。正常响应保持 HTTP/1.1 keep-alive，
        # 让浏览器复用同一条 TLS 连接——跨境链路上省掉的是每次 1~4 秒的握手。
        if status >= 400:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def _send_json(self, status: int, obj, headers: dict | None = None,
                   set_cookie: str | None = None) -> None:
        self._send(status, _json_bytes(obj), "application/json; charset=utf-8",
                   headers=headers, set_cookie=set_cookie)

    def _error(self, status: int, msg: str, hint: str = "",
               headers: dict | None = None, set_cookie: str | None = None) -> None:
        payload = {"error": msg}
        if hint:
            payload["hint"] = hint
        self._send_json(status, payload, headers=headers, set_cookie=set_cookie)

    def _redirect(self, location: str, set_cookie: str | None = None) -> None:
        self._send(302, b"", "text/plain; charset=utf-8",
                   set_cookie=set_cookie, location=location)

    def log_message(self, fmt: str, *args) -> None:  # 默认日志太吵
        log("  %s - %s" % (self.address_string(), fmt % args))

    # ---------------------------------------------------------------- 工具
    def _client_ip(self) -> str:
        return self.client_address[0] if self.client_address else ""

    def _cookie_raw(self) -> str:
        raw = self.headers.get("Cookie", "")
        if not raw:
            return ""
        jar = cookies.SimpleCookie()
        try:
            jar.load(raw)
        except cookies.CookieError:
            return ""
        morsel = jar.get(COOKIE_NAME)
        return morsel.value if morsel else ""

    def _session(self) -> dict | None:
        return auth.get_session(Config.db_path, self._cookie_raw())

    def _set_cookie(self, raw: str) -> str:
        parts = [
            f"{COOKIE_NAME}={raw}",
            "Path=/",
            "HttpOnly",
            "SameSite=Strict",
            f"Max-Age={auth.COOKIE_MAX_AGE}",
        ]
        if Config.cookie_secure:
            parts.append("Secure")
        return "; ".join(parts)

    def _clear_cookie(self) -> str:
        parts = [
            f"{COOKIE_NAME}=",
            "Path=/",
            "HttpOnly",
            "SameSite=Strict",
            "Max-Age=0",
            "Expires=Thu, 01 Jan 1970 00:00:00 GMT",
        ]
        if Config.cookie_secure:
            parts.append("Secure")
        return "; ".join(parts)

    @staticmethod
    def _norm_netloc(netloc: str) -> str:
        netloc = (netloc or "").lower()
        if netloc.endswith(":443"):
            netloc = netloc[:-4]
        elif netloc.endswith(":80"):
            netloc = netloc[:-3]
        return netloc

    def _same_origin(self) -> bool:
        """登录/注册的 CSRF 防护：浏览器跨站请求会带 Origin/Referer。"""
        host = self._norm_netloc(self.headers.get("Host", ""))
        for name in ("Origin", "Referer"):
            value = self.headers.get(name)
            if value:
                try:
                    return self._norm_netloc(urllib.parse.urlsplit(value).netloc) == host
                except ValueError:
                    return False
        return True  # 非浏览器客户端（curl）没有 Origin/Referer

    def _read_json(self) -> dict:
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            raise ValueError("Content-Type must be application/json")
        try:
            n = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            raise ValueError("bad Content-Length")
        if n <= 0:
            raise ValueError("empty body")
        if n > MAX_BODY:
            raise ValueError("body too large")
        raw = self.rfile.read(n)
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            raise ValueError("invalid JSON")
        if not isinstance(data, dict):
            raise ValueError("JSON object required")
        return data

    def _require_session(self) -> dict | None:
        sess = self._session()
        if sess is None:
            self._error(401, "login required", hint="请重新登录")
            return None
        return sess

    def _require_csrf(self, sess: dict) -> bool:
        given = self.headers.get("X-CSRF-Token", "")
        if not given or not hmac.compare_digest(
                given.encode("utf-8", "ignore"), sess["csrf"].encode("utf-8")):
            self._error(403, "csrf token invalid", hint="刷新页面后重试")
            return False
        return True

    def _static(self, name: str, ctype: str) -> None:
        # 只允许固定文件，避免路径穿越
        allowed = {"index.html", "login.html"}
        if name not in allowed:
            return self._error(404, "not found")
        path = os.path.join(HERE, name)
        try:
            with open(path, "rb") as f:
                body = f.read()
        except OSError:
            return self._error(500, f"静态文件缺失: {name}")
        self._send(200, body, ctype)

    # ---------------------------------------------------------------- 路由
    def do_GET(self) -> None:
        path = urllib.parse.urlsplit(self.path).path

        if path in ("/", "/index.html"):
            if self._session() is None:
                return self._redirect("/login")
            return self._static("index.html", "text/html; charset=utf-8")
        if path == "/login":
            if self._session() is not None:
                return self._redirect("/")
            return self._static("login.html", "text/html; charset=utf-8")
        if path == "/favicon.ico":
            return self._send(204, b"", "text/plain")
        if path == "/api/auth/status":
            initialized = auth.count_admins(Config.db_path) > 0
            return self._send_json(200, {"initialized": initialized})
        if path == "/api/auth/me":
            sess = self._require_session()
            if sess is None:
                return
            return self._send_json(200, {
                "authenticated": True,
                "username": sess["username"],
                "csrf": sess["csrf"],
                "expires_at": sess["expires_at"],
            })
        if path == "/api/admin/users":
            sess = self._require_session()
            if sess is None:
                return
            return self._list_admins(sess)
        if path == "/api/meta":
            # 页面展示用：VPN 对外地址（客户端要填的服务器地址）。
            # 需要登录态——地址本身不算秘密，但没必要对未登录访客暴露。
            sess = self._require_session()
            if sess is None:
                return
            ip = public_ip()
            port = Config.vpn_public_port
            return self._send_json(200, {
                "vpn_public_ip": ip,
                "vpn_public_port": port,
                "vpn_address": f"{ip}:{port}" if ip else "",
            })
        if path == "/api/service/mode":
            sess = self._require_session()
            if sess is None:
                return
            return self._svc_mode_get(sess)
        if path == "/api/service/users":
            sess = self._require_session()
            if sess is None:
                return
            return self._svc_users(sess)
        if path == "/api/service/audit":
            sess = self._require_session()
            if sess is None:
                return
            return self._svc_audit(sess)
        if path == "/api/service/blacklist":
            sess = self._require_session()
            if sess is None:
                return
            return self._svc_blacklist_get(sess)
        if path == "/api/service/servers":
            sess = self._require_session()
            if sess is None:
                return
            return self._svc_servers_get(sess)
        if path == "/api/service/servers/local-pubkey":
            sess = self._require_session()
            if sess is None:
                return
            return self._send_json(200, {"pubkey": _local_server_pubkey()})
        if path.startswith("/api/"):
            return self._proxy("GET")
        return self._error(404, "not found")

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_POST(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path == "/api/auth/login":
            return self._login()
        if path == "/api/auth/logout":
            return self._logout()
        if path == "/api/auth/password":
            return self._change_password()
        if path == "/api/admin/users":
            sess = self._require_session()
            if sess is None:
                return
            if not self._require_csrf(sess):
                return
            return self._create_admin(sess)
        if path == "/api/service/mode":
            sess = self._require_session()
            if sess is None:
                return
            if not self._require_csrf(sess):
                return
            return self._svc_mode_set(sess)
        if path == "/api/service/users/note":
            sess = self._require_session()
            if sess is None:
                return
            if not self._require_csrf(sess):
                return
            return self._svc_user_note(sess)
        if path == "/api/service/users/approve":
            sess = self._require_session()
            if sess is None:
                return
            if not self._require_csrf(sess):
                return
            return self._svc_user_action(sess, "approved")
        if path == "/api/service/users/reject":
            sess = self._require_session()
            if sess is None:
                return
            if not self._require_csrf(sess):
                return
            return self._svc_user_action(sess, "rejected")
        if path == "/api/service/users/restore":
            sess = self._require_session()
            if sess is None:
                return
            if not self._require_csrf(sess):
                return
            return self._svc_user_restore(sess)
        if path == "/api/service/users/revoke":
            sess = self._require_session()
            if sess is None:
                return
            if not self._require_csrf(sess):
                return
            return self._svc_user_action(sess, "revoked")
        if path == "/api/service/blacklist":
            sess = self._require_session()
            if sess is None:
                return
            if not self._require_csrf(sess):
                return
            return self._svc_blacklist_add(sess)
        if path == "/api/service/servers":
            sess = self._require_session()
            if sess is None:
                return
            if not self._require_csrf(sess):
                return
            return self._svc_servers_upsert(sess)
        if path == "/api/service/servers/toggle":
            sess = self._require_session()
            if sess is None:
                return
            if not self._require_csrf(sess):
                return
            return self._svc_servers_toggle(sess)
        if path.startswith("/api/"):
            return self._proxy("POST")
        return self._error(404, "not found")

    def do_DELETE(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path.startswith("/api/service/users/"):
            sess = self._require_session()
            if sess is None:
                return
            if not self._require_csrf(sess):
                return
            fp = urllib.parse.unquote(path.rsplit("/", 1)[1]).strip().lower()
            return self._svc_user_purge(sess, fp)
        if path.startswith("/api/service/blacklist/"):
            sess = self._require_session()
            if sess is None:
                return
            if not self._require_csrf(sess):
                return
            domain = urllib.parse.unquote(path.rsplit("/", 1)[1]).strip().lower()
            return self._svc_blacklist_del(sess, domain)
        if path.startswith("/api/service/servers/"):
            sess = self._require_session()
            if sess is None:
                return
            if not self._require_csrf(sess):
                return
            addr = urllib.parse.unquote(path.rsplit("/", 1)[1]).strip()
            return self._svc_servers_del(sess, addr)
        if path.startswith("/api/"):
            return self._proxy("DELETE")
        return self._error(404, "not found")

    # ---------------------------------------------- 受管服务（用户管理）
    def _svc_mode_get(self, sess) -> None:
        try:
            conn = svc_connect()
        except RuntimeError as e:
            return self._error(503, str(e))
        try:
            mode = svc_db.get_setting(conn, "issue_mode", "auto")
        finally:
            conn.close()
        return self._send_json(200, {"mode": mode})

    def _svc_mode_set(self, sess) -> None:
        try:
            data = self._read_json()
        except ValueError as e:
            return self._error(400, str(e))
        mode = str(data.get("mode", "")).strip()
        if mode not in ("auto", "manual"):
            return self._error(400, "mode must be auto or manual")
        try:
            conn = svc_connect()
        except RuntimeError as e:
            return self._error(503, str(e))
        try:
            svc_db.set_setting(conn, "issue_mode", mode)
        finally:
            conn.close()
        auth.audit(Config.db_path, sess["username"], self._client_ip(),
                   "svc_issue_mode", detail=mode)
        return self._send_json(200, {"ok": True, "mode": mode})

    def _svc_user_note(self, sess) -> None:
        try:
            data = self._read_json()
        except ValueError as e:
            return self._error(400, str(e))
        fp = str(data.get("fp", "")).strip().lower()
        if len(fp) != 64 or any(c not in "0123456789abcdef" for c in fp):
            return self._error(400, "invalid fp")
        note = str(data.get("note", "")).strip()[:256]
        try:
            conn = svc_connect()
        except RuntimeError as e:
            return self._error(503, str(e))
        try:
            if svc_db.get_trial(conn, fp) is None:
                return self._error(404, "unknown fp")
            svc_db.set_note(conn, fp, note)
        finally:
            conn.close()
        auth.audit(Config.db_path, sess["username"], self._client_ip(),
                   "svc_note", detail=fp[:16])
        return self._send_json(200, {"ok": True, "fp": fp, "note": note})

    def _svc_users(self, sess) -> None:
        try:
            conn = svc_connect()
        except RuntimeError as e:
            return self._error(503, str(e))
        try:
            rows = svc_db.list_trials(conn)
        finally:
            conn.close()
        users = [{
            "fp": r["fp"], "client_id": r["client_id"], "status": r["status"],
            "os": r["os"], "cpu": r["cpu"], "ram_mb": r["ram_mb"],
            "brand": r["brand"] if "brand" in r.keys() else "",
            "model": r["model"] if "model" in r.keys() else "",
            "note": r["note"] if "note" in r.keys() else "",
            "first_ip": r["first_ip"], "last_ip": r["last_ip"],
            "created_at": r["created_at"], "expire_at": r["expire_at"],
            "quota_bytes": r["quota_bytes"], "used_bytes": r["used_bytes"],
        } for r in rows]
        return self._send_json(200, {"users": users})

    def _svc_user_action(self, sess, status: str) -> None:
        try:
            data = self._read_json()
        except ValueError as e:
            return self._error(400, str(e))
        fp = str(data.get("fp", "")).strip().lower()
        if len(fp) != 64 or any(c not in "0123456789abcdef" for c in fp):
            return self._error(400, "invalid fp")
        try:
            conn = svc_connect()
        except RuntimeError as e:
            return self._error(503, str(e))
        try:
            if svc_db.get_trial(conn, fp) is None:
                return self._error(404, "unknown fp")
            svc_db.set_status(conn, fp, status)
        finally:
            conn.close()
        auth.audit(Config.db_path, sess["username"], self._client_ip(),
                   "svc_" + status, detail=fp[:16])
        return self._send_json(200, {"ok": True, "fp": fp, "status": status})

    def _svc_user_restore(self, sess) -> None:
        """垃圾桶恢复：rejected/revoked → 重新给一轮试用（3 天 / 2GB）。"""
        try:
            data = self._read_json()
        except ValueError as e:
            return self._error(400, str(e))
        fp = str(data.get("fp", "")).strip().lower()
        if len(fp) != 64 or any(c not in "0123456789abcdef" for c in fp):
            return self._error(400, "invalid fp")
        try:
            conn = svc_connect()
        except RuntimeError as e:
            return self._error(503, str(e))
        try:
            row = svc_db.get_trial(conn, fp)
            if row is None:
                return self._error(404, "unknown fp")
            if row["status"] not in ("rejected", "revoked"):
                return self._error(400, "only rejected/revoked can be restored")
            now = int(time.time())
            svc_db.restore_trial(conn, fp,
                                 now + 3 * 86400, 2 * 1024 ** 3)
        finally:
            conn.close()
        auth.audit(Config.db_path, sess["username"], self._client_ip(),
                   "svc_restore", detail=fp[:16])
        return self._send_json(200, {"ok": True, "fp": fp, "status": "trial"})

    def _svc_user_purge(self, sess, fp: str) -> None:
        """垃圾桶彻底删除：抹掉记录，该设备可重新申请试用。"""
        if len(fp) != 64 or any(c not in "0123456789abcdef" for c in fp):
            return self._error(400, "invalid fp")
        try:
            conn = svc_connect()
        except RuntimeError as e:
            return self._error(503, str(e))
        try:
            row = svc_db.get_trial(conn, fp)
            if row is None:
                return self._error(404, "unknown fp")
            if row["status"] not in ("rejected", "revoked"):
                return self._error(400, "only rejected/revoked can be purged")
            svc_db.purge_trial(conn, fp)
        finally:
            conn.close()
        auth.audit(Config.db_path, sess["username"], self._client_ip(),
                   "svc_purge", detail=fp[:16])
        return self._send_json(200, {"ok": True, "fp": fp})

    def _svc_audit(self, sess) -> None:
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        client_id = (qs.get("client_id", [""])[0] or "").strip() or None
        day = (qs.get("day", [""])[0] or "").strip() or None
        try:
            conn = svc_connect()
        except RuntimeError as e:
            return self._error(503, str(e))
        try:
            rows = svc_db.list_audit(conn, day=day, client_id=client_id)
        finally:
            conn.close()
        return self._send_json(200, {"audit": [dict(r) for r in rows]})

    def _svc_blacklist_get(self, sess) -> None:
        try:
            conn = svc_connect()
        except RuntimeError as e:
            return self._error(503, str(e))
        try:
            rows = svc_db.list_blacklist(conn)
        finally:
            conn.close()
        return self._send_json(200, {"blacklist": [dict(r) for r in rows]})

    # ---------------------------------------------- 受管服务（服务器清单）
    # 运营在这里维护"哪些 VPN 服务器下发给客户端"；broker 每次请求按
    # enabled=1 的记录实时生成并签名 server-list.ini（见 broker.py）。
    def _svc_servers_get(self, sess) -> None:
        try:
            conn = svc_connect()
        except RuntimeError as e:
            return self._error(503, str(e))
        try:
            rows = svc_db.list_vpn_servers(conn)
        finally:
            conn.close()
        return self._send_json(200, {
            "servers": [dict(r) for r in rows],
            "local_pubkey": _local_server_pubkey(),
        })

    def _svc_servers_upsert(self, sess) -> None:
        try:
            data = self._read_json()
        except ValueError as e:
            return self._error(400, str(e))
        addr = str(data.get("addr", "")).strip()
        pubkey = str(data.get("pubkey", "")).strip()
        remark = str(data.get("remark", "")).strip()[:64]
        enabled = 1 if data.get("enabled", True) else 0
        try:
            sort_order = int(data.get("sort_order", 0) or 0)
        except (TypeError, ValueError):
            return self._error(400, "invalid sort_order")
        if not _valid_server_addr(addr):
            return self._error(400, "invalid addr（格式 ip:port）")
        if not _valid_server_pubkey(pubkey):
            return self._error(
                400, "invalid pubkey（需要该服务器 keys/server_sig.pub 的 SPKI DER base64）")
        # 防呆：service 签名公钥绝不能填进服务器 pubkey 字段（2026-11-01 事故：
        # 填错后客户端验签失败、卡在"连接中"，排查了很久）
        svc_pub = _service_pubkey_b64()
        if svc_pub and pubkey == svc_pub:
            return self._error(
                400, "pubkey 填成了 broker 的 service 签名公钥；"
                     "这里要填该 VPN 服务器自己的 keys/server_sig.pub")
        try:
            conn = svc_connect()
        except RuntimeError as e:
            return self._error(503, str(e))
        try:
            svc_db.upsert_vpn_server(conn, addr=addr, pubkey=pubkey,
                                     remark=remark, enabled=enabled,
                                     sort_order=sort_order)
        finally:
            conn.close()
        auth.audit(Config.db_path, sess["username"], self._client_ip(),
                   "svc_server_upsert", detail=addr)
        return self._send_json(200, {"ok": True, "addr": addr})

    def _svc_servers_toggle(self, sess) -> None:
        try:
            data = self._read_json()
        except ValueError as e:
            return self._error(400, str(e))
        addr = str(data.get("addr", "")).strip()
        enabled = bool(data.get("enabled", True))
        if not _valid_server_addr(addr):
            return self._error(400, "invalid addr")
        try:
            conn = svc_connect()
        except RuntimeError as e:
            return self._error(503, str(e))
        try:
            ok = svc_db.set_vpn_server_enabled(conn, addr, enabled)
        finally:
            conn.close()
        if not ok:
            return self._error(404, "not found")
        auth.audit(Config.db_path, sess["username"], self._client_ip(),
                   "svc_server_toggle", detail=("%s=%d" % (addr, 1 if enabled else 0)))
        return self._send_json(200, {"ok": True, "addr": addr, "enabled": enabled})

    def _svc_servers_del(self, sess, addr: str) -> None:
        if not _valid_server_addr(addr):
            return self._error(400, "invalid addr")
        try:
            conn = svc_connect()
        except RuntimeError as e:
            return self._error(503, str(e))
        try:
            ok = svc_db.delete_vpn_server(conn, addr)
        finally:
            conn.close()
        if not ok:
            return self._error(404, "not found")
        auth.audit(Config.db_path, sess["username"], self._client_ip(),
                   "svc_server_del", detail=addr)
        return self._send_json(200, {"ok": True, "addr": addr})

    def _svc_blacklist_add(self, sess) -> None:
        try:
            data = self._read_json()
        except ValueError as e:
            return self._error(400, str(e))
        value = str(data.get("domain", data.get("value", ""))).strip().lower()
        note = str(data.get("note", "")).strip()[:100]
        btype = str(data.get("type", "domain")).strip().lower()
        if btype not in ("domain", "ip", "machine"):
            return self._error(400, "invalid type")
        if btype == "domain" and not _valid_domain(value):
            return self._error(400, "invalid domain")
        if btype == "ip":
            import ipaddress
            try:
                ipaddress.ip_address(value)
            except ValueError:
                return self._error(400, "invalid ip")
        if btype == "machine" and (not value or len(value) > 64 or
                                   any(c not in _SAFE_ID_CHARS for c in value)):
            return self._error(400, "invalid client_id")
        try:
            conn = svc_connect()
        except RuntimeError as e:
            return self._error(503, str(e))
        try:
            svc_db.upsert_blacklist(conn, value, note, btype)
        finally:
            conn.close()
        auth.audit(Config.db_path, sess["username"], self._client_ip(),
                   "svc_blacklist_add", detail=btype + ":" + value)
        return self._send_json(200, {"ok": True, "domain": value, "type": btype})

    def _svc_blacklist_del(self, sess, domain: str) -> None:
        if not _valid_domain(domain):
            return self._error(400, "invalid domain")
        try:
            conn = svc_connect()
        except RuntimeError as e:
            return self._error(503, str(e))
        try:
            removed = svc_db.remove_blacklist(conn, domain)
        finally:
            conn.close()
        if not removed:
            return self._error(404, "domain not in blacklist")
        auth.audit(Config.db_path, sess["username"], self._client_ip(),
                   "svc_blacklist_del", detail=domain)
        return self._send_json(200, {"ok": True, "domain": domain})

    # ---------------------------------------------------------------- 认证
    def _login(self) -> None:
        if not self._same_origin():
            return self._error(403, "origin not allowed")
        ip = self._client_ip()
        wait = _RATE.retry_after(f"login:ip:{ip}", 20, 900)
        if wait:
            return self._error(429, "too many attempts",
                               headers={"Retry-After": str(wait)})
        try:
            data = self._read_json()
        except ValueError as e:
            return self._error(400, str(e))
        username = data.get("username", "")
        password = data.get("password", "")
        if not isinstance(username, str) or not isinstance(password, str):
            return self._error(400, "invalid fields")

        ukey = f"login:user:{username.lower()}"
        wait = _RATE.retry_after(ukey, 5, 900)
        if wait:
            return self._error(429, "too many attempts",
                               headers={"Retry-After": str(wait)})

        admin = auth.authenticate(Config.db_path, username, password)
        if admin is None:
            _RATE.hit(f"login:ip:{ip}", 900)
            _RATE.hit(ukey, 900)
            auth.audit(Config.db_path, username, ip, "login_fail")
            return self._error(401, "invalid username or password")
        _RATE.reset(ukey)
        raw, _csrf = auth.create_session(
            Config.db_path, admin["id"], ip, self.headers.get("User-Agent", ""))
        auth.audit(Config.db_path, admin["username"], ip, "login_ok")
        return self._send_json(200, {"ok": True, "username": admin["username"]},
                               set_cookie=self._set_cookie(raw))

    def _change_password(self) -> None:
        sess = self._require_session()
        if sess is None:
            return
        if not self._require_csrf(sess):
            return
        try:
            data = self._read_json()
        except ValueError as e:
            return self._error(400, str(e))
        current = data.get("current_password", "")
        new = data.get("new_password", "")
        if not isinstance(current, str) or not isinstance(new, str):
            return self._error(400, "invalid fields")
        try:
            ok = auth.change_password(
                Config.db_path, sess["admin_id"], current, new)
        except ValueError as e:
            return self._error(400, str(e))
        except Exception as e:
            log(f"[auth] change password failed: {e}")
            return self._error(500, "change password failed")
        if not ok:
            auth.audit(Config.db_path, sess["username"], self._client_ip(),
                       "password_change_fail")
            return self._error(400, "current password incorrect")
        # auth.change_password 已删除该用户全部会话；强制重新登录。
        auth.audit(Config.db_path, sess["username"], self._client_ip(),
                   "password_change")
        return self._send_json(200, {"ok": True, "relogin": True},
                               set_cookie=self._clear_cookie())

    def _logout(self) -> None:
        sess = self._require_session()
        if sess is None:
            return
        if not self._require_csrf(sess):
            return
        auth.delete_session(Config.db_path, self._cookie_raw())
        auth.audit(Config.db_path, sess["username"], self._client_ip(), "logout")
        return self._send_json(200, {"ok": True}, set_cookie=self._clear_cookie())

    def _list_admins(self, sess: dict) -> None:
        rows = auth.list_admins(Config.db_path)
        admins = [{
            "id": r["id"],
            "username": r["username"],
            "created_at": r["created_at"],
            "last_login_at": r["last_login_at"],
            "is_active": bool(r["is_active"]),
        } for r in rows]
        return self._send_json(200, {"admins": admins,
                                     "current": sess["username"]})

    def _create_admin(self, sess: dict) -> None:
        try:
            data = self._read_json()
        except ValueError as e:
            return self._error(400, str(e))
        username = data.get("username", "")
        password = data.get("password", "")
        if not isinstance(username, str) or not isinstance(password, str):
            return self._error(400, "invalid fields")
        try:
            auth.create_admin(Config.db_path, username, password)
        except ValueError as e:
            return self._error(400, str(e))
        except Exception as e:
            if "UNIQUE" in str(e).upper():
                return self._error(409, "username already exists")
            log(f"[auth] create admin failed: {e}")
            return self._error(500, "create admin failed")
        auth.audit(Config.db_path, sess["username"], self._client_ip(),
                   "admin_create", username)
        return self._send_json(200, {"ok": True, "username": username})

    # ---------------------------------------------------------------- 代理
    def _proxy(self, method: str) -> None:
        sess = self._require_session()
        if sess is None:
            return
        if method not in ("GET", "HEAD") and not self._require_csrf(sess):
            return
        if not Config.token:
            return self._error(502, "webadmin 未配置中转管理令牌",
                               hint="检查 start-admin-web.sh / ADMIN_TOKEN")

        body = b""
        if method in ("POST", "PUT", "PATCH"):
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return self._error(400, "Content-Length 非法")
            if n > MAX_BODY:
                return self._error(413, "请求体超过 8KB")
            body = self.rfile.read(n) if n else b""

        url = Config.controller.rstrip("/") + self.path
        headers = {"Connection": "close", "Accept": "application/json",
                   "Authorization": "Bearer " + Config.token}
        if body:
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=body or None, headers=headers, method=method)
        try:
            with _OPENER.open(req, timeout=UPSTREAM_TIMEOUT) as r:
                status, data = r.status, r.read()
        except urllib.error.HTTPError as e:
            status, data = e.code, e.read()
        except urllib.error.URLError as e:
            return self._error(502, "连不上中转站", f"{Config.controller} —— {e.reason}")
        except TimeoutError:
            return self._error(504, "中转站响应超时", f"{UPSTREAM_TIMEOUT:.0f}s")
        except OSError as e:
            return self._error(502, "连接中转站失败", str(e))

        if status == 401:
            # 浏览器会话是有效的；这里 401 说明 webadmin 持有的中转令牌失效。
            # 不能把 401 透传给前端，否则会被误判为“登录过期”而死循环。
            return self._error(502, "webadmin 服务端令牌失效",
                               hint="检查 relay_admin_token.txt 并重启 webadmin")
        self._send(status, data, "application/json; charset=utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="ScholarVPN 后台管理 Web 客户端（管理员登录 + vpn_controller 前端）")
    ap.add_argument("--listen", default=os.environ.get("WEBADMIN_BIND", "127.0.0.1"),
                    help="本服务监听地址，默认 127.0.0.1")
    ap.add_argument("--port", type=int, default=int(os.environ.get("WEBADMIN_PORT", "8080")),
                    help="本服务监听端口，默认 8080")
    ap.add_argument("--controller", default=os.environ.get("CONTROLLER_URL", "http://127.0.0.1:18081"),
                    help="中转站地址，默认 http://127.0.0.1:18081")
    ap.add_argument("--controller-ca", default=os.environ.get("CONTROLLER_CA", ""),
                    help="上游 HTTPS 的私有 CA 文件（公共 CA 留空）")
    ap.add_argument("--token", default=os.environ.get("ADMIN_TOKEN", ""),
                    help="中转管理令牌（只在服务端使用，不下发浏览器）")
    ap.add_argument("--db", default=os.environ.get("WEBADMIN_DB", Config.db_path),
                    help="SQLite 数据库路径")
    ap.add_argument("--cookie-secure", default=os.environ.get("WEBADMIN_COOKIE_SECURE", ""),
                    help="Cookie 是否带 Secure（默认 HTTPS 开启、HTTP 关闭）")
    ap.add_argument("--tls-cert", default=os.environ.get("WEBADMIN_TLS_CERT", ""),
                    help="本服务 HTTPS 证书链（fullchain.pem）")
    ap.add_argument("--tls-key", default=os.environ.get("WEBADMIN_TLS_KEY", ""),
                    help="本服务 HTTPS 私钥（privkey.pem，0600）")
    ap.add_argument("--vpn-public-ip", default=os.environ.get("VPN_PUBLIC_IP", ""),
                    help="VPN 服务器对外地址（公网 IP 或域名），页面展示供复制；"
                         "留空则自动探测出口 IP")
    ap.add_argument("--vpn-public-port", default=os.environ.get("VPN_PUBLIC_PORT", "51820"),
                    help="VPN 对外端口，默认 51820")
    args = ap.parse_args()

    Config.controller = args.controller.rstrip("/")
    Config.controller_ca = args.controller_ca or ""
    Config.token = args.token or ""
    Config.bind = args.listen
    Config.port = args.port
    Config.db_path = args.db
    Config.tls_cert = args.tls_cert or ""
    Config.tls_key = args.tls_key or ""
    Config.vpn_public_ip = (args.vpn_public_ip or "").strip()
    try:
        Config.vpn_public_port = int(args.vpn_public_port)
    except (TypeError, ValueError):
        Config.vpn_public_port = 51820

    if (Config.tls_cert and not Config.tls_key) or (Config.tls_key and not Config.tls_cert):
        log("[x] --tls-cert 与 --tls-key 必须同时提供")
        return 1
    Config.tls = bool(Config.tls_cert and Config.tls_key)
    if args.cookie_secure:
        Config.cookie_secure = args.cookie_secure not in ("0", "false", "no")
    else:
        Config.cookie_secure = Config.tls

    if Config.controller_ca:
        global _OPENER
        _OPENER = _build_opener(Config.controller_ca)

    if not os.path.isfile(os.path.join(HERE, "index.html")):
        log(f"[x] 找不到 {os.path.join(HERE, 'index.html')}")
        return 1

    try:
        auth.init_db(Config.db_path)
        auth.purge_expired(Config.db_path)
    except Exception as e:
        log(f"[x] 初始化数据库失败 {Config.db_path}: {e}")
        return 1

    srv = TimeoutThreadingHTTPServer((Config.bind, Config.port), Handler)
    srv.daemon_threads = True

    if Config.tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(Config.tls_cert, Config.tls_key)
        # 注意：**不要** wrap srv.socket。交给 get_request 手动握手，
        # 否则 SSLSocket.accept() 内的握手不受超时约束，半开连接会卡死整个服务。
        srv.ssl_context = ctx
    elif Config.bind not in ("127.0.0.1", "::1", "localhost"):
        log("[!] 警告: 管理页面以明文 HTTP 暴露在非环回地址。"
            "生产环境请配置 --tls-cert/--tls-key，或只绑 127.0.0.1 走 SSH 隧道。")

    scheme = "https" if Config.tls else "http"
    initialized = auth.count_admins(Config.db_path) > 0
    print(f"[+] 后台管理 Web 已启动: {scheme}://{Config.bind}:{Config.port}/", flush=True)
    print(f"    中转站: {Config.controller}", flush=True)
    print(f"    数据库: {Config.db_path}（管理员 {auth.count_admins(Config.db_path)} 个）", flush=True)
    print(f"    管理员初始化: {'已完成（登录页）' if initialized else '未完成（服务器执行 manage.py create-admin）'}", flush=True)
    print(f"    中转令牌: {'已配置（仅服务端使用）' if Config.token else '未配置 —— 登录后 API 会 502'}", flush=True)
    print(f"    TLS: {'已启用（TLS 1.2+）' if Config.tls else '未启用'}", flush=True)
    print("    Ctrl+C 退出", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] 已退出")
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
