#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================================
# tools/broker/test_broker.py —— broker 端到端测试（本机起真实 HTTP 服务）
#
# 覆盖：注册/签名验签/换发/同 IP 限频/状态查询/404/静态列表签名/审批转正式/篡改拒绝
# 运行：python tools/broker/test_broker.py
# ============================================================================

import base64
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
BROKER = os.path.join(HERE, "broker.py")

sys.path.insert(0, HERE)
import db  # noqa: E402

from cryptography.hazmat.primitives import serialization          # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (   # noqa: E402
    Ed25519PrivateKey,
)

g_pass = 0
g_fail = 0


def check(ok: bool, what: str) -> None:
    global g_pass, g_fail
    if ok:
        g_pass += 1
    else:
        g_fail += 1
        print(f"  FAIL  {what}")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def get(url: str):
    """返回 (status, headers, body)。HTTPError 也带回响应。"""
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def parse_ini(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip()
    return out


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="svp-broker-test-")
    try:
        # ---- 现场生成 service 密钥对（与 release.key 同格式，PKCS8 PEM）----
        key = Ed25519PrivateKey.generate()
        key_path = os.path.join(tmp, "service.key")
        pub_path = os.path.join(tmp, "service_pub.pem")
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        pub_pem = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        with open(pub_path, "wb") as f:
            f.write(pub_pem)
        pub = serialization.load_pem_public_key(pub_pem)

        def verify_sig(body: bytes, sig_b64: str) -> bool:
            try:
                pub.verify(base64.b64decode(sig_b64), body)
                return True
            except Exception:
                return False

        db_path = os.path.join(tmp, "service.db")
        tokens_path = os.path.join(tmp, "register_tokens.txt")
        list_dir = os.path.join(tmp, "svc")
        port = free_port()
        env = dict(os.environ,
                   SERVICE_TOKENS_FILE=tokens_path,
                   SERVICE_IP_LIMIT="3")
        base = f"http://127.0.0.1:{port}"

        proc = subprocess.Popen(
            [sys.executable, BROKER, "serve", "--db", db_path,
             "--bind", "127.0.0.1", "--port", str(port),
             "--key", key_path, "--list-dir", list_dir],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        try:
            for _ in range(50):     # 等服务起来
                try:
                    get(base + "/trial/status?fp=" + "0" * 64)
                    break
                except OSError:
                    time.sleep(0.1)

            fp1 = "a" * 64
            # ---- 1. 注册：200 + 签名可验 + 字段正确 + 令牌落 register_tokens.txt
            st, hd, body = get(base + f"/trial/register?fp={fp1}"
                               f"&os=Windows%2010.0&cpu=Intel%20i7&ram=16384"
                               f"&mac=aabbccddeeff11223344556677889900")
            ini = parse_ini(body.decode("utf-8"))
            check(st == 200, "注册返回 200")
            check(verify_sig(body, hd.get("X-Service-Signature", "")),
                  "注册响应签名可验")
            check(ini.get("status") == "trial", "状态 trial")
            check(ini.get("client_id", "").startswith("trial-"), "client_id 前缀")
            check(len(ini.get("token", "")) == 64, "注册响应携带 64hex 令牌")
            check(int(ini.get("quota_bytes", "0")) == 2 * 1024 ** 3, "配额 2GB")
            check(int(ini.get("expire_at", "0")) > int(ini.get("issued", "0")),
                  "到期时间晚于签发时间")
            with open(tokens_path, encoding="utf-8") as f:
                toks = f.read().split()
            check(ini.get("token") in toks, "令牌已追加进 register_tokens.txt")
            check(db.get_trial(db.connect(db_path), fp1)["mac_hash"]
                  == "aabbccddeeff11223344556677889900", "机器指纹字段入库")

            # ---- 2. 同 fp 换发：client_id 不变、新令牌、两枚令牌都在文件里
            st, hd, body = get(base + f"/trial/register?fp={fp1}")
            ini2 = parse_ini(body.decode("utf-8"))
            check(st == 200 and verify_sig(body, hd.get("X-Service-Signature", "")),
                  "换发响应 200 且签名可验")
            check(ini2.get("client_id") == ini.get("client_id"), "换发 client_id 不变")
            check(ini2.get("token") != ini.get("token"), "换发产生新令牌")
            with open(tokens_path, encoding="utf-8") as f:
                toks = f.read().split()
            check(ini2.get("token") in toks and ini.get("token") in toks,
                  "两枚令牌均在 register_tokens.txt")

            # ---- 3. 同 IP 限频：第 3、4 个新 fp → 第 4 个被 429
            for i in range(2):
                st, _, _ = get(base + f"/trial/register?fp={'b' * 63}{i}")
                check(st == 200, f"新 fp #{i + 2} 注册成功")
            st, _, _ = get(base + f"/trial/register?fp={'c' * 64}")
            check(st == 429, "同 IP 第 4 次新申请被限频 429")

            # ---- 4. 状态查询：无 token 字段；未知 fp 404
            st, hd, body = get(base + f"/trial/status?fp={fp1}")
            ini3 = parse_ini(body.decode("utf-8"))
            check(st == 200 and "token" not in ini3, "状态查询不回明文令牌")
            check(verify_sig(body, hd.get("X-Service-Signature", "")),
                  "状态响应签名可验")
            st, _, _ = get(base + "/trial/status?fp=" + "e" * 64)
            check(st == 404, "未知 fp 返回 404")

            # ---- 5. 服务器列表：CLI 生成 + 静态下发 + 签名可验 + 篡改被拒
            pub_b64 = base64.b64encode(key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
            r = subprocess.run(
                [sys.executable, BROKER, "server-list", "--db", db_path,
                 "--key", key_path, "--out-dir", list_dir,
                 "--server", "203.0.113.7:51820", "--pubkey", pub_b64,
                 "--remark", "HK-01"],
                capture_output=True, text=True)
            check(r.returncode == 0, "server-list CLI 生成成功")
            # 受控下发：只有已登记设备（注册过的 fp）能拿到列表
            st, _, _ = get(base + "/svc/server-list.ini")
            check(st == 403, "未登记设备拉列表被拒 403")
            st, _, body = get(base + "/svc/server-list.ini?fp=" + fp1)
            check(st == 200 and b"server1 = 203.0.113.7:51820" in body,
                  "已登记设备拉列表 200")
            st, _, sig = get(base + "/svc/server-list.ini.sig?fp=" + fp1)
            check(st == 200 and verify_sig(body, sig.decode("ascii")),
                  "列表签名可验")
            check(not verify_sig(body + b"x", sig.decode("ascii")),
                  "篡改列表内容后验签失败")

            # ---- 6. 审批转正式：解除配额与到期
            r = subprocess.run(
                [sys.executable, BROKER, "approve", "--db", db_path,
                 "--fp", fp1], capture_output=True, text=True)
            check(r.returncode == 0, "approve CLI 成功")
            st, _, body = get(base + f"/trial/status?fp={fp1}")
            ini4 = parse_ini(body.decode("utf-8"))
            check(ini4.get("status") == "approved"
                  and ini4.get("quota_bytes") == "0"
                  and ini4.get("expire_at") == "0",
                  "转正式后 quota=0 expire=0")

            # ---- 7. 黑名单读写（三种类型 + 迁移兼容）
            conn = db.connect(db_path)
            db.upsert_blacklist(conn, "t.me", "示例")
            db.upsert_blacklist(conn, "t.me", "示例2")
            db.upsert_blacklist(conn, "1.2.3.4", "示例", "ip")
            db.upsert_blacklist(conn, "trial-aaaa0001", "", "machine")
            bl = db.list_blacklist(conn)
            check(len(bl) == 3, "黑名单去重更新")
            by_v = {r["domain"]: r["type"] for r in bl}
            check(by_v.get("t.me") == "domain" and by_v.get("1.2.3.4") == "ip"
                  and by_v.get("trial-aaaa0001") == "machine", "黑名单类型入库")
            conn.close()
        finally:
            proc.terminate()
            proc.wait(timeout=10)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n结果: {g_pass} 通过, {g_fail} 失败")
    return 0 if g_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
