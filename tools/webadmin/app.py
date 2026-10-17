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
#   · 登录/注册限速，错误提示不区分用户名是否存在；
#   · 首次管理员用一次性初始化令牌创建，之后注册关闭，由已登录管理员添加；
#   · 中转管理令牌只保存在服务端，用于访问 127.0.0.1:18081，浏览器永远拿不到。
#
# 零第三方依赖：只用 Python 3 标准库 + OpenSSL（ssl/sqlite3/hashlib）。
# ============================================================================
from __future__ import annotations

import argparse
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

MAX_BODY = 8 * 1024
UPSTREAM_TIMEOUT = 15.0
COOKIE_NAME = "sv_admin_session"

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
    bootstrap_token = ""    # 首次管理员初始化令牌
    bind = "127.0.0.1"
    port = 8080
    tls_cert = ""
    tls_key = ""
    tls = False
    cookie_secure = False
    db_path = os.path.join(HERE, "data", "webadmin.db")


def _json_bytes(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "ScholarVPN-WebAdmin/2.0"
    protocol_version = "HTTP/1.1"

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
        self.send_header("Connection", "close")
        self._security_headers()
        if location:
            self.send_header("Location", location)
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.close_connection = True
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
        allowed = {"index.html", "login.html", "register.html"}
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
        if path in ("/login", "/register"):
            if self._session() is not None:
                return self._redirect("/")
            name = "login.html" if path == "/login" else "register.html"
            return self._static(name, "text/html; charset=utf-8")
        if path == "/favicon.ico":
            return self._send(204, b"", "text/plain")
        if path == "/api/auth/status":
            initialized = auth.count_admins(Config.db_path) > 0
            return self._send_json(200, {
                "initialized": initialized,
                "registration_open": not initialized,
            })
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
        if path.startswith("/api/"):
            return self._proxy("GET")
        return self._error(404, "not found")

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_POST(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path == "/api/auth/register":
            return self._register()
        if path == "/api/auth/login":
            return self._login()
        if path == "/api/auth/logout":
            return self._logout()
        if path == "/api/admin/users":
            sess = self._require_session()
            if sess is None:
                return
            if not self._require_csrf(sess):
                return
            return self._create_admin(sess)
        if path.startswith("/api/"):
            return self._proxy("POST")
        return self._error(404, "not found")

    def do_DELETE(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path.startswith("/api/"):
            return self._proxy("DELETE")
        return self._error(404, "not found")

    # ---------------------------------------------------------------- 认证
    def _register(self) -> None:
        if not self._same_origin():
            return self._error(403, "origin not allowed")
        ip = self._client_ip()
        wait = _RATE.retry_after(f"register:ip:{ip}", 5, 3600)
        if wait:
            return self._error(429, "too many attempts", headers={"Retry-After": str(wait)})
        _RATE.hit(f"register:ip:{ip}", 3600)

        try:
            data = self._read_json()
        except ValueError as e:
            return self._error(400, str(e))
        username = data.get("username", "")
        password = data.get("password", "")
        bootstrap = data.get("bootstrap_token", "")
        if not isinstance(username, str) or not isinstance(password, str) \
                or not isinstance(bootstrap, str):
            return self._error(400, "invalid fields")

        if auth.count_admins(Config.db_path) > 0:
            return self._error(403, "registration closed",
                               hint="首个管理员已创建；后续账号请由已登录管理员添加")
        if not Config.bootstrap_token or not hmac.compare_digest(
                bootstrap.encode("utf-8", "ignore"),
                Config.bootstrap_token.encode("utf-8")):
            auth.audit(Config.db_path, username, ip, "register_fail", "bad bootstrap")
            return self._error(403, "invalid bootstrap token")

        try:
            admin_id = auth.create_first_admin(Config.db_path, username, password)
        except PermissionError:
            return self._error(403, "registration closed")
        except ValueError as e:
            return self._error(400, str(e))
        except Exception as e:
            log(f"[auth] create first admin failed: {e}")
            return self._error(500, "create admin failed")

        raw, _csrf = auth.create_session(
            Config.db_path, admin_id, ip, self.headers.get("User-Agent", ""))
        auth.audit(Config.db_path, username, ip, "register_ok")
        return self._send_json(200, {"ok": True, "username": username},
                               set_cookie=self._set_cookie(raw))

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
    ap.add_argument("--bootstrap-token", default=os.environ.get("WEBADMIN_BOOTSTRAP_TOKEN", ""),
                    help="首次管理员初始化令牌；留空则复用 --token")
    ap.add_argument("--db", default=os.environ.get("WEBADMIN_DB", Config.db_path),
                    help="SQLite 数据库路径")
    ap.add_argument("--cookie-secure", default=os.environ.get("WEBADMIN_COOKIE_SECURE", ""),
                    help="Cookie 是否带 Secure（默认 HTTPS 开启、HTTP 关闭）")
    ap.add_argument("--tls-cert", default=os.environ.get("WEBADMIN_TLS_CERT", ""),
                    help="本服务 HTTPS 证书链（fullchain.pem）")
    ap.add_argument("--tls-key", default=os.environ.get("WEBADMIN_TLS_KEY", ""),
                    help="本服务 HTTPS 私钥（privkey.pem，0600）")
    args = ap.parse_args()

    Config.controller = args.controller.rstrip("/")
    Config.controller_ca = args.controller_ca or ""
    Config.token = args.token or ""
    Config.bootstrap_token = args.bootstrap_token or Config.token
    Config.bind = args.listen
    Config.port = args.port
    Config.db_path = args.db
    Config.tls_cert = args.tls_cert or ""
    Config.tls_key = args.tls_key or ""

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

    srv = ThreadingHTTPServer((Config.bind, Config.port), Handler)
    srv.daemon_threads = True

    if Config.tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(Config.tls_cert, Config.tls_key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    elif Config.bind not in ("127.0.0.1", "::1", "localhost"):
        log("[!] 警告: 管理页面以明文 HTTP 暴露在非环回地址。"
            "生产环境请配置 --tls-cert/--tls-key，或只绑 127.0.0.1 走 SSH 隧道。")

    scheme = "https" if Config.tls else "http"
    initialized = auth.count_admins(Config.db_path) > 0
    print(f"[+] 后台管理 Web 已启动: {scheme}://{Config.bind}:{Config.port}/", flush=True)
    print(f"    中转站: {Config.controller}", flush=True)
    print(f"    数据库: {Config.db_path}（管理员 {auth.count_admins(Config.db_path)} 个）", flush=True)
    print(f"    管理员初始化: {'已完成（登录页）' if initialized else '未完成（访问 /register 创建首个管理员）'}", flush=True)
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
