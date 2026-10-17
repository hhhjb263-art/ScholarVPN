#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================================
# app.py —— ScholarVPN 后台管理 Web 客户端
# ----------------------------------------------------------------------------
# 给 vpn_controller 的极简 JSON API（默认 127.0.0.1:18081）套一层网页。
# 协议依据：docs/客户端实现方案接口.md
#
# 为什么需要这层代理，而不是网页直接 fetch 18081：
#   1) controller 不返回 CORS 头，浏览器从 file:// 或别的端口访问会被拦；
#   2) 管理令牌不该放进浏览器——放在服务端环境变量里，浏览器永远看不到；
#   3) controller 的 HTTP 入口是单线程、每请求短连接，集中代理更好控制超时。
#
# 零依赖：只用 Python 3 标准库（http.server + urllib），不需要 pip install。
#
# 用法：
#   ADMIN_TOKEN=xxxx python3 app.py                       # 令牌走环境变量（推荐）
#   python3 app.py --controller 127.0.0.1:18081 --port 8080
#   python3 app.py --listen 127.0.0.1 --port 8080         # 只给本机访问
#
#   令牌也可以不设，改在网页里输入（存在浏览器 sessionStorage，每次请求经
#   X-Admin-Token 头转给本服务）——适合临时排查，不推荐长期用。
#
# 环境变量：
#   ADMIN_TOKEN       controller 的管理令牌（Bearer）
#   CONTROLLER_URL    中转地址，默认 http://127.0.0.1:18081
#   WEBADMIN_BIND     本服务监听地址，默认 127.0.0.1
#   WEBADMIN_PORT     本服务监听端口，默认 8080
# ============================================================================
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# controller 的请求上限是 8192 字节（含头），这里给 body 留 8KB 是安全的
MAX_BODY = 8 * 1024
# controller 转发给 agent 等回执的上限是 10s，代理端留点余量
UPSTREAM_TIMEOUT = 15.0

HERE = os.path.dirname(os.path.abspath(__file__))

# 访问中转站时**显式禁用系统代理**。
# 很多服务器为 apt/docker 设了 http_proxy/https_proxy，urllib 会把它套到
# 连 127.0.0.1 / 内网 IP 的请求上，于是代理替我们回一个 502，
# 现象是"页面能开、所有接口都 502"——极难排查。
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


class Config:
    controller = "http://127.0.0.1:18081"
    token = ""
    bind = "127.0.0.1"
    port = 8080


class Handler(BaseHTTPRequestHandler):
    server_version = "ScholarVPN-WebAdmin/1.0"
    protocol_version = "HTTP/1.1"

    # ---------------------------------------------------------------- 工具
    def _send(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, status: int, obj) -> None:
        self._send(status, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _error(self, status: int, msg: str, hint: str = "") -> None:
        payload = {"error": msg}
        if hint:
            payload["hint"] = hint
        self._send_json(status, payload)

    def log_message(self, fmt: str, *args) -> None:  # 默认日志太吵，收敛一下
        log("  %s - %s" % (self.address_string(), fmt % args))

    # ---------------------------------------------------------------- 路由
    def do_GET(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path == "/" or path == "/index.html":
            return self._static("index.html", "text/html; charset=utf-8")
        if path == "/favicon.ico":
            return self._send(204, b"", "text/plain")
        if path.startswith("/api/"):
            return self._proxy("GET")
        self._error(404, "not found")

    def do_POST(self) -> None:
        if urllib.parse.urlsplit(self.path).path.startswith("/api/"):
            return self._proxy("POST")
        self._error(404, "not found")

    def do_DELETE(self) -> None:
        if urllib.parse.urlsplit(self.path).path.startswith("/api/"):
            return self._proxy("DELETE")
        self._error(404, "not found")

    def do_HEAD(self) -> None:
        self.do_GET()

    # ---------------------------------------------------------------- 静态
    def _static(self, name: str, ctype: str) -> None:
        p = os.path.join(HERE, name)
        try:
            with open(p, "rb") as f:
                self._send(200, f.read(), ctype)
        except OSError:
            self._error(500, f"静态文件缺失: {name}")

    # ---------------------------------------------------------------- 代理
    def _proxy(self, method: str) -> None:
        # 令牌：优先用请求头带来的（网页里填的），否则用服务端配置的
        token = self.headers.get("X-Admin-Token") or Config.token

        body = b""
        if method in ("POST", "PUT", "PATCH"):
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return self._error(400, "Content-Length 非法")
            if n > MAX_BODY:
                # controller 会回 413 并立即 close，我们提前挡掉更干净
                return self._error(413, "请求体超过 8KB")
            body = self.rfile.read(n) if n else b""

        # 路径原样透传：controller 不做 percent-decode，且 {id} 只保证 [A-Za-z0-9._-]
        url = Config.controller.rstrip("/") + self.path
        headers = {"Connection": "close", "Accept": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        if body:
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=body or None, headers=headers, method=method)
        try:
            with _OPENER.open(req, timeout=UPSTREAM_TIMEOUT) as r:
                status, data = r.status, r.read()
        except urllib.error.HTTPError as e:
            # controller / AdminServer 的 4xx·5xx 原样透传，别在这里改写语义
            status, data = e.code, e.read()
        except urllib.error.URLError as e:
            return self._error(502, "连不上中转站", f"{Config.controller} —— {e.reason}")
        except TimeoutError:
            return self._error(504, "中转站响应超时", f"{UPSTREAM_TIMEOUT:.0f}s")
        except OSError as e:
            return self._error(502, "连接中转站失败", str(e))

        # 透传状态码与响应体；Content-Type 统一按 JSON
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="ScholarVPN 后台管理 Web 客户端（vpn_controller 的网页前端）")
    ap.add_argument("--listen", default=os.environ.get("WEBADMIN_BIND", "127.0.0.1"),
                    help="本服务监听地址，默认 127.0.0.1")
    ap.add_argument("--port", type=int, default=int(os.environ.get("WEBADMIN_PORT", "8080")),
                    help="本服务监听端口，默认 8080")
    ap.add_argument("--controller", default=os.environ.get("CONTROLLER_URL", "http://127.0.0.1:18081"),
                    help="中转站地址，默认 http://127.0.0.1:18081")
    ap.add_argument("--token", default=os.environ.get("ADMIN_TOKEN", ""),
                    help="中转站管理令牌；也可留空，改在网页里输入")
    args = ap.parse_args()

    Config.controller = args.controller.rstrip("/")
    Config.token = args.token or ""
    Config.bind = args.listen
    Config.port = args.port

    if not os.path.isfile(os.path.join(HERE, "index.html")):
        log(f"[x] 找不到 {os.path.join(HERE, 'index.html')}")
        return 1

    srv = ThreadingHTTPServer((Config.bind, Config.port), Handler)
    srv.daemon_threads = True

    print(f"[+] 后台管理 Web 已启动: http://{Config.bind}:{Config.port}/", flush=True)
    print(f"    中转站: {Config.controller}", flush=True)
    print(f"    管理令牌: {'已配置（环境变量/参数）' if Config.token else '未配置 —— 请在网页里输入'}", flush=True)
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
