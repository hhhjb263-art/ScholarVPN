#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""演示用的假 vpn_controller —— 只为让 Web 管理端有数据可看。
接口形状严格按 docs/客户端实现方案接口.md 第 2 节。"""
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ADMIN_TOKEN = "goodtoken"
TOKENS = [
    "7f3a91c2e8b04d16a5c7f2093b8e6d41c0a9f27e5b3d1864c2e07f9a4b6d3e18",
    "b1d4e7f02a6c9385d1e4f7a0c3b6d9e2f5a8c1d4e7b0f3a6c9d2e5f8b1a4c7d0",
    "c2e5f8b1a4d7c0e3f6a9d2b5e8c1f4a7d0b3e6f9c2a5d8b1e4f7a0c3d6b9e2f5",
]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _auth(self):
        if self.headers.get("Authorization") != "Bearer " + ADMIN_TOKEN:
            self._json(401, {"error": "unauthorized"})
            return False
        return True

    def do_GET(self):
        if not self._auth():
            return
        p = self.path
        if p == "/api/servers":
            return self._json(200, {"servers": [{
                "id": "hk-01",
                "pubkey_hex": "25d87aa460a40de6ff62a2fac3dee2c8c1cf99dcc424d31c2be8863a5549b446",
                "ip": "203.0.113.7",
                "last_seen": 128374923,
            }]})
        if p.endswith("/info"):
            return self._json(200, {
                "version": "1.0",
                "pubkey_pem": ("-----BEGIN PUBLIC KEY-----\n"
                               "MCowBQYDK2VwAyEAJdhqpGCkDe8V9f7V6obYCuNV8JYcO4tP0FTU2tWSuSw=\n"
                               "-----END PUBLIC KEY-----\n"),
                "pubkey_hex": "25d87aa460a40de6ff62a2fac3dee2c8c1cf99dcc424d31c2be8863a5549b446",
                "ip": "0.0.0.0",
                "port": 51820,
            })
        if p.endswith("/tokens"):
            return self._json(200, {"tokens": TOKENS})
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if not self._auth():
            return
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return self._json(400, {"error": "bad request"})
        c = int(body.get("count", 0))
        if not (1 <= c <= 1000):
            return self._json(400, {"error": "count must be 1-1000"})
        new = ["%064x" % (0x5eed000 + i) for i in range(c)]
        TOKENS.extend(new)
        self._json(200, {"tokens": new})

    def do_DELETE(self):
        if not self._auth():
            return
        m = re.match(r"^/api/servers/[^/]+/tokens/([0-9a-f]+)$", self.path)
        if not m:
            return self._json(404, {"error": "not found"})
        t = m.group(1)
        if t in TOKENS:
            TOKENS.remove(t)
            return self._json(200, {"deleted": True})
        self._json(404, {"error": "token not found"})


if __name__ == "__main__":
    print("[mock] fake vpn_controller on 127.0.0.1:19998 (token=goodtoken)", flush=True)
    ThreadingHTTPServer(("127.0.0.1", 19998), Handler).serve_forever()
