# ============================================================================
# tools/webadmin/test_service_panel.py —— 用户管理面板接口的本地端到端测试
#
# 起真实 app.py（临时端口 + 种子受管服务库 + 临时管理员库），验证：
#   未登录 401 / 登录 / CSRF 拦截 / 用户列表 / 转正式 / 拒绝 /
#   非法与未知 fp / 审计查询 / 黑名单增查删 / 既有登录体系不受影响
# 运行：python tools/webadmin/test_service_panel.py（无需真实 broker/controller）
# ============================================================================
import io
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools", "broker"))
sys.path.insert(0, os.path.join(ROOT, "tools", "webadmin"))
import db as svc_db        # noqa: E402
import auth                # noqa: E402

g_pass = 0
g_fail = 0


def check(ok, what):
    global g_pass, g_fail
    if ok:
        g_pass += 1
    else:
        g_fail += 1
        print("  FAIL ", what)


def req(method, url, body=None, headers=None):
    h = dict(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def main():
    tmp = tempfile.mkdtemp(prefix="svp-webadmin-test-")
    port = 18099
    base = f"http://127.0.0.1:{port}"
    svc_db_path = os.path.join(tmp, "service.db")
    admin_db = os.path.join(tmp, "webadmin.db")
    try:
        # ---- 种子：受管服务库 ----
        conn = svc_db.connect(svc_db_path)
        svc_db.init_db(conn)
        now = int(time.time())
        svc_db.create_trial(conn, fp="a" * 64, client_id="trial-aaaa0001",
                            token_hash="x1", os_name="Windows 11", cpu="i7",
                            ram_mb=16384, mac_hash="m1", ip="1.2.3.4",
                            created_at=now, expire_at=now + 86400,
                            quota_bytes=2 * 1024 ** 3)
        svc_db.create_trial(conn, fp="b" * 64, client_id="trial-bbbb0002",
                            token_hash="x2", os_name="Ubuntu 24.04", cpu="EPYC",
                            ram_mb=8192, mac_hash="m2", ip="5.6.7.8",
                            created_at=now, expire_at=0, quota_bytes=0)
        svc_db.upsert_audit(conn, "2026-10-31", "trial-aaaa0001", "example.com", 5)
        svc_db.upsert_blacklist(conn, "t.me", "测试")
        conn.close()

        # ---- 管理员账号 ----
        auth.init_db(admin_db)
        auth.create_admin(admin_db, "tester", "password123")

        # ---- 启动 app.py ----
        env = dict(os.environ, SVC_DB=svc_db_path)
        proc = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "tools", "webadmin", "app.py"),
             "--listen", "127.0.0.1", "--port", str(port), "--db", admin_db,
             "--controller", "http://127.0.0.1:19999", "--token", "x"],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        try:
            for _ in range(50):
                st, _, _ = req("GET", base + "/api/auth/status")
                if st == 200:
                    break
                time.sleep(0.1)

            # 1. 未登录访问 → 401
            st, _, _ = req("GET", base + "/api/service/users")
            check(st == 401, "未登录 401")

            # 2. 登录
            st, h, body = req("POST", base + "/api/auth/login",
                              {"username": "tester", "password": "password123"})
            check(st == 200, "登录成功")
            cookie = ""
            for v in h.get("Set-Cookie", "").split(";"):
                if v.strip().startswith("sv_admin_session="):
                    cookie = v.strip()
            check(bool(cookie), "获得会话 Cookie")

            # 3. me → CSRF
            st, _, body = req("GET", base + "/api/auth/me", headers={"Cookie": cookie})
            me = json.loads(body)
            check(st == 200 and me.get("csrf"), "取得 CSRF token")
            csrf = me["csrf"]
            hdr = {"Cookie": cookie, "X-CSRF-Token": csrf}

            # 4. 用户列表
            st, _, body = req("GET", base + "/api/service/users", headers=hdr)
            users = json.loads(body)["users"]
            check(st == 200 and len(users) == 2, "用户列表 2 条")

            # 5. 无 CSRF 的写请求 → 403
            st, _, _ = req("POST", base + "/api/service/users/approve",
                           {"fp": "a" * 64}, {"Cookie": cookie})
            check(st == 403, "缺 CSRF 403")

            # 6. 转正式
            st, _, body = req("POST", base + "/api/service/users/approve",
                              {"fp": "a" * 64}, hdr)
            check(st == 200, "approve 200")
            conn = sqlite3.connect(svc_db_path)
            row = conn.execute("SELECT status, expire_at, quota_bytes FROM trials"
                               " WHERE fp=?", ("a" * 64,)).fetchone()
            conn.close()
            check(row == ("approved", 0, 0), "DB 落库 approved/quota=0/expire=0")

            # 7. 拒绝另一个
            st, _, body = req("POST", base + "/api/service/users/reject",
                              {"fp": "b" * 64}, hdr)
            check(st == 200, "reject 200")

            # 7b. 取消授权（approved → revoked）
            conn = sqlite3.connect(svc_db_path)
            conn.execute("UPDATE trials SET status='approved' WHERE fp=?", ("a" * 64,))
            conn.commit(); conn.close()
            st, _, body = req("POST", base + "/api/service/users/revoke",
                              {"fp": "a" * 64}, hdr)
            check(st == 200, "revoke 200")
            conn = sqlite3.connect(svc_db_path)
            row = conn.execute("SELECT status FROM trials WHERE fp=?", ("a" * 64,)).fetchone()
            conn.close()
            check(row == ("revoked",), "DB 落库 revoked")

            # 7b-2. 垃圾桶：恢复（重新给一轮试用）与彻底删除
            st, _, _ = req("POST", base + "/api/service/users/restore",
                           {"fp": "a" * 64}, hdr)
            check(st == 200, "restore 200")
            conn = sqlite3.connect(svc_db_path)
            row = conn.execute("SELECT status, expire_at, quota_bytes FROM trials"
                               " WHERE fp=?", ("a" * 64,)).fetchone()
            conn.close()
            check(row[0] == "trial" and row[1] > 0 and row[2] == 2 * 1024 ** 3,
                  "恢复 = 新一轮试用（3 天 / 2GB）")
            st, _, _ = req("POST", base + "/api/service/users/revoke",
                           {"fp": "a" * 64}, hdr)
            check(st == 200, "再取消授权回到垃圾桶")
            st, _, _ = req("DELETE", base + "/api/service/users/" + "a" * 64,
                           headers=hdr)
            check(st == 200, "彻底删除 200")
            conn = sqlite3.connect(svc_db_path)
            row = conn.execute("SELECT COUNT(*) FROM trials WHERE fp=?",
                               ("a" * 64,)).fetchone()
            conn.close()
            check(row == (0,), "记录已抹除")
            st, _, _ = req("DELETE", base + "/api/service/users/" + "a" * 64,
                           headers=hdr)
            check(st == 404, "重复删除 404")

            # 8. 非法 fp → 400；未知 fp → 404
            st, _, _ = req("POST", base + "/api/service/users/approve",
                           {"fp": "zz"}, hdr)
            check(st == 400, "非法 fp 400")
            st, _, _ = req("POST", base + "/api/service/users/approve",
                           {"fp": "c" * 64}, hdr)
            check(st == 404, "未知 fp 404")

            # 9. 审计查询
            st, _, body = req("GET", base + "/api/service/audit?client_id=trial-aaaa0001",
                              headers=hdr)
            audit = json.loads(body)["audit"]
            check(st == 200 and len(audit) == 1 and audit[0]["domain"] == "example.com",
                  "审计查询")

            # 10. 黑名单增/查/删（三种类型）
            st, _, _ = req("POST", base + "/api/service/blacklist",
                           {"domain": "x.example.com", "note": "n", "type": "domain"}, hdr)
            check(st == 200, "黑名单添加（域名）")
            st, _, _ = req("POST", base + "/api/service/blacklist",
                           {"domain": "9.9.9.9", "note": "", "type": "ip"}, hdr)
            check(st == 200, "黑名单添加（IP）")
            st, _, _ = req("POST", base + "/api/service/blacklist",
                           {"domain": "trial-aaaa0001", "note": "", "type": "machine"}, hdr)
            check(st == 200, "黑名单添加（整机）")
            st, _, body = req("GET", base + "/api/service/blacklist", headers=hdr)
            bl = json.loads(body)["blacklist"]
            types = {r["domain"]: r.get("type", "domain") for r in bl}
            check(st == 200 and types.get("x.example.com") == "domain"
                  and types.get("9.9.9.9") == "ip"
                  and types.get("trial-aaaa0001") == "machine", "黑名单列表带类型")
            st, _, _ = req("DELETE", base + "/api/service/blacklist/x.example.com",
                           headers=hdr)
            check(st == 200, "黑名单删除")
            st, _, _ = req("POST", base + "/api/service/blacklist",
                           {"domain": "not a domain!!", "type": "domain"}, hdr)
            check(st == 400, "非法域名 400")
            st, _, _ = req("POST", base + "/api/service/blacklist",
                           {"domain": "1.2.3.4.5", "type": "ip"}, hdr)
            check(st == 400, "非法 IP 400")

            # 11. 既有功能不受影响：/ → 登录跳转（不跟随重定向）；静态页 200
            import http.client
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("GET", "/")
            r = c.getresponse()
            body = r.read()
            c.close()
            check(r.status == 302 and (r.getheader("Location") or "") == "/login",
                  "/ 302 → /login")
            st, _, _ = req("GET", base + "/login")
            check(st == 200, "登录页 200")
            st, _, _ = req("GET", base + "/api/auth/status")
            check(st == 200, "auth/status 200")
        finally:
            proc.terminate()
            proc.wait(timeout=10)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n结果: {g_pass} 通过, {g_fail} 失败")
    return 0 if g_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
