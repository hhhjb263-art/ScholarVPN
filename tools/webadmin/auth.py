#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================================
# auth.py —— 后台管理网页的管理员认证（SQLite）
# ----------------------------------------------------------------------------
# 安全设计：
#   · 所有 SQL 使用 ? 参数化，绝不拼接用户输入；表名/列名固定。
#   · 密码用 hashlib.scrypt（OpenSSL 实现）+ 每用户随机盐，常量时间比较；
#     数据库只存 hash，不存明文。
#   · 会话令牌随机 256-bit，数据库只存 SHA-256；Cookie 为 HttpOnly/Secure/
#     SameSite=Strict；登录时换新令牌（防会话固定）。
#   · CSRF：会话内随机 token，所有写操作必须带 X-CSRF-Token。
#   · 登录/注册失败限速；登录错误统一提示，避免用户名枚举。
#   · 首次管理员只能通过一次性初始化令牌创建；之后注册关闭，由已登录管理员
#     创建更多账号。
# ============================================================================
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager

# ---- 密码哈希参数（将来升级参数时保留旧 hash 的可验证性） ----
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SCRYPT_MAXMEM = 128 * 1024 * 1024

# ---- 会话 ----
SESSION_IDLE = 12 * 3600          # 12 小时无操作过期
SESSION_ABSOLUTE = 7 * 24 * 3600  # 最长 7 天
COOKIE_MAX_AGE = SESSION_IDLE

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
PASSWORD_MIN = 10
PASSWORD_MAX = 128

# 限制同时进行的 scrypt 计算，避免大量登录请求把内存/CPU 打满。
_SCRYPT_SEM = threading.BoundedSemaphore(4)


def _scrypt(password: bytes, salt: bytes, n: int, r: int, p: int, dklen: int) -> bytes:
    with _SCRYPT_SEM:
        return hashlib.scrypt(password, salt=salt, n=n, r=r, p=p,
                              dklen=dklen, maxmem=SCRYPT_MAXMEM)

SCHEMA = """
CREATE TABLE IF NOT EXISTS admins (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    last_login_at INTEGER,
    is_active     INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash  TEXT PRIMARY KEY,
    admin_id    INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    csrf        TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    ip          TEXT NOT NULL DEFAULT '',
    user_agent  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sessions_admin ON sessions(admin_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS audit (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    username TEXT NOT NULL DEFAULT '',
    ip       TEXT NOT NULL DEFAULT '',
    action   TEXT NOT NULL,
    detail   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
"""


def now() -> int:
    return int(time.time())


def validate_username(username: str) -> bool:
    return bool(USERNAME_RE.fullmatch(username or ""))


def validate_password(username: str, password: str) -> str | None:
    """返回错误说明；None 表示通过。"""
    if not (PASSWORD_MIN <= len(password) <= PASSWORD_MAX):
        return f"密码长度需在 {PASSWORD_MIN}–{PASSWORD_MAX} 之间"
    if password == username:
        return "密码不能与用户名相同"
    if not any(not c.isspace() for c in password):
        return "密码不能全是空白"
    return None


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = _scrypt(password.encode("utf-8"), salt, SCRYPT_N, SCRYPT_R,
                 SCRYPT_P, SCRYPT_DKLEN)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64e(salt)}${_b64e(dk)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n_s, r_s, p_s, salt_s, hash_s = stored.split("$")
        if algo != "scrypt":
            return False
        n, r, p = int(n_s), int(r_s), int(p_s)
        # 限制参数，避免被恶意 DB 内容拖垮 CPU/内存
        if not (2 ** 12 <= n <= 2 ** 17 and 1 <= r <= 16 and 1 <= p <= 4):
            return False
        salt = _b64d(salt_s)
        expected = _b64d(hash_s)
        if len(expected) < 16 or len(expected) > 64:
            return False
        dk = _scrypt(password.encode("utf-8"), salt, n, r, p, len(expected))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


# 用户不存在时也做一次同样开销的校验，降低用户名枚举的时序差异。
_DUMMY_HASH = hash_password(secrets.token_hex(16))


@contextmanager
def _db(path: str):
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(path: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, mode=0o700, exist_ok=True)
    try:
        os.chmod(parent, 0o700)
    except OSError:
        pass
    with _db(path) as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(SCHEMA)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def count_admins(path: str) -> int:
    with _db(path) as conn:
        row = conn.execute("SELECT COUNT(*) AS n FROM admins").fetchone()
        return int(row["n"])


def _insert_admin(conn, username: str, password: str) -> int:
    err = validate_password(username, password)
    if err:
        raise ValueError(err)
    if not validate_username(username):
        raise ValueError("用户名需为 3–32 位字母、数字、点、下划线或短横线")
    cur = conn.execute(
        "INSERT INTO admins(username, password_hash, created_at) VALUES(?,?,?)",
        (username, hash_password(password), now()),
    )
    return int(cur.lastrowid)


def create_admin(path: str, username: str, password: str) -> int:
    """已登录管理员创建新账号（不自动登录新账号）。"""
    with _db(path) as conn:
        return _insert_admin(conn, username, password)


def create_first_admin(path: str, username: str, password: str) -> int:
    """只在系统没有任何管理员时创建；用写事务避免并发抢注。"""
    with _db(path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        n = conn.execute("SELECT COUNT(*) AS n FROM admins").fetchone()["n"]
        if int(n) != 0:
            raise PermissionError("registration closed")
        return _insert_admin(conn, username, password)


def authenticate(path: str, username: str, password: str) -> dict | None:
    """成功返回 {id, username}；失败返回 None。"""
    if not isinstance(username, str) or not isinstance(password, str):
        return None
    if len(username) > 64 or len(password) > PASSWORD_MAX:
        # 仍然做一次 dummy 校验，保持时序
        verify_password(password[:PASSWORD_MAX], _DUMMY_HASH)
        return None

    with _db(path) as conn:
        row = conn.execute(
            "SELECT id, username, password_hash, is_active FROM admins "
            "WHERE username = ? COLLATE NOCASE",
            (username,),
        ).fetchone()
        if row is None or int(row["is_active"]) != 1:
            verify_password(password, _DUMMY_HASH)
            return None
        if not verify_password(password, row["password_hash"]):
            return None
        conn.execute(
            "UPDATE admins SET last_login_at = ? WHERE id = ?",
            (now(), int(row["id"])),
        )
        return {"id": int(row["id"]), "username": row["username"]}


def set_password(path: str, username: str, password: str) -> bool:
    """恢复/重置密码；成功后删除该管理员的全部会话，强制重新登录。"""
    err = validate_password(username, password)
    if err:
        raise ValueError(err)
    with _db(path) as conn:
        row = conn.execute(
            "SELECT id FROM admins WHERE username = ? COLLATE NOCASE", (username,)
        ).fetchone()
        if row is None:
            return False
        conn.execute(
            "UPDATE admins SET password_hash = ? WHERE id = ?",
            (hash_password(password), int(row["id"])),
        )
        conn.execute("DELETE FROM sessions WHERE admin_id = ?", (int(row["id"]),))
        return True


def list_admins(path: str) -> list[dict]:
    with _db(path) as conn:
        rows = conn.execute(
            "SELECT id, username, created_at, last_login_at, is_active "
            "FROM admins ORDER BY id"
        ).fetchall()
        return [dict(r) for r in rows]


def _token_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def create_session(path: str, admin_id: int, ip: str = "", ua: str = "") -> tuple[str, str]:
    """返回 (raw_token, csrf)。raw token 只进 Cookie，DB 存 SHA-256。"""
    raw = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    ts = now()
    with _db(path) as conn:
        conn.execute(
            "INSERT INTO sessions(token_hash, admin_id, csrf, created_at, last_seen, "
            "expires_at, ip, user_agent) VALUES(?,?,?,?,?,?,?,?)",
            (_token_hash(raw), admin_id, csrf, ts, ts,
             ts + SESSION_ABSOLUTE, ip[:64], ua[:255]),
        )
    return raw, csrf


def get_session(path: str, raw: str) -> dict | None:
    if not raw:
        return None
    th = _token_hash(raw)
    ts = now()
    with _db(path) as conn:
        row = conn.execute(
            "SELECT s.token_hash, s.admin_id, s.csrf, s.created_at, s.last_seen, "
            "s.expires_at, a.username, a.is_active "
            "FROM sessions s JOIN admins a ON a.id = s.admin_id "
            "WHERE s.token_hash = ?",
            (th,),
        ).fetchone()
        if row is None:
            return None
        if int(row["is_active"]) != 1 or int(row["expires_at"]) <= ts \
                or ts - int(row["last_seen"]) > SESSION_IDLE:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (th,))
            return None
        conn.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?", (ts, th))
        return {
            "token_hash": th,
            "admin_id": int(row["admin_id"]),
            "username": row["username"],
            "csrf": row["csrf"],
            "created_at": int(row["created_at"]),
            "expires_at": int(row["expires_at"]),
        }


def delete_session(path: str, raw: str) -> None:
    if not raw:
        return
    with _db(path) as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(raw),))


def purge_expired(path: str) -> None:
    ts = now()
    with _db(path) as conn:
        conn.execute(
            "DELETE FROM sessions WHERE expires_at <= ? OR last_seen <= ?",
            (ts, ts - SESSION_IDLE),
        )


def audit(path: str, username: str, ip: str, action: str, detail: str = "") -> None:
    """审计失败不应影响业务；只记录动作，不记录密码/令牌。"""
    try:
        with _db(path) as conn:
            conn.execute(
                "INSERT INTO audit(ts, username, ip, action, detail) VALUES(?,?,?,?,?)",
                (now(), (username or "")[:64], (ip or "")[:64],
                 (action or "")[:32], (detail or "")[:255]),
            )
    except Exception:
        pass


class RateLimiter:
    """简单内存限速器；服务重启后计数清零。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}

    def _prune(self, key: str, window: int, ts: float) -> list[float]:
        arr = [t for t in self._hits.get(key, []) if t > ts - window]
        if arr:
            self._hits[key] = arr
        else:
            self._hits.pop(key, None)
        return arr

    def retry_after(self, key: str, limit: int, window: int) -> int:
        ts = time.time()
        with self._lock:
            arr = self._prune(key, window, ts)
            if len(arr) >= limit:
                return max(1, int(window - (ts - arr[0])))
            return 0

    def hit(self, key: str, window: int) -> None:
        ts = time.time()
        with self._lock:
            # 粗暴防止无限增长：条目太多时清掉过期键
            if len(self._hits) > 5000:
                self._hits = {
                    k: [t for t in v if t > ts - window]
                    for k, v in self._hits.items()
                    if any(t > ts - window for t in v)
                }
            self._hits.setdefault(key, []).append(ts)

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)
