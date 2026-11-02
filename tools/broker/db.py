#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================================
# tools/broker/db.py —— 受管服务数据库访问层
#
# 迁移约束（docs/受管服务与试用授权方案.md 8.2）：broker / webadmin 的所有 SQL
# 只允许出现在本文件。将来迁 MySQL/PostgreSQL 只改这里，调用方零感知。
# vpn-server (C++) 侧的 SQL 在它自己的 ServiceDB 模块里，同样隔离。
# ============================================================================

import os
import sqlite3
import time

DEFAULT_DB_PATH = os.environ.get("SERVICE_DB", "service.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS trials (
  fp          TEXT PRIMARY KEY,
  client_id   TEXT UNIQUE,
  token_hash  TEXT,
  os TEXT DEFAULT '', cpu TEXT DEFAULT '',
  ram_mb INTEGER DEFAULT 0, mac_hash TEXT DEFAULT '',
  first_ip TEXT DEFAULT '', last_ip TEXT DEFAULT '',
  created_at INTEGER DEFAULT 0,
  expire_at INTEGER DEFAULT 0,
  quota_bytes INTEGER DEFAULT 0,
  used_bytes INTEGER DEFAULT 0,
  status TEXT DEFAULT 'trial'
);
CREATE TABLE IF NOT EXISTS register_ip_log (
  ip TEXT, ts INTEGER
);
CREATE INDEX IF NOT EXISTS idx_iplog ON register_ip_log(ip, ts);
CREATE TABLE IF NOT EXISTS audit_domains (
  day TEXT, client_id TEXT, domain TEXT, hits INTEGER DEFAULT 0,
  PRIMARY KEY (day, client_id, domain)
);
CREATE TABLE IF NOT EXISTS blacklist (
  domain TEXT PRIMARY KEY, added_at INTEGER DEFAULT 0, note TEXT DEFAULT '',
  type TEXT DEFAULT 'domain'
);
-- 可下发的 VPN 服务器清单（2026-11-01）：运营在后台勾选哪些下发给客户端，
-- broker 每次请求按 enabled=1 的记录实时生成并签名 server-list.ini。
-- addr 是 "ip:port"，pubkey 是该服务器 Ed25519 公钥的 SPKI DER base64
-- （必须来自该服务器 keys/server_sig.pub，不是 service 签名钥）。
CREATE TABLE IF NOT EXISTS vpn_servers (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  addr        TEXT NOT NULL UNIQUE,
  pubkey      TEXT NOT NULL,
  remark      TEXT NOT NULL DEFAULT '',
  enabled     INTEGER NOT NULL DEFAULT 1,
  sort_order  INTEGER NOT NULL DEFAULT 0,
  created_at  INTEGER NOT NULL DEFAULT 0,
  updated_at  INTEGER NOT NULL DEFAULT 0
);
-- 受管服务全局开关（2026-11-02）：issue_mode = auto（新设备申请即自动通过试用）
-- 或 manual（新设备申请进入 pending，等后台人工通过）
CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT ''
);
"""
# 旧库迁移：blacklist 增加类型列（domain=域名黑名单 / ip=目的 IP / machine=整机）
def _migrate(conn: sqlite3.Connection) -> None:
    cols = [r[1] for r in conn.execute("PRAGMA table_info(blacklist)")]
    if cols and "type" not in cols:
        conn.execute("ALTER TABLE blacklist ADD COLUMN type TEXT NOT NULL DEFAULT 'domain'")
        conn.commit()
    # 2026-11-02：设备品牌/型号（仅后台展示核对用，不参与指纹、不含个人隐私）
    #           note = 管理员私有备注（不下发客户端）
    tcols = [r[1] for r in conn.execute("PRAGMA table_info(trials)")]
    if tcols and "brand" not in tcols:
        conn.execute("ALTER TABLE trials ADD COLUMN brand TEXT NOT NULL DEFAULT ''")
    if tcols and "model" not in tcols:
        conn.execute("ALTER TABLE trials ADD COLUMN model TEXT NOT NULL DEFAULT ''")
    if tcols and "note" not in tcols:
        conn.execute("ALTER TABLE trials ADD COLUMN note TEXT NOT NULL DEFAULT ''")
    conn.commit()


def connect(path: str = None) -> sqlite3.Connection:
    """每线程/每请求新建连接（sqlite3 对象默认不跨线程复用）。"""
    conn = sqlite3.connect(path or DEFAULT_DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    _migrate(conn)
    conn.commit()


# ---------------------------------------------------------------- 限频 ----

def register_allowed(conn: sqlite3.Connection, ip: str,
                     limit: int = 3, window_sec: int = 86400,
                     now: int = None) -> bool:
    now = now or int(time.time())
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM register_ip_log WHERE ip=? AND ts>?",
        (ip, now - window_sec)).fetchone()
    return row["n"] < limit


def log_register_ip(conn: sqlite3.Connection, ip: str, now: int = None) -> None:
    now = now or int(time.time())
    conn.execute("INSERT INTO register_ip_log(ip, ts) VALUES(?,?)", (ip, now))
    conn.commit()


# ---------------------------------------------------------------- trials ----

def get_trial(conn: sqlite3.Connection, fp: str):
    return conn.execute("SELECT * FROM trials WHERE fp=?", (fp,)).fetchone()


def get_trial_by_client(conn: sqlite3.Connection, client_id: str):
    return conn.execute("SELECT * FROM trials WHERE client_id=?",
                        (client_id,)).fetchone()


def create_trial(conn: sqlite3.Connection, *, fp: str, client_id: str,
                 token_hash: str, os_name: str, cpu: str, ram_mb: int,
                 mac_hash: str, ip: str, created_at: int, expire_at: int,
                 quota_bytes: int, brand: str = "", model: str = "",
                 status: str = "trial") -> None:
    conn.execute(
        "INSERT INTO trials(fp, client_id, token_hash, os, cpu, ram_mb,"
        " mac_hash, first_ip, last_ip, created_at, expire_at, quota_bytes,"
        " used_bytes, status, brand, model)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,0,?,?,?)",
        (fp, client_id, token_hash, os_name, cpu, ram_mb, mac_hash, ip, ip,
         created_at, expire_at, quota_bytes, status, brand, model))
    conn.commit()


# ------------------------------------------------------------ 全局设置 ----
# 受管服务开关（issue_mode = auto | manual）等，webadmin 写 / broker 读。

def get_setting(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO settings(key, value) VALUES(?,?)"
        " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value))
    conn.commit()


def touch_last_ip(conn: sqlite3.Connection, fp: str, ip: str) -> None:
    conn.execute("UPDATE trials SET last_ip=? WHERE fp=?", (ip, fp))
    conn.commit()


def update_device_info(conn: sqlite3.Connection, fp: str, brand: str,
                       model: str) -> None:
    """客户端上报品牌/型号（status 同步顺带刷新）——存量设备重连即补齐。"""
    if not brand and not model:
        return
    conn.execute("UPDATE trials SET brand=?, model=? WHERE fp=?",
                 (brand[:64], model[:64], fp))
    conn.commit()


def set_note(conn: sqlite3.Connection, fp: str, note: str) -> None:
    """管理员私有备注：仅后台可见，不下发客户端。"""
    conn.execute("UPDATE trials SET note=? WHERE fp=?", (note[:256], fp))
    conn.commit()


def reissue_token(conn: sqlite3.Connection, fp: str, token_hash: str) -> None:
    """重复申请：同一 fp 换发新令牌（client_id 不变）。"""
    conn.execute("UPDATE trials SET token_hash=? WHERE fp=?", (token_hash, fp))
    conn.commit()


def set_status(conn: sqlite3.Connection, fp: str, status: str) -> None:
    """approved = 解除配额与到期；rejected = 服务端拒绝连接。"""
    if status == "approved":
        conn.execute("UPDATE trials SET status=?, expire_at=0, quota_bytes=0"
                     " WHERE fp=?", (status, fp))
    else:
        conn.execute("UPDATE trials SET status=? WHERE fp=?", (status, fp))
    conn.commit()


def restore_trial(conn: sqlite3.Connection, fp: str, expire_at: int,
                  quota_bytes: int) -> None:
    """垃圾桶恢复：回到试用态，给一轮新的 3 天 / 2GB（与 broker 默认一致；
    若 broker 用环境变量改过默认值，这里需要同步）。"""
    conn.execute("UPDATE trials SET status='trial', expire_at=?, quota_bytes=?"
                 " WHERE fp=?", (expire_at, quota_bytes, fp))
    conn.commit()


def purge_trial(conn: sqlite3.Connection, fp: str) -> bool:
    """垃圾桶彻底删除：抹掉整行记录（该设备可重新申请试用）。"""
    cur = conn.execute("DELETE FROM trials WHERE fp=?", (fp,))
    conn.commit()
    return cur.rowcount > 0


def list_trials(conn: sqlite3.Connection):
    return conn.execute("SELECT * FROM trials ORDER BY created_at DESC").fetchall()


# ---------------------------------------------------------------- 审计 ----

def upsert_audit(conn: sqlite3.Connection, day: str, client_id: str,
                 domain: str, hits: int = 1) -> None:
    conn.execute(
        "INSERT INTO audit_domains(day, client_id, domain, hits) VALUES(?,?,?,?)"
        " ON CONFLICT(day, client_id, domain) DO UPDATE SET hits=hits+?",
        (day, client_id, domain, hits, hits))
    conn.commit()


def list_audit(conn: sqlite3.Connection, day: str = None,
               client_id: str = None):
    sql = "SELECT * FROM audit_domains WHERE 1=1"
    args = []
    if day:
        sql += " AND day=?"
        args.append(day)
    if client_id:
        sql += " AND client_id=?"
        args.append(client_id)
    sql += " ORDER BY hits DESC LIMIT 500"
    return conn.execute(sql, args).fetchall()


# ---------------------------------------------------------------- 黑名单 ----

def upsert_blacklist(conn: sqlite3.Connection, value: str,
                     note: str = "", btype: str = "domain") -> None:
    """btype: domain=域名（支持 *. 通配）/ ip=目的 IP（精确）/ machine=整机（client_id）。"""
    conn.execute(
        "INSERT INTO blacklist(domain, added_at, note, type) VALUES(?,?,?,?)"
        " ON CONFLICT(domain) DO UPDATE SET note=?, type=?",
        (value, int(time.time()), note, btype, note, btype))
    conn.commit()


def remove_blacklist(conn: sqlite3.Connection, domain: str) -> bool:
    cur = conn.execute("DELETE FROM blacklist WHERE domain=?", (domain,))
    conn.commit()
    return cur.rowcount > 0


def list_blacklist(conn: sqlite3.Connection):
    return conn.execute("SELECT * FROM blacklist ORDER BY domain").fetchall()


# ------------------------------------------------------------ VPN 服务器清单 ----
# 后台勾选、broker 实时生成签名列表下发给客户端（2026-11-01）

def list_vpn_servers(conn: sqlite3.Connection):
    """全部条目（含未启用），按 sort_order、id 排序，供后台展示。"""
    return conn.execute(
        "SELECT * FROM vpn_servers ORDER BY sort_order, id").fetchall()


def list_enabled_vpn_servers(conn: sqlite3.Connection):
    """只取已启用的，供 broker 生成下发列表。"""
    return conn.execute(
        "SELECT * FROM vpn_servers WHERE enabled=1 ORDER BY sort_order, id").fetchall()


def count_vpn_servers(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT COUNT(*) FROM vpn_servers").fetchone()[0])


def upsert_vpn_server(conn: sqlite3.Connection, *, addr: str, pubkey: str,
                      remark: str = "", enabled: int = 1,
                      sort_order: int = 0) -> None:
    """按 addr 新增或更新（addr 唯一）。"""
    now = int(time.time())
    conn.execute(
        "INSERT INTO vpn_servers(addr, pubkey, remark, enabled, sort_order,"
        " created_at, updated_at) VALUES(?,?,?,?,?,?,?)"
        " ON CONFLICT(addr) DO UPDATE SET pubkey=excluded.pubkey,"
        " remark=excluded.remark, enabled=excluded.enabled,"
        " sort_order=excluded.sort_order, updated_at=excluded.updated_at",
        (addr, pubkey, remark, 1 if enabled else 0, sort_order, now, now))
    conn.commit()


def set_vpn_server_enabled(conn: sqlite3.Connection, addr: str, enabled: bool) -> bool:
    cur = conn.execute(
        "UPDATE vpn_servers SET enabled=?, updated_at=? WHERE addr=?",
        (1 if enabled else 0, int(time.time()), addr))
    conn.commit()
    return cur.rowcount > 0


def delete_vpn_server(conn: sqlite3.Connection, addr: str) -> bool:
    cur = conn.execute("DELETE FROM vpn_servers WHERE addr=?", (addr,))
    conn.commit()
    return cur.rowcount > 0


def seed_vpn_servers_from_ini(conn: sqlite3.Connection, path: str) -> int:
    """把旧的静态 server-list.ini 导入数据库（首次迁移用，已存在则跳过）。"""
    import re as _re
    if not os.path.isfile(path):
        return 0
    items = {}
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            m = _re.match(r"^(server|pubkey|remark)(\d+)\s*=\s*(.+)$", line)
            if not m:
                continue
            kind, idx, val = m.group(1), m.group(2), m.group(3).strip()
            items.setdefault(idx, {})[kind] = val
    added = 0
    for idx in sorted(items, key=lambda x: int(x)):
        it = items[idx]
        addr, pub = it.get("server", ""), it.get("pubkey", "")
        if not addr or not pub:
            continue
        exists = conn.execute(
            "SELECT 1 FROM vpn_servers WHERE addr=?", (addr,)).fetchone()
        if exists:
            continue
        upsert_vpn_server(conn, addr=addr, pubkey=pub,
                          remark=it.get("remark", ""), enabled=1,
                          sort_order=int(idx))
        added += 1
    return added
