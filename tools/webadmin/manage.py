#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================================
# manage.py —— 管理员账号恢复/运维 CLI（在本机 root 下运行）
# ----------------------------------------------------------------------------
# 用法：
#   python3 manage.py list
#   python3 manage.py create-admin <用户名>
#   python3 manage.py reset-password <用户名>
#
# 密码通过终端交互输入，不放在命令行参数里（避免进入 shell history）。
# 数据库路径：WEBADMIN_DB 环境变量，默认 tools/webadmin/data/webadmin.db
# ============================================================================
from __future__ import annotations

import getpass
import os
import sys

import auth

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get("WEBADMIN_DB", os.path.join(HERE, "data", "webadmin.db"))


def ask_password(username: str) -> str:
    p1 = getpass.getpass("新密码: ")
    p2 = getpass.getpass("再次输入: ")
    if p1 != p2:
        print("两次输入不一致", file=sys.stderr)
        sys.exit(1)
    err = auth.validate_password(username, p1)
    if err:
        print(err, file=sys.stderr)
        sys.exit(1)
    return p1


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    cmd = sys.argv[1]
    auth.init_db(DB)

    if cmd == "list":
        for a in auth.list_admins(DB):
            print(f'{a["id"]:4d}  {a["username"]}  active={a["is_active"]}')
        return 0

    if cmd in ("create-admin", "reset-password"):
        if len(sys.argv) < 3:
            print(f"用法: {cmd} <用户名>", file=sys.stderr)
            return 1
        username = sys.argv[2]
        if not auth.validate_username(username):
            print("用户名需为 3–32 位字母、数字、点、下划线或短横线", file=sys.stderr)
            return 1
        password = ask_password(username)
        if cmd == "create-admin":
            try:
                auth.create_admin(DB, username, password)
            except Exception as e:
                print(f"创建失败: {e}", file=sys.stderr)
                return 1
            print(f"已创建管理员: {username}")
        else:
            if not auth.set_password(DB, username, password):
                print("用户不存在", file=sys.stderr)
                return 1
            print(f"已重置密码并注销该用户全部会话: {username}")
        return 0

    print(f"未知命令: {cmd}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
