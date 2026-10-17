#!/usr/bin/env bash
# ============================================================================
# start-admin-web.sh —— 读取 admin-domain.env 后启动中转管理网页
# ----------------------------------------------------------------------------
# 用法：
#   ./start-admin-web.sh                 # 前台运行（Ctrl+C 退出）
#   nohup ./start-admin-web.sh >> logs/webadmin.log 2>&1 &   # 后台运行
#
# 中转令牌只在服务端使用（访问 127.0.0.1:18081），不会下发给浏览器；
# 浏览器登录由管理员账号 + 服务端会话来控制。
# 首次管理员注册时，初始化令牌默认就是该中转令牌。
# 证书/端口/上游地址来自 admin-domain.env（命令行环境变量优先）。
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEB_DIR="$SCRIPT_DIR/../tools/webadmin"
ENV_FILE="$SCRIPT_DIR/admin-domain.env"

load_domain_env() {
    local file="$ENV_FILE" line key val
    [ -f "$file" ] || return 0
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in ''|'#'*) continue ;; esac
        key="${line%%=*}"
        val="${line#*=}"
        [ "$key" = "$line" ] && continue
        if [ -z "${!key+x}" ]; then
            export "$key=$val"
        fi
    done < "$file"
}
load_domain_env

if [ -z "${ADMIN_TOKEN:-}" ]; then
    ADMIN_TOKEN="$(cd "$SCRIPT_DIR" && ./admin-relay.sh token)"
    export ADMIN_TOKEN
fi

mkdir -p "$SCRIPT_DIR/run"
printf '%s\n' "$$" > "$SCRIPT_DIR/run/webadmin.pid"

cd "$WEB_DIR"
exec python3 app.py "$@"
