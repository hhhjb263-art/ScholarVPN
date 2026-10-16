#!/usr/bin/env bash
# ============================================================================
# admin-relay.sh —— 中转服务器侧：vpn_controller 一键启停 + agent 白名单管理
# ----------------------------------------------------------------------------
# 本脚本负责「中转服务器」这一端：
#   vpn_controller —— 接受各 VPN 服务器的 admin_agent 出站反连（默认 19090），
#                     并提供一个 HTTP 入口（默认 127.0.0.1:18081）用于下发管理命令。
#
# 使用顺序（很重要）：
#   1) 在 VPN 端跑 ./admin-vpn.sh fingerprint 拿到指纹
#   2) 在本机跑 ./admin-relay.sh add-agent <指纹>       ← 会顺带重启 controller
#   3) 在 VPN 端跑 ./admin-vpn.sh start                 ← agent 才能被准入
#
# 用法：
#   ./admin-relay.sh start                     后台启动 vpn_controller
#   ./admin-relay.sh fg                        前台启动（Ctrl+C 退出）
#   ./admin-relay.sh stop                      停止
#   ./admin-relay.sh restart                   重启
#   ./admin-relay.sh status                    查看状态 + 已接入 agent
#   ./admin-relay.sh logs                      跟踪日志
#   ./admin-relay.sh doctor                    环境自检
#   ./admin-relay.sh add-agent <64位hex>       登记一个 agent 指纹（自动重启）
#   ./admin-relay.sh del-agent <64位hex>       移除一个 agent 指纹（自动重启）
#   ./admin-relay.sh list-agents               列出白名单
#   ./admin-relay.sh token                     打印 HTTP 入口令牌
#
# 环境变量（都有默认值，可前缀覆盖）：
#   AGENT_BIND=0.0.0.0         agent 通道监听地址（公网中转必须是 0.0.0.0）
#   AGENT_PORT=19090           agent 通道端口
#   HTTP_BIND=127.0.0.1        HTTP 入口地址（默认仅环回，建议保持）
#   HTTP_PORT=18081            HTTP 入口端口
#   ADMIN_TOKEN=（自动生成）   HTTP 入口 Bearer；留空则用/生成 $SCRIPT_DIR/admin_token.txt
#   AGENTS_FILE=$SCRIPT_DIR/agents.txt   agent 公钥指纹白名单
#   LOGS_DIR / RUN_DIR         日志 / PID 目录
#
# 首次运行会自动完成：依赖检查 → 构建 → 建目录 → 生成 HTTP 入口令牌
# ============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

BUILD_DIR="$SCRIPT_DIR/build"
LOGS_DIR="${LOGS_DIR:-$SCRIPT_DIR/logs}"
RUN_DIR="${RUN_DIR:-$SCRIPT_DIR/run}"
CTL_BIN="$BUILD_DIR/vpn_controller"
AGENTS_FILE="${AGENTS_FILE:-$SCRIPT_DIR/agents.txt}"
TOKEN_FILE="$SCRIPT_DIR/relay_admin_token.txt"

AGENT_BIND="${AGENT_BIND:-0.0.0.0}"
AGENT_PORT="${AGENT_PORT:-19090}"
HTTP_BIND="${HTTP_BIND:-127.0.0.1}"
HTTP_PORT="${HTTP_PORT:-18081}"

CTL_LOG="$LOGS_DIR/vpn_controller.log"
CTL_PID="$RUN_DIR/vpn_controller.pid"

# ---------------------------------------------------------------- 输出
if [ -t 2 ]; then
    C_R=$'\033[31m'; C_G=$'\033[32m'; C_Y=$'\033[33m'; C_B=$'\033[1m'; C_0=$'\033[0m'
else
    C_R=''; C_G=''; C_Y=''; C_B=''; C_0=''
fi
info() { printf '%s[*]%s %s\n' "$C_B" "$C_0" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$C_G" "$C_0" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_Y" "$C_0" "$*" >&2; }
err()  { printf '%s[x]%s %s\n' "$C_R" "$C_0" "$*" >&2; }
die()  { err "$*"; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------- 依赖
check_deps() {
    local bad=0
    for c in cmake g++ openssl; do
        if have "$c"; then ok "$c  $(command -v "$c")"; else err "缺少命令: $c"; bad=1; fi
    done
    if have ninja; then ok "ninja  $(command -v ninja)"
    elif have make; then ok "make  $(command -v make)"
    else err "缺少 make 或 ninja"; bad=1; fi

    if [ -f /usr/include/openssl/evp.h ] || { have pkg-config && pkg-config --exists openssl 2>/dev/null; }; then
        ok "OpenSSL 开发头文件"
    else
        err "缺少 OpenSSL 开发包 → sudo apt install -y libssl-dev"
        bad=1
    fi

    if have openssl; then
        local v
        v="$(openssl version 2>/dev/null | awk '{print $2}')"
        case "$v" in
            3.*|4.*) ok "OpenSSL $v" ;;
            *) err "OpenSSL ${v:-未知} 过旧，本工程需要 3.0+"; bad=1 ;;
        esac
    fi

    have curl && ok "curl  $(command -v curl)" || warn "没有 curl，status/doctor 的健康检查会跳过"
    return "$bad"
}

# ---------------------------------------------------------------- 构建
build_if_needed() {
    if [ -x "$CTL_BIN" ]; then
        ok "可执行文件已存在，跳过构建（强制重建：rm -rf build）"
        return 0
    fi
    info "构建 vpn_controller ..."
    cmake -S "$SCRIPT_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release \
        || die "cmake 配置失败（先跑 ./admin-relay.sh doctor 看依赖）"
    cmake --build "$BUILD_DIR" --target vpn_controller \
        -j"$(nproc 2>/dev/null || echo 2)" || die "编译失败"
    [ -x "$CTL_BIN" ] || die "构建后仍找不到 $CTL_BIN"
    ok "构建完成"
}

# ---------------------------------------------------------------- 首次运行准备
prepare_dirs() {
    mkdir -p "$LOGS_DIR" "$RUN_DIR" || die "创建目录失败（$LOGS_DIR / $RUN_DIR）"
    [ -f "$AGENTS_FILE" ] || : > "$AGENTS_FILE"
}

ensure_relay_token() {
    if [ -n "${ADMIN_TOKEN:-}" ]; then RELAY_TOKEN="$ADMIN_TOKEN"; return 0; fi
    if [ -f "$TOKEN_FILE" ]; then
        RELAY_TOKEN="$(head -n1 "$TOKEN_FILE" 2>/dev/null | tr -d '\r\n')"
        [ -n "$RELAY_TOKEN" ] && return 0
    fi
    info "首次运行：生成 HTTP 入口令牌 ..."
    RELAY_TOKEN="$(openssl rand -hex 32)" || die "生成令牌失败"
    printf '%s\n' "$RELAY_TOKEN" > "$TOKEN_FILE" || die "写令牌失败: $TOKEN_FILE"
    chmod 600 "$TOKEN_FILE" 2>/dev/null
    ok "已生成 $TOKEN_FILE"
}

FP_NORM=""
normalize_fp() {   # 校验并归一化指纹，结果写入全局 FP_NORM
    # 绝不能写成 fp="$(normalize_fp ...)"：那样 die 只会杀掉命令替换的子 shell，
    # 主脚本会带着空指纹继续往下跑（本脚本第一版就踩了这个坑）。
    local fp
    fp="$(printf '%s' "${1:-}" | tr 'A-F' 'a-f' | tr -d ' \t\r\n')"
    [ -n "$fp" ] || die "指纹为空"
    case "$fp" in *[!0-9a-f]*) die "指纹只能是十六进制字符（0-9a-f）" ;; esac
    [ "${#fp}" -eq 64 ] || die "指纹长度应为 64（当前 ${#fp}）"
    FP_NORM="$fp"
}

count_agents() {   # 白名单条数（非空行）。
    # 不用 grep -c：空文件时它退出码非 0，`$(grep -c ... || echo 0)` 会拼出 "0\n0"
    local n=0
    if [ -f "$AGENTS_FILE" ]; then
        n="$(awk 'NF' "$AGENTS_FILE" 2>/dev/null | wc -l)"
        n="${n//[!0-9]/}"
    fi
    printf '%s' "${n:-0}"
}

# ---------------------------------------------------------------- 进程
is_running() {
    local pidfile="$1" p
    [ -f "$pidfile" ] || return 1
    p="$(cat "$pidfile" 2>/dev/null)"
    [ -n "$p" ] && kill -0 "$p" 2>/dev/null
}

wait_log() {
    local f="$1" pat="$2" n="${3:-50}" i=0
    while [ "$i" -lt "$n" ]; do
        grep -q "$pat" "$f" 2>/dev/null && return 0
        sleep 0.2; i=$((i + 1))
    done
    return 1
}

# 等日志里出现「成功标志」；若先出现「失败标志」则立刻返回非 0，不用干等到超时。
# 签名与 admin-vpn.sh 保持一致：<日志> <成功关键字> <失败关键字> <最多等几次×0.2s>
wait_log_ok() {
    local f="$1" ok="$2" bad="${3:-失败}" n="${4:-60}" i=0
    while [ "$i" -lt "$n" ]; do
        grep -q "$ok"  "$f" 2>/dev/null && return 0
        grep -q "$bad" "$f" 2>/dev/null && return 1
        sleep 0.2; i=$((i + 1))
    done
    return 1
}

port_in_use() {   # 只依赖 ss；没有 ss 就返回"未占用"（不阻塞启动）
    have ss || return 1
    ss -ltn 2>/dev/null | grep -q ":$1 "
}

start_one() {
    local name="$1" pid="$2" log="$3"; shift 3
    if is_running "$pid"; then warn "$name 已在运行 (pid $(cat "$pid"))"; return 0; fi
    : > "$log"
    "$@" >>"$log" 2>&1 &
    echo $! > "$pid"
    return 0
}

stop_one() {
    local name="$1" pid="$2" p i=0
    if ! [ -f "$pid" ]; then warn "$name 未运行"; return 0; fi
    p="$(cat "$pid" 2>/dev/null)"
    if [ -z "$p" ] || ! kill -0 "$p" 2>/dev/null; then
        warn "$name 未运行（残留 pid $p，已清理）"; rm -f "$pid"; return 0
    fi
    kill "$p" 2>/dev/null
    while kill -0 "$p" 2>/dev/null && [ "$i" -lt 25 ]; do sleep 0.2; i=$((i + 1)); done
    if kill -0 "$p" 2>/dev/null; then
        warn "$name 未响应 TERM，改用 KILL"
        kill -9 "$p" 2>/dev/null; sleep 0.3
    fi
    rm -f "$pid"
    ok "$name 已停止"
}

# ---------------------------------------------------------------- 子命令
do_start() {
    check_deps || die "依赖检查未通过（执行 ./admin-relay.sh doctor 看详情）"
    build_if_needed
    prepare_dirs
    ensure_relay_token

    local n
    n="$(count_agents)"
    if [ "$n" -eq 0 ]; then
        warn "白名单为空，任何 agent 都会被拒。先跑： ./admin-relay.sh add-agent 后跟 64 位指纹"
    fi

    # 端口预检：给出可操作的错误，而不是让 controller 自己报 bind 失败
    local prt
    for prt in "$AGENT_PORT" "$HTTP_PORT"; do
        if port_in_use "$prt"; then
            err "端口 $prt 已被占用（多半是上次没退干净的 vpn_controller）"
            pgrep -af 'vpn_controller' >&2 || true
            die "先执行 ./admin-relay.sh stop，或 pkill -f build/vpn_controller"
        fi
    done

    info "启动 vpn_controller  agent=$AGENT_BIND:$AGENT_PORT  http=$HTTP_BIND:$HTTP_PORT  白名单 $n 条"
    start_one vpn_controller "$CTL_PID" "$CTL_LOG" \
        "$CTL_BIN" --agent-bind "$AGENT_BIND" --agent-port "$AGENT_PORT" \
                   --http-bind "$HTTP_BIND"  --http-port "$HTTP_PORT" \
                   --admin-token "$RELAY_TOKEN" \
                   --agents "$AGENTS_FILE"
    # 成功标志用「白名单」——失败信息里不含这三个字，不会被误判
    if ! wait_log_ok "$CTL_LOG" "白名单" "失败" 60; then
        err "vpn_controller 启动失败，日志："
        tail -n 20 "$CTL_LOG" >&2
        do_stop >/dev/null 2>&1
        die "启动失败"
    fi
    ok "vpn_controller 就绪"
    grep -E 'agent 通道|agent 接入|拒绝' "$CTL_LOG" | sed 's/^/    /'
    printf '\n'
    info "HTTP 入口令牌: $RELAY_TOKEN"
    info "测试： curl -H 'Authorization: Bearer $RELAY_TOKEN' http://$HTTP_BIND:$HTTP_PORT/api/servers"
}

do_fg() {
    check_deps || die "依赖检查未通过"
    build_if_needed
    prepare_dirs
    ensure_relay_token
    trap 'printf "\n"; info "收到中断，正在停止 ..."; do_stop; exit 0' INT TERM

    start_one vpn_controller "$CTL_PID" "$CTL_LOG" \
        "$CTL_BIN" --agent-bind "$AGENT_BIND" --agent-port "$AGENT_PORT" \
                   --http-bind "$HTTP_BIND"  --http-port "$HTTP_PORT" \
                   --admin-token "$RELAY_TOKEN" \
                   --agents "$AGENTS_FILE"
    if ! wait_log_ok "$CTL_LOG" "白名单" "失败" 60; then
        tail -n 20 "$CTL_LOG" >&2; do_stop >/dev/null 2>&1; die "启动失败"
    fi
    info "前台运行中，Ctrl+C 退出（日志 $CTL_LOG）"
    printf '\n'
    tail -n 0 -f "$CTL_LOG" &
    wait
}

do_stop() { stop_one vpn_controller "$CTL_PID"; }

do_status() {
    local rc=0
    if is_running "$CTL_PID"; then
        ok "vpn_controller 运行中 (pid $(cat "$CTL_PID"))"
    else
        warn "vpn_controller 未运行"; rc=1
    fi
    if have ss; then
        local prt
        for prt in "$AGENT_PORT" "$HTTP_PORT"; do
            if ss -ltn 2>/dev/null | grep -q ":$prt "; then ok "端口 $prt 监听中"; else warn "端口 $prt 未监听"; fi
        done
    fi
    local n
    n="$(count_agents)"
    info "白名单 $AGENTS_FILE: $n 条"
    if have curl && is_running "$CTL_PID"; then
        printf '\n%s已接入的 agent：%s\n' "$C_B" "$C_0"
        curl -sf -H "Authorization: Bearer $RELAY_TOKEN" \
            "http://$HTTP_BIND:$HTTP_PORT/api/servers" || warn "查询 /api/servers 失败（controller 刚起？令牌不对？）"
        printf '\n'
    fi
    return "$rc"
}

do_logs() {
    [ -f "$CTL_LOG" ] || die "日志不存在: $CTL_LOG"
    info "tail -f $CTL_LOG   (Ctrl+C 退出)"
    tail -n 40 -f "$CTL_LOG"
}

do_doctor() {
    printf '%s=== 环境 ===%s\n' "$C_B" "$C_0"
    printf '脚本目录 : %s\n' "$SCRIPT_DIR"
    printf '系统     : %s %s\n' "$(uname -s 2>/dev/null)" "$(uname -m 2>/dev/null)"

    printf '\n%s=== 依赖 ===%s\n' "$C_B" "$C_0"
    check_deps || warn "依赖有问题（见上）"

    printf '\n%s=== 路径 ===%s\n' "$C_B" "$C_0"
    local p
    for p in "$BUILD_DIR" "$LOGS_DIR" "$RUN_DIR"; do
        [ -d "$p" ] && ok "目录 $p" || warn "目录不存在 $p"
    done
    [ -x "$CTL_BIN" ] && ok "可执行 $CTL_BIN" || warn "可执行缺失 $CTL_BIN（start 时会自动构建）"
    [ -f "$AGENTS_FILE" ] && ok "白名单 $AGENTS_FILE（$(count_agents) 条）" \
                          || warn "白名单不存在 $AGENTS_FILE（start 时会自动创建）"
    [ -f "$TOKEN_FILE" ] && ok "令牌文件 $TOKEN_FILE" || warn "令牌文件缺失 $TOKEN_FILE（start 时会自动生成）"

    printf '\n%s=== 配置 ===%s\n' "$C_B" "$C_0"
    printf 'agent 通道 : %s:%s\n' "$AGENT_BIND" "$AGENT_PORT"
    printf 'HTTP 入口  : %s:%s\n' "$HTTP_BIND" "$HTTP_PORT"

    if have ss; then
        printf '\n%s=== 端口占用 ===%s\n' "$C_B" "$C_0"
        local prt
        for prt in "$AGENT_PORT" "$HTTP_PORT"; do
            if ss -ltn 2>/dev/null | grep -q ":$prt "; then warn "端口 $prt 已被占用"; else ok "端口 $prt 空闲"; fi
        done
    fi

    printf '\n%s=== 防火墙提醒 ===%s\n' "$C_B" "$C_0"
    warn "中转要接受公网 agent 反连，需放行 TCP $AGENT_PORT（ufw allow $AGENT_PORT/tcp）"
    warn "HTTP 入口 $HTTP_PORT 建议只走 SSH 隧道，不要对公网开放"

    printf '\n%s=== 残留进程 ===%s\n' "$C_B" "$C_0"
    if pgrep -af 'build/vpn_controller' 2>/dev/null; then :; else ok "无残留"; fi
}

do_add_agent() {
    normalize_fp "${1:-}"
    local fp="$FP_NORM"
    prepare_dirs
    if grep -qx "$fp" "$AGENTS_FILE" 2>/dev/null; then
        warn "该指纹已在白名单，跳过写入"
    else
        printf '%s\n' "$fp" >> "$AGENTS_FILE" || die "写入 $AGENTS_FILE 失败"
        ok "已登记: $fp"
    fi
    if is_running "$CTL_PID"; then
        info "白名单只在启动时读取一次，正在重启 vpn_controller 使其生效 ..."
        do_stop
        do_start
    else
        info "controller 未运行；下次 start 时白名单自然生效"
    fi
}

do_del_agent() {
    normalize_fp "${1:-}"
    local fp="$FP_NORM"
    [ -f "$AGENTS_FILE" ] || die "白名单不存在: $AGENTS_FILE"
    grep -qx "$fp" "$AGENTS_FILE" || die "白名单里没有这个指纹"
    local tmp="$AGENTS_FILE.tmp.$$"
    grep -vx "$fp" "$AGENTS_FILE" > "$tmp" || true
    mv "$tmp" "$AGENTS_FILE" || die "更新白名单失败"
    ok "已移除: $fp"
    if is_running "$CTL_PID"; then
        info "重启 vpn_controller 使白名单生效 ..."
        do_stop; do_start
    fi
}

do_list_agents() {
    [ -f "$AGENTS_FILE" ] || { warn "白名单不存在: $AGENTS_FILE"; return 0; }
    local n
    n="$(count_agents)"
    if [ "$n" -eq 0 ]; then
        warn "白名单为空（$AGENTS_FILE）"
        return 0
    fi
    info "$AGENTS_FILE  ($n 条)"
    awk 'NF { printf "%4d  %s\n", ++i, $0 }' "$AGENTS_FILE"
}

usage() {
    # 只打印文件开头的注释块（跳过 shebang）
    awk 'NR>1 && /^#/ { sub(/^# ?/, ""); print; next } NR>1 { exit }' "${BASH_SOURCE[0]}"
}

# ---------------------------------------------------------------- 分发
RELAY_TOKEN=""
cmd="${1:-help}"; shift 2>/dev/null || true
case "$cmd" in
    start)        do_start ;;
    fg)           do_fg ;;
    stop)         do_stop ;;
    restart)      do_stop; do_start ;;
    status)       ensure_relay_token >/dev/null 2>&1 || true; do_status ;;
    logs)         do_logs ;;
    doctor)       do_doctor ;;
    add-agent)    do_add_agent "${1:-}" ;;
    del-agent)    do_del_agent "${1:-}" ;;
    list-agents)  do_list_agents ;;
    token)        ensure_relay_token >/dev/null 2>&1; printf '%s\n' "$RELAY_TOKEN" ;;
    help|-h|--help) usage ;;
    *) err "未知子命令: $cmd"; printf '\n'; usage; exit 1 ;;
esac
