#!/usr/bin/env bash
# ============================================================================
# admin-vpn.sh —— VPN 服务器侧：后台管理组件一键启停
# ----------------------------------------------------------------------------
# 本脚本负责「VPN 服务器」这一端的两个组件：
#   1) admin_server —— 本机管理 API（默认 127.0.0.1:18080）：发令牌 / 查公钥
#   2) admin_agent  —— 出站反连「中转服务器」的 vpn_controller，转发管理命令
#
# 注意：它跟 vpn_server（隧道数据面）完全独立，两者互不依赖。
#       纯测后台管理链路时不需要跑 vpn_server，也就不需要 root。
#
# 用法：
#   ./admin-vpn.sh start              后台启动 admin_server + admin_agent
#   ./admin-vpn.sh fg                 前台启动（Ctrl+C 一起退出，便于调试）
#   ./admin-vpn.sh stop               停止
#   ./admin-vpn.sh restart            重启
#   ./admin-vpn.sh status             查看状态
#   ./admin-vpn.sh logs [组件]        跟踪日志（组件=admin_server|admin_agent，默认两者）
#   ./admin-vpn.sh doctor             环境自检（不启动任何东西）
#   ./admin-vpn.sh fingerprint        打印本机身份指纹（拿去中转端 add-agent）
#   ./admin-vpn.sh token              打印管理令牌（admin_cli / curl 用）
#
# 环境变量（都有默认值，可前缀覆盖）：
#   ADMIN_BIND=127.0.0.1       admin_server 监听地址（强烈建议保持环回）
#   ADMIN_PORT=18080           admin_server 监听端口
#   ADMIN_NAME=vpn-1           上报给中转的展示名（中转那边拿它当 server id）
#   RELAY_HOST=127.0.0.1       中转服务器地址
#   RELAY_PORT=19090           中转的 agent 通道端口
#   KEYS_DIR=<脚本目录>/keys   密钥与令牌目录
#   LOGS_DIR / RUN_DIR         日志 / PID 目录
#   ADMIN_TOKEN=（空）         管理令牌；留空则用 KEYS_DIR/admin_token.txt（没有就自动生成）
#
# 首次运行会自动完成：依赖检查 → 构建 → 建目录 → 生成 Ed25519 身份密钥
# ============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

BUILD_DIR="$SCRIPT_DIR/build"
KEYS_DIR="${KEYS_DIR:-$SCRIPT_DIR/keys}"
LOGS_DIR="${LOGS_DIR:-$SCRIPT_DIR/logs}"
RUN_DIR="${RUN_DIR:-$SCRIPT_DIR/run}"

ADMIN_BIND="${ADMIN_BIND:-127.0.0.1}"
ADMIN_PORT="${ADMIN_PORT:-18080}"
ADMIN_NAME="${ADMIN_NAME:-vpn-1}"
RELAY_HOST="${RELAY_HOST:-127.0.0.1}"
RELAY_PORT="${RELAY_PORT:-19090}"

ADMIN_BIN="$BUILD_DIR/admin_server"
AGENT_BIN="$BUILD_DIR/admin_agent"
SIG_KEY="$KEYS_DIR/server_sig.key"
SIG_PUB="$KEYS_DIR/server_sig.pub"
TOKEN_FILE="$KEYS_DIR/admin_token.txt"

AS_LOG="$LOGS_DIR/admin_server.log"
AG_LOG="$LOGS_DIR/admin_agent.log"
AS_PID="$RUN_DIR/admin_server.pid"
AG_PID="$RUN_DIR/admin_agent.pid"

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
            *) err "OpenSSL ${v:-未知} 过旧，本工程需要 3.0+（用到 EVP_PKEY_is_a / OSSL_PARAM）"; bad=1 ;;
        esac
    fi
    return "$bad"
}

# ---------------------------------------------------------------- 构建
build_if_needed() {
    if [ -x "$ADMIN_BIN" ] && [ -x "$AGENT_BIN" ]; then
        ok "可执行文件已存在，跳过构建（强制重建：rm -rf build）"
        return 0
    fi
    info "构建 admin_server / admin_agent ..."
    cmake -S "$SCRIPT_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release \
        || die "cmake 配置失败（先跑 ./admin-vpn.sh doctor 看依赖）"
    cmake --build "$BUILD_DIR" --target admin_server admin_agent \
        -j"$(nproc 2>/dev/null || echo 2)" || die "编译失败"
    [ -x "$ADMIN_BIN" ] || die "构建后仍找不到 $ADMIN_BIN"
    [ -x "$AGENT_BIN" ] || die "构建后仍找不到 $AGENT_BIN"
    ok "构建完成"
}

# ---------------------------------------------------------------- 首次运行准备
prepare_dirs() {
    mkdir -p "$KEYS_DIR" "$LOGS_DIR" "$RUN_DIR" || die "创建目录失败（$KEYS_DIR / $LOGS_DIR / $RUN_DIR）"
}

ensure_keys() {
    if [ -f "$SIG_KEY" ] && [ -f "$SIG_PUB" ]; then
        ok "身份密钥已存在: $SIG_KEY"
        return 0
    fi
    info "首次运行：生成 Ed25519 身份密钥 ..."
    openssl genpkey -algorithm ED25519 -out "$SIG_KEY" || die "生成私钥失败"
    openssl pkey -in "$SIG_KEY" -pubout -out "$SIG_PUB" || die "导出公钥失败"
    chmod 600 "$SIG_KEY" 2>/dev/null
    chmod 644 "$SIG_PUB" 2>/dev/null
    ok "已生成 $SIG_KEY / $SIG_PUB"
    warn "这是 agent 的身份来源（= vpn_server 的身份）。若客户端里硬编码了服务器公钥，"
    warn "换用新密钥后需同步更新客户端 kServerSigPubPem，否则客户端握手验签会失败。"
}

fingerprint() {   # 成功打印指纹；失败打印原因并返回非 0（可安全用于 $(...)）
    if [ ! -f "$SIG_PUB" ]; then
        err "找不到 $SIG_PUB（先执行一次 start 或 doctor 生成密钥）"
        return 1
    fi
    openssl pkey -pubin -in "$SIG_PUB" -outform DER 2>/dev/null \
        | tail -c 32 | od -An -tx1 -v | tr -d ' \n'
}

read_token() {
    if [ -n "${ADMIN_TOKEN:-}" ]; then printf '%s' "$ADMIN_TOKEN"; return 0; fi
    [ -f "$TOKEN_FILE" ] || return 1
    head -n1 "$TOKEN_FILE" 2>/dev/null | tr -d '\r\n'
}

# ---------------------------------------------------------------- 进程
is_running() {
    local pidfile="$1" p
    [ -f "$pidfile" ] || return 1
    p="$(cat "$pidfile" 2>/dev/null)"
    [ -n "$p" ] && kill -0 "$p" 2>/dev/null
}

wait_log() {   # wait_log <日志文件> <关键字> <最多等几次×0.2s>
    local f="$1" pat="$2" n="${3:-50}" i=0
    while [ "$i" -lt "$n" ]; do
        grep -q "$pat" "$f" 2>/dev/null && return 0
        sleep 0.2; i=$((i + 1))
    done
    return 1
}

start_one() {  # start_one <名字> <pid文件> <日志文件> <命令...>
    local name="$1" pid="$2" log="$3"; shift 3
    if is_running "$pid"; then warn "$name 已在运行 (pid $(cat "$pid"))"; return 0; fi
    : > "$log"
    "$@" >>"$log" 2>&1 &
    echo $! > "$pid"
    return 0
}

stop_one() {   # stop_one <名字> <pid文件>
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
        kill -9 "$p" 2>/dev/null
        sleep 0.3
    fi
    rm -f "$pid"
    ok "$name 已停止"
}

# ---------------------------------------------------------------- 子命令
do_start() {
    check_deps || die "依赖检查未通过（执行 ./admin-vpn.sh doctor 看详情）"
    build_if_needed
    prepare_dirs
    ensure_keys

    local fp tok
    fp="$(fingerprint)" || die "无法获取身份指纹"

    # admin_server：显式摘掉 ADMIN_TOKEN，保证它一定去读/写 TOKEN_FILE
    info "启动 admin_server  ($ADMIN_BIND:$ADMIN_PORT)"
    start_one admin_server "$AS_PID" "$AS_LOG" \
        env -u ADMIN_TOKEN ADMIN_BIND="$ADMIN_BIND" ADMIN_PORT="$ADMIN_PORT" KEYS_DIR="$KEYS_DIR" "$ADMIN_BIN"
    if ! wait_log "$AS_LOG" "Server start" 60; then
        err "admin_server 未在 12s 内就绪，日志末尾："
        tail -n 20 "$AS_LOG" >&2
        do_stop >/dev/null 2>&1
        die "启动失败"
    fi
    ok "admin_server 就绪"

    tok="$(read_token)" || die "读不到管理令牌 $TOKEN_FILE"
    [ -n "$tok" ] || die "管理令牌为空"

    info "启动 admin_agent   -> $RELAY_HOST:$RELAY_PORT  (name=$ADMIN_NAME)"
    start_one admin_agent "$AG_PID" "$AG_LOG" \
        "$AGENT_BIN" --controller "$RELAY_HOST:$RELAY_PORT" \
                     --admin "$ADMIN_BIND:$ADMIN_PORT" \
                     --key "$SIG_KEY" --token "$tok" --name "$ADMIN_NAME"
    if wait_log "$AG_LOG" "已接入 controller" 100; then
        ok "admin_agent 已接入中转"
    else
        warn "agent 尚未接入中转（它会自动退避重连，不算致命）"
        warn "常见原因：中转端没启动 / 指纹没在中转端登记。日志末尾："
        tail -n 20 "$AG_LOG" >&2
    fi

    printf '\n'
    ok "本机身份指纹: $fp"
    info "去中转端登记： ./admin-relay.sh add-agent $fp"
    info "管理令牌文件: $TOKEN_FILE"
}

do_fg() {
    check_deps || die "依赖检查未通过"
    build_if_needed
    prepare_dirs
    ensure_keys

    local fp tok
    fp="$(fingerprint)" || die "无法获取身份指纹"
    trap 'printf "\n"; info "收到中断，正在停止 ..."; do_stop; exit 0' INT TERM

    start_one admin_server "$AS_PID" "$AS_LOG" \
        env -u ADMIN_TOKEN ADMIN_BIND="$ADMIN_BIND" ADMIN_PORT="$ADMIN_PORT" KEYS_DIR="$KEYS_DIR" "$ADMIN_BIN"
    if ! wait_log "$AS_LOG" "Server start" 60; then
        tail -n 20 "$AS_LOG" >&2
        do_stop >/dev/null 2>&1
        die "admin_server 启动失败"
    fi

    tok="$(read_token)" || die "读不到管理令牌 $TOKEN_FILE"
    start_one admin_agent "$AG_PID" "$AG_LOG" \
        "$AGENT_BIN" --controller "$RELAY_HOST:$RELAY_PORT" \
                     --admin "$ADMIN_BIND:$ADMIN_PORT" \
                     --key "$SIG_KEY" --token "$tok" --name "$ADMIN_NAME"

    printf '\n'
    ok "本机身份指纹: $fp"
    info "前台运行中，Ctrl+C 一起退出（日志见 $LOGS_DIR/）"
    printf '\n'
    tail -n 0 -f "$AS_LOG" "$AG_LOG" &
    wait
}

do_stop() {
    stop_one admin_agent "$AG_PID"
    stop_one admin_server "$AS_PID"
}

do_status() {
    local rc=0
    for pair in "admin_server:$AS_PID:$ADMIN_PORT" "admin_agent:$AG_PID:-"; do
        local name="${pair%%:*}" rest="${pair#*:}" pid="${rest%%:*}" port="${rest##*:}"
        if is_running "$pid"; then
            ok "$name 运行中 (pid $(cat "$pid"))"
        else
            warn "$name 未运行"; rc=1
        fi
        if [ "$port" != "-" ] && have ss; then
            if ss -ltn 2>/dev/null | grep -q ":$port "; then ok "端口 $port 监听中"; else warn "端口 $port 未监听"; fi
        fi
    done
    [ -f "$TOKEN_FILE" ] && info "令牌文件: $TOKEN_FILE" || warn "令牌文件不存在: $TOKEN_FILE"
    return "$rc"
}

do_logs() {
    local which="${1:-all}"
    local files=()
    case "$which" in
        admin_server) files=("$AS_LOG") ;;
        admin_agent)  files=("$AG_LOG") ;;
        all)          files=("$AS_LOG" "$AG_LOG") ;;
        *) die "未知组件: $which（可选 admin_server|admin_agent|all）" ;;
    esac
    local f
    for f in "${files[@]}"; do
        [ -f "$f" ] || { warn "日志不存在: $f"; continue; }
    done
    info "tail -f ${files[*]}   (Ctrl+C 退出)"
    tail -n 40 -f "${files[@]}"
}

do_doctor() {
    printf '%s=== 环境 ===%s\n' "$C_B" "$C_0"
    printf '脚本目录 : %s\n' "$SCRIPT_DIR"
    printf '系统     : %s %s\n' "$(uname -s 2>/dev/null)" "$(uname -m 2>/dev/null)"
    printf '内核     : %s\n' "$(uname -r 2>/dev/null)"

    printf '\n%s=== 依赖 ===%s\n' "$C_B" "$C_0"
    check_deps || warn "依赖有问题（见上）"

    printf '\n%s=== 路径 ===%s\n' "$C_B" "$C_0"
    local p
    for p in "$BUILD_DIR" "$KEYS_DIR" "$LOGS_DIR" "$RUN_DIR"; do
        [ -d "$p" ] && ok "目录 $p" || warn "目录不存在 $p"
    done
    for p in "$ADMIN_BIN" "$AGENT_BIN"; do
        [ -x "$p" ] && ok "可执行 $p" || warn "可执行缺失 $p（start 时会自动构建）"
    done
    for p in "$SIG_KEY" "$SIG_PUB" "$TOKEN_FILE"; do
        [ -f "$p" ] && ok "文件 $p" || warn "文件缺失 $p（start 时会自动生成）"
    done

    printf '\n%s=== 配置 ===%s\n' "$C_B" "$C_0"
    printf 'admin_server 监听 : %s:%s\n' "$ADMIN_BIND" "$ADMIN_PORT"
    printf '上报中转          : %s:%s  (name=%s)\n' "$RELAY_HOST" "$RELAY_PORT" "$ADMIN_NAME"

    if [ -f "$SIG_PUB" ]; then
        printf '本机身份指纹      : %s\n' "$(fingerprint)"
    fi

    if have ss; then
        printf '\n%s=== 端口占用 ===%s\n' "$C_B" "$C_0"
        local prt
        for prt in "$ADMIN_PORT" "$RELAY_PORT"; do
            if ss -ltn 2>/dev/null | grep -q ":$prt "; then warn "端口 $prt 已被占用"; else ok "端口 $prt 空闲"; fi
        done
    fi

    printf '\n%s=== 残留进程 ===%s\n' "$C_B" "$C_0"
    if pgrep -af 'build/(admin_server|admin_agent)' 2>/dev/null; then :; else ok "无残留"; fi
}

usage() {
    # 只打印文件开头的注释块（跳过 shebang）
    awk 'NR>1 && /^#/ { sub(/^# ?/, ""); print; next } NR>1 { exit }' "${BASH_SOURCE[0]}"
}

# ---------------------------------------------------------------- 分发
cmd="${1:-help}"; shift 2>/dev/null || true
case "$cmd" in
    start)       do_start ;;
    fg)          do_fg ;;
    stop)        do_stop ;;
    restart)     do_stop; do_start ;;
    status)      do_status ;;
    logs)        do_logs "${1:-all}" ;;
    doctor)      do_doctor ;;
    fingerprint) fingerprint || exit 1; printf '\n' ;;
    token)       t="$(read_token)" || die "读不到令牌（$TOKEN_FILE）"; printf '%s\n' "$t" ;;
    help|-h|--help) usage ;;
    *) err "未知子命令: $cmd"; printf '\n'; usage; exit 1 ;;
esac
