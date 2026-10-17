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
#   ./admin-vpn.sh build              编译 admin_server + admin_agent（增量，先查依赖）
#   ./admin-vpn.sh rebuild            清空 build/ 后重新编译（换了编译器/依赖时用）
#   ./admin-vpn.sh start              后台启动 admin_server + admin_agent
#   ./admin-vpn.sh fg                 前台启动并一直等着（Ctrl+C 一起干净退出）
#   ./admin-vpn.sh stop               停止（含兜底清扫孤儿进程）
#   ./admin-vpn.sh kill               强制清理：不看 PID 文件，直接按名字杀
#   ./admin-vpn.sh restart            重启
#   ./admin-vpn.sh status             查看状态
#   ./admin-vpn.sh logs [组件]        跟踪日志（组件=admin_server|admin_agent，默认两者）
#   ./admin-vpn.sh doctor             环境自检（不启动任何东西）
#   ./admin-vpn.sh fingerprint        打印本机身份指纹（拿去中转端 add-agent）
#   ./admin-vpn.sh token              打印管理令牌（admin_cli / curl 用）
#
# 注：start / fg 在发现可执行文件缺失时会自动编译，所以 build 不是必须的；
#     但想单独编译、或想看完整编译输出时用它。
#
# 环境变量（都有默认值，可前缀覆盖）：
#   BUILD_TYPE=Release         编译类型（Release / Debug / RelWithDebInfo / 留空=无优化）
#   ADMIN_BIND=127.0.0.1       admin_server 监听地址（强烈建议保持环回）
#   ADMIN_PORT=18080           admin_server 监听端口
#   ADMIN_NAME=vpn-1           上报给中转的展示名（中转那边拿它当 server id）
#   RELAY_HOST=127.0.0.1       中转服务器地址（生产环境填域名，如 admin.example.com）
#   RELAY_PORT=19090           中转的 agent 通道端口
#   RELAY_TLS=0                1=启用 TLS（用系统 CA 校验中转证书）
#   RELAY_TLS_CA=（空）        自定义信任根 PEM（自签/私有 CA；设置后隐含启用 TLS）
#   RELAY_TLS_NAME=（空）      证书校验名；留空=RELAY_HOST（用 IP 连接时也建议显式设置域名）
#   KEYS_DIR=<脚本目录>/keys   密钥与令牌目录
#   LOGS_DIR / RUN_DIR         日志 / PID 目录
#   ADMIN_TOKEN=（空）         管理令牌；留空则用 KEYS_DIR/admin_token.txt（没有就自动生成）
#
# 首次运行会自动完成：依赖检查 → 构建 → 建目录 → 生成 Ed25519 身份密钥
# ============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

# 可选：读取 admin-domain.env（由 setup-admin-domain.sh 生成）。
# 只填充“当前环境里还没设置”的变量，命令行前缀仍然优先。
load_domain_env() {
    local file="$SCRIPT_DIR/admin-domain.env" line key val
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

BUILD_DIR="$SCRIPT_DIR/build"
KEYS_DIR="${KEYS_DIR:-$SCRIPT_DIR/keys}"
LOGS_DIR="${LOGS_DIR:-$SCRIPT_DIR/logs}"
RUN_DIR="${RUN_DIR:-$SCRIPT_DIR/run}"

ADMIN_BIND="${ADMIN_BIND:-127.0.0.1}"
ADMIN_PORT="${ADMIN_PORT:-18080}"
ADMIN_NAME="${ADMIN_NAME:-vpn-1}"
RELAY_HOST="${RELAY_HOST:-127.0.0.1}"
RELAY_PORT="${RELAY_PORT:-19090}"
RELAY_TLS="${RELAY_TLS:-0}"
RELAY_TLS_CA="${RELAY_TLS_CA:-}"
RELAY_TLS_NAME="${RELAY_TLS_NAME:-}"
AGENT_TLS_ARGS=()

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
build_targets() {   # 配置 + 编译两个组件（build / rebuild / start 自动构建共用）
    info "构建 admin_server / admin_agent（BUILD_TYPE=${BUILD_TYPE-Release}）..."
    cmake -S "$SCRIPT_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE="${BUILD_TYPE-Release}" \
        || die "cmake 配置失败（先跑 ./admin-vpn.sh doctor 看依赖）"
    cmake --build "$BUILD_DIR" --target admin_server admin_agent \
        -j"$(nproc 2>/dev/null || echo 2)" || die "编译失败"
    [ -x "$ADMIN_BIN" ] || die "构建后仍找不到 $ADMIN_BIN"
    [ -x "$AGENT_BIN" ] || die "构建后仍找不到 $AGENT_BIN"
}

build_if_needed() {
    if [ -x "$ADMIN_BIN" ] && [ -x "$AGENT_BIN" ]; then
        ok "可执行文件已存在，跳过构建（强制重建：./admin-vpn.sh rebuild）"
        return 0
    fi
    build_targets
    ok "构建完成"
}

do_build() {
    check_deps || die "依赖检查未通过（执行 ./admin-vpn.sh doctor 看详情）"
    build_targets
    ok "构建完成"
}

do_rebuild() {
    info "清空 $BUILD_DIR 后重新编译 ..."
    rm -rf "$BUILD_DIR" || die "删除 $BUILD_DIR 失败"
    do_build
}

# ---------------------------------------------------------------- 首次运行准备
prepare_dirs() {
    mkdir -p "$KEYS_DIR" "$LOGS_DIR" "$RUN_DIR" || die "创建目录失败（$KEYS_DIR / $LOGS_DIR / $RUN_DIR）"
    local d
    for d in "$KEYS_DIR" "$LOGS_DIR" "$RUN_DIR"; do
        if [ ! -w "$d" ]; then
            err "目录不可写: $d   属主=$(stat -c '%U:%G' "$d" 2>/dev/null)"
            die "多半是之前用 sudo 跑过留下的。修复： sudo chown -R \$USER:\$USER '$SCRIPT_DIR'"
        fi
    done
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

# agent → controller 的管理通道 TLS。RELAY_TLS_CA 非空时只信任该 CA；
# RELAY_TLS=1 时用系统 CA（Let's Encrypt 等公共 CA）。
prepare_agent_tls() {
    AGENT_TLS_ARGS=()
    if [ -n "$RELAY_TLS_CA" ]; then
        [ -r "$RELAY_TLS_CA" ] || die "RELAY_TLS_CA 不可读: $RELAY_TLS_CA"
        AGENT_TLS_ARGS=(--tls-ca "$RELAY_TLS_CA"
                        --tls-server-name "${RELAY_TLS_NAME:-$RELAY_HOST}")
        ok "agent 管理通道 TLS 已启用（自定义 CA）"
    elif [ "$RELAY_TLS" = "1" ]; then
        AGENT_TLS_ARGS=(--tls --tls-server-name "${RELAY_TLS_NAME:-$RELAY_HOST}")
        ok "agent 管理通道 TLS 已启用（系统 CA）"
    else
        warn "agent 管理通道未启用 TLS（明文 TCP）。生产环境请设置 RELAY_TLS=1 或 RELAY_TLS_CA"
    fi
}

# ---------------------------------------------------------------- 进程
# 判存在用 /proc 而不是 kill -0：PID 文件里若是别的属主（曾用 sudo 起过）的进程，
# kill -0 会因 EPERM 失败被误判成"未运行"。只要进程存在，/proc/<pid> 一定在。
proc_alive() { [ -n "${1:-}" ] && [ -d "/proc/$1" ]; }

is_running() {
    local pidfile="$1" p
    [ -f "$pidfile" ] || return 1
    p="$(cat "$pidfile" 2>/dev/null)"
    proc_alive "$p"
}

wait_log() {   # wait_log <日志文件> <关键字> <最多等几次×0.2s>
    local f="$1" pat="$2" n="${3:-50}" i=0
    while [ "$i" -lt "$n" ]; do
        grep -q "$pat" "$f" 2>/dev/null && return 0
        sleep 0.2; i=$((i + 1))
    done
    return 1
}

# 等「成功标志」；若先出现「失败标志」则立刻返回非 0，不干等到超时。
# 注意失败关键字要选得足够精确：admin_server 的 "setsockopt ... failed" 是非致命的，
# 用它当失败标志会误杀；所以这里只认 "bind failed"。
wait_log_ok() {   # wait_log_ok <日志> <成功关键字> <失败关键字> <最多等几次×0.2s>
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

start_one() {  # start_one <名字> <pid文件> <日志文件> <命令...>
    local name="$1" pid="$2" log="$3"; shift 3
    if is_running "$pid"; then warn "$name 已在运行 (pid $(cat "$pid"))"; return 0; fi
    if ! : > "$log" 2>/dev/null; then
        err "$name 无法写入日志文件: $log"
        return 1
    fi
    "$@" >>"$log" 2>&1 &
    local child=$!
    # PID 文件写不进去必须当失败处理：否则进程活着但 stop/status 永远管不到它
    if ! echo "$child" > "$pid" 2>/dev/null; then
        err "$name 已启动 (pid $child) 但 PID 文件写入失败: $pid"
        err "→ stop/status 会失效，正在回滚（杀掉该进程）"
        kill "$child" 2>/dev/null
        return 1
    fi
    return 0
}

stop_one() {   # stop_one <名字> <pid文件>
    local name="$1" pid="$2" p i=0
    if ! [ -f "$pid" ]; then warn "$name 未运行"; return 0; fi
    p="$(cat "$pid" 2>/dev/null)"
    if ! proc_alive "$p"; then
        warn "$name 未运行（残留 pid $p，已清理）"; rm -f "$pid"; return 0
    fi
    if ! kill "$p" 2>/dev/null; then
        warn "$name 发送 TERM 失败（pid $p，多半是权限不足）"
    fi
    while proc_alive "$p" && [ "$i" -lt 25 ]; do sleep 0.2; i=$((i + 1)); done
    if proc_alive "$p"; then
        warn "$name 未响应 TERM，改用 KILL"
        kill -9 "$p" 2>/dev/null
        i=0                              # KILL 后最多再等 1.5s 确认它真的消失
        while proc_alive "$p" && [ "$i" -lt 15 ]; do sleep 0.1; i=$((i + 1)); done
    fi
    # 最终校验：没死就报失败并保留 pid 文件，绝不删了 pid 谎报"已停止"
    if proc_alive "$p"; then
        err "$name 仍在运行 (pid $p) —— 确认进程属主，必要时 sudo"
        return 1
    fi
    rm -f "$pid"
    ok "$name 已停止"
}

# 找出匹配某模式的进程 PID（排除自身）。
# 优先 pgrep；精简系统没有 pgrep 时退化为 ps+awk。
# 退化路径的关键：先把 ps 快照取完再 awk —— 否则 awk 自己的命令行里就含这个模式，
# 会把自己也算成"残留进程"然后自杀。模式按 ERE 处理（pgrep/awk ~ 都是 ERE 语义）。
find_pids() {   # find_pids <ERE 模式>
    local pat="$1" snap
    if have pgrep; then
        pgrep -f "$pat" 2>/dev/null
    else
        snap="$(ps -eo pid=,args= 2>/dev/null || true)"
        printf '%s\n' "$snap" | awk -v p="$pat" '$0 ~ p { print $1 }'
    fi | awk -v me="$$" 'NF && $1 != me { print $1 }'
}

# 兜底清扫：PID 文件可能丢失（旧脚本起的 / 手动起的），只按 pid 文件停会留下孤儿进程
# —— 也就是"退都没退干净"。
sweep_orphans() {   # sweep_orphans <可执行文件绝对路径>
    local bin="$1" pat pids
    # 同时匹配绝对路径启动和 ./basename / basename 启动（旧脚本、手动起的常见）；
    # 边界 (^|/)...( |$) 保证不误伤 admin_server.log、admin_server_old 之类。
    pat="(^|/)${bin##*/}( |\$)"
    pids="$(find_pids "$pat")"
    [ -n "$pids" ] || return 0
    warn "发现残留进程，一并清理：$bin"
    printf '%s\n' "$pids" | sed 's/^/    pid /' >&2
    # shellcheck disable=SC2086
    kill $pids 2>/dev/null || true
    sleep 0.5
    pids="$(find_pids "$pat")"
    if [ -n "$pids" ]; then
        warn "仍未退出，改用 KILL"
        # shellcheck disable=SC2086
        kill -9 $pids 2>/dev/null || true
        sleep 0.3
        pids="$(find_pids "$pat")"
    fi
    if [ -n "$pids" ]; then                # 复核后仍在 = 清理失败（多半权限不足）
        warn "仍有残留未清理（权限不足？）：$(printf '%s' "$pids" | tr '\n' ' ')"
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------- 子命令
do_start() {
    check_deps || die "依赖检查未通过（执行 ./admin-vpn.sh doctor 看详情）"
    build_if_needed
    prepare_dirs
    ensure_keys
    prepare_agent_tls

    local fp tok
    fp="$(fingerprint)" || die "无法获取身份指纹"

    # 先看自己的 pid 文件：已经在跑就幂等跳过（否则端口预检会把自己占的端口报成冲突）
    if is_running "$AS_PID"; then
        warn "admin_server 已在运行 (pid $(cat "$AS_PID"))，跳过启动"
        info "改了 ADMIN_BIND/ADMIN_PORT 等环境变量需 restart 才生效： ./admin-vpn.sh restart"
    else
        # 端口预检：给出可操作的错误，而不是让 admin_server 自己报 bind 失败
        if port_in_use "$ADMIN_PORT"; then
            err "端口 $ADMIN_PORT 已被占用（多半是上次没退干净的 admin_server）"
            pgrep -af 'admin_server' >&2 || true
            die "先执行 ./admin-vpn.sh stop，或 pkill -f build/admin_server"
        fi

        # admin_server：显式摘掉 ADMIN_TOKEN，保证它一定去读/写 TOKEN_FILE
        info "启动 admin_server  ($ADMIN_BIND:$ADMIN_PORT)"
        start_one admin_server "$AS_PID" "$AS_LOG" \
            env -u ADMIN_TOKEN ADMIN_BIND="$ADMIN_BIND" ADMIN_PORT="$ADMIN_PORT" KEYS_DIR="$KEYS_DIR" "$ADMIN_BIN" \
            || die "启动 admin_server 失败（见上）"
        if ! wait_log_ok "$AS_LOG" "Server start" "bind failed" 60; then
            err "admin_server 启动失败，日志："
            tail -n 20 "$AS_LOG" >&2
            do_stop >/dev/null 2>&1
            die "启动失败"
        fi
        ok "admin_server 就绪"
    fi

    tok="$(read_token)" || die "读不到管理令牌 $TOKEN_FILE"
    [ -n "$tok" ] || die "管理令牌为空"

    info "启动 admin_agent   -> $RELAY_HOST:$RELAY_PORT  (name=$ADMIN_NAME)"
    start_one admin_agent "$AG_PID" "$AG_LOG" \
        "$AGENT_BIN" --controller "$RELAY_HOST:$RELAY_PORT" \
                     --admin "$ADMIN_BIND:$ADMIN_PORT" \
                     --key "$SIG_KEY" --token "$tok" --name "$ADMIN_NAME" \
                     "${AGENT_TLS_ARGS[@]}" \
        || die "启动 admin_agent 失败（见上）"
    if wait_log "$AG_LOG" "已接入 controller" 100; then
        ok "admin_agent 已接入中转"
    else
        warn "agent 尚未接入中转（它会自动退避重连，不算致命）"
        if grep -q "准入被拒" "$AG_LOG" 2>/dev/null; then
            err "中转明确拒绝了它 —— 指纹不在白名单里"
            warn "到中转端执行： ./admin-relay.sh add-agent $fp"
        elif grep -q "连接 controller.*失败" "$AG_LOG" 2>/dev/null; then
            err "连不上中转 $RELAY_HOST:$RELAY_PORT —— 中转端起了吗？防火墙放行了吗？"
        fi
        warn "日志末尾："
        tail -n 10 "$AG_LOG" >&2
    fi

    printf '\n'
    ok "本机身份指纹: $fp"
    info "去中转端登记： ./admin-relay.sh add-agent $fp"
    info "管理令牌文件: $TOKEN_FILE"
}

FG_TAIL_PID=""
fg_cleanup() {
    printf '\n'
    info "收到中断，正在停止 ..."
    do_stop
    if [ -n "$FG_TAIL_PID" ]; then kill "$FG_TAIL_PID" 2>/dev/null || true; fi
    ok "已全部退出"
    exit 0
}

do_fg() {
    check_deps || die "依赖检查未通过"
    build_if_needed
    prepare_dirs
    ensure_keys
    prepare_agent_tls

    local fp tok
    fp="$(fingerprint)" || die "无法获取身份指纹"
    trap fg_cleanup INT TERM

    start_one admin_server "$AS_PID" "$AS_LOG" \
        env -u ADMIN_TOKEN ADMIN_BIND="$ADMIN_BIND" ADMIN_PORT="$ADMIN_PORT" KEYS_DIR="$KEYS_DIR" "$ADMIN_BIN" \
        || die "启动 admin_server 失败（见上）"
    if ! wait_log_ok "$AS_LOG" "Server start" "bind failed" 60; then
        tail -n 20 "$AS_LOG" >&2
        do_stop >/dev/null 2>&1
        die "admin_server 启动失败"
    fi
    ok "admin_server 就绪"

    tok="$(read_token)" || die "读不到管理令牌 $TOKEN_FILE"
    start_one admin_agent "$AG_PID" "$AG_LOG" \
        "$AGENT_BIN" --controller "$RELAY_HOST:$RELAY_PORT" \
                     --admin "$ADMIN_BIND:$ADMIN_PORT" \
                     --key "$SIG_KEY" --token "$tok" --name "$ADMIN_NAME" \
                     "${AGENT_TLS_ARGS[@]}" \
        || die "启动 admin_agent 失败（见上）"

    printf '\n'
    ok "本机身份指纹: $fp"
    info "前台运行中 —— Ctrl+C 会把两个进程一起停掉"
    printf '\n'
    tail -n 0 -f "$AS_LOG" "$AG_LOG" &
    FG_TAIL_PID=$!

    # 轮询等"任一服务退出"（Ctrl+C 走 trap）。
    # 不用 wait：它会连 tail 一起等，且任一子进程退出就返回，语义不清晰。
    while is_running "$AS_PID" && is_running "$AG_PID"; do
        sleep 1
    done
    warn "有服务已退出，开始收尾"
    do_stop
    if [ -n "$FG_TAIL_PID" ]; then kill "$FG_TAIL_PID" 2>/dev/null || true; fi
    ok "已全部退出"
}

do_stop() {
    local rc=0
    stop_one admin_agent "$AG_PID"  || rc=1
    stop_one admin_server "$AS_PID" || rc=1
    # 兜底：PID 文件缺失时（旧脚本 / 手动起的）只按 pid 文件会漏，扫一遍按名字杀
    sweep_orphans "$AGENT_BIN"      || rc=1
    sweep_orphans "$ADMIN_BIN"      || rc=1
    return "$rc"
}

do_kill() {   # 强制清理：不看 PID 文件，直接按可执行路径杀
    local rc=0
    info "强制清理所有 admin_server / admin_agent 进程"
    sweep_orphans "$AGENT_BIN" || rc=1
    sweep_orphans "$ADMIN_BIN" || rc=1
    rm -f "$AS_PID" "$AG_PID"
    if [ "$rc" -eq 0 ]; then
        ok "清理完成"
    else
        err "清理未完全成功（见上），如需强制请确认权限后用 sudo"
    fi
    return "$rc"
}

do_status() {
    local rc=0
    for pair in "admin_server:$AS_PID:$ADMIN_PORT" "admin_agent:$AG_PID:-"; do
        # 拆两条 local：同一条里 ${rest} 会在 rest 赋值前被展开，set -u 下直接报错
        local name="${pair%%:*}" rest="${pair#*:}"
        local pid="${rest%%:*}" port="${rest##*:}"
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
    printf '管理通道 TLS      : %s\n' \
           "$([ -n "$RELAY_TLS_CA" ] || [ "$RELAY_TLS" = "1" ] && echo '启用' || echo '未启用（明文 TCP）')"
    [ -n "$RELAY_TLS_CA" ] && printf 'TLS 信任根        : %s\n' "$RELAY_TLS_CA"
    printf 'TLS 校验名        : %s\n' "${RELAY_TLS_NAME:-$RELAY_HOST}"

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
    build)       do_build ;;
    rebuild)     do_rebuild ;;
    start)       do_start ;;
    fg)          do_fg ;;
    stop)        do_stop ;;
    kill)        do_kill ;;
    restart)     do_stop; do_start ;;
    status)      do_status ;;
    logs)        do_logs "${1:-all}" ;;
    doctor)      do_doctor ;;
    fingerprint) fingerprint || exit 1; printf '\n' ;;
    token)       t="$(read_token)" || die "读不到令牌（$TOKEN_FILE）"; printf '%s\n' "$t" ;;
    help|-h|--help) usage ;;
    *) err "未知子命令: $cmd"; printf '\n'; usage; exit 1 ;;
esac
