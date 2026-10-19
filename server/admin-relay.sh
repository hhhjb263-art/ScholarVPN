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
#   ./admin-relay.sh fg                        前台启动并一直等着（Ctrl+C 干净退出）
#   ./admin-relay.sh stop                      停止（含兜底清扫孤儿进程）
#   ./admin-relay.sh kill                      强制清理：不看 PID 文件，直接按名字杀
#   ./admin-relay.sh restart                   重启
#   ./admin-relay.sh status                    查看状态 + 已接入 agent
#   ./admin-relay.sh logs                      跟踪日志
#   ./admin-relay.sh doctor                    环境自检
#   ./admin-relay.sh install                   装成 systemd 服务（开机自启 + 崩溃自动拉起，需 root）
#   ./admin-relay.sh uninstall                 卸载服务（停止 + 取消自启 + 删 unit，需 root）
#   ./admin-relay.sh enable | disable          仅控制开机自启（需 root）
#   ./admin-relay.sh unit                      打印 systemd unit 内容（不写盘，检查用）
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
#   TLS_CERT=（空）            agent 通道 TLS 证书链（fullchain.pem）；与 TLS_KEY 成对
#   TLS_KEY=（空）             agent 通道 TLS 私钥（privkey.pem，0600）
#   ADMIN_TOKEN=（自动生成）   HTTP 入口 Bearer；留空则用/生成 $SCRIPT_DIR/admin_token.txt
#   AGENTS_FILE=$SCRIPT_DIR/agents.txt   agent 公钥指纹白名单
#   LOGS_DIR / RUN_DIR         日志 / PID 目录
#   UNIT_NAME=scholarvpn-admin-relay  systemd 服务名（同机跑多套隔离实例时改它）
#
# 首次运行会自动完成：依赖检查 → 构建 → 建目录 → 生成 HTTP 入口令牌
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
LOGS_DIR="${LOGS_DIR:-$SCRIPT_DIR/logs}"
RUN_DIR="${RUN_DIR:-$SCRIPT_DIR/run}"
CTL_BIN="$BUILD_DIR/vpn_controller"
AGENTS_FILE="${AGENTS_FILE:-$SCRIPT_DIR/agents.txt}"
TOKEN_FILE="$SCRIPT_DIR/relay_admin_token.txt"

AGENT_BIND="${AGENT_BIND:-0.0.0.0}"
AGENT_PORT="${AGENT_PORT:-19090}"
HTTP_BIND="${HTTP_BIND:-127.0.0.1}"
HTTP_PORT="${HTTP_PORT:-18081}"
TLS_CERT="${TLS_CERT:-}"
TLS_KEY="${TLS_KEY:-}"
TLS_ARGS=()

CTL_LOG="$LOGS_DIR/vpn_controller.log"
CTL_PID="$RUN_DIR/vpn_controller.pid"

# ---------------------------------------------------------------- systemd
# 服务名（可用 UNIT_NAME 覆盖，便于同一台机器跑多套隔离实例）
UNIT_NAME="${UNIT_NAME:-scholarvpn-admin-relay}"
UNIT_FILE="/etc/systemd/system/${UNIT_NAME}.service"
UNIT_ENV_FILE="/etc/default/${UNIT_NAME}"

# 实例标识：注入到子进程环境里，供 sweep_orphans 区分"本实例"与"同机其他实例"。
# 默认取 RUN_DIR（不同实例的 PID 目录本就该不同）。
INSTANCE_TAG="${INSTANCE_TAG:-$RUN_DIR}"

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
    local d
    for d in "$LOGS_DIR" "$RUN_DIR"; do
        if [ ! -w "$d" ]; then
            err "目录不可写: $d   属主=$(stat -c '%U:%G' "$d" 2>/dev/null)"
            die "多半是之前用 sudo 跑过留下的。修复： sudo chown -R \$USER:\$USER '$SCRIPT_DIR'"
        fi
    done
    [ -f "$AGENTS_FILE" ] || : > "$AGENTS_FILE" \
        || die "无法创建白名单 $AGENTS_FILE（所在目录不可写？）"
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

# agent 通道 TLS：证书/私钥必须成对。生产环境用域名 + Let's Encrypt 证书，
# 这里只校验文件可读并拼参数；证书的签发/续期交给 certbot，不在脚本里重造。
prepare_tls() {
    TLS_ARGS=()
    if [ -z "$TLS_CERT" ] && [ -z "$TLS_KEY" ]; then
        warn "agent 通道未启用 TLS（明文 TCP）。生产环境请设置 TLS_CERT/TLS_KEY"
        return 0
    fi
    [ -n "$TLS_CERT" ] && [ -n "$TLS_KEY" ] || die "TLS_CERT 与 TLS_KEY 必须同时设置"
    [ -r "$TLS_CERT" ] || die "证书不可读: $TLS_CERT"
    [ -r "$TLS_KEY" ] || die "私钥不可读: $TLS_KEY"
    if have openssl; then
        openssl x509 -in "$TLS_CERT" -noout -checkend 0 >/dev/null 2>&1 \
            || die "证书已过期或无法解析: $TLS_CERT"
        openssl x509 -in "$TLS_CERT" -noout -checkend 2592000 >/dev/null 2>&1 \
            || warn "证书将在 30 天内过期: $TLS_CERT —— 记得续期"
        openssl x509 -in "$TLS_CERT" -noout -subject -enddate 2>/dev/null | sed 's/^/    /'
    fi
    TLS_ARGS=(--tls-cert "$TLS_CERT" --tls-key "$TLS_KEY")
    ok "agent 通道 TLS 已启用"
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
# 判存在用 /proc 而不是 kill -0：PID 文件里若是别的属主（曾用 sudo 起过）的进程，
# kill -0 会因 EPERM 失败被误判成"未运行"。只要进程存在，/proc/<pid> 一定在。
proc_alive() { [ -n "${1:-}" ] && [ -d "/proc/$1" ]; }

is_running() {
    local pidfile="$1" p
    [ -f "$pidfile" ] || return 1
    p="$(cat "$pidfile" 2>/dev/null)"
    proc_alive "$p"
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
    if ! : > "$log" 2>/dev/null; then
        err "$name 无法写入日志文件: $log"
        return 1
    fi
    # 注入实例标识：sweep_orphans 靠它区分本实例与同机其他实例的进程
    SCHOLARVPN_INSTANCE="$INSTANCE_TAG" "$@" >>"$log" 2>&1 &
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

stop_one() {
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
    local bin="$1" pat pids pid tag mine others left
    # 同时匹配绝对路径启动和 ./basename / basename 启动（旧脚本、手动起的常见）；
    # 边界 (^|/)...( |$) 保证不误伤 vpn_controller.log、vpn_controller_old 之类。
    pat="(^|/)${bin##*/}( |\$)"
    pids="$(find_pids "$pat")"
    [ -n "$pids" ] || return 0

    # 按实例标识分流：只杀本实例的，其余只报告不动手。
    #
    # 为什么必须这么做（2026-10-19 在真机上踩过）：
    # 同机跑两套部署时二进制路径相同，原来按 basename 无差别 kill，
    # 一套 stop 会把另一套的 vpn_controller 一起干掉。
    # 现在只清理 environ 里 SCHOLARVPN_INSTANCE == $INSTANCE_TAG 的进程；
    # 旧脚本/手动起的进程没有该变量，一律跳过（宁可漏杀，不可误杀）。
    mine=""; others=""
    for pid in $pids; do
        tag="$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null \
               | sed -n 's/^SCHOLARVPN_INSTANCE=//p' | head -1)"
        if [ "$tag" = "$INSTANCE_TAG" ]; then
            mine="$mine $pid"
        else
            others="$others $pid"
        fi
    done

    if [ -n "$others" ]; then
        warn "跳过非本实例（$INSTANCE_TAG）的进程：$others"
        warn "  它们属于同机其他部署或旧脚本启动；确需清理请自行确认后 kill"
    fi
    [ -n "$mine" ] || return 0

    warn "发现本实例的残留进程，一并清理：$bin"
    printf '%s\n' $mine | sed 's/^/    pid /' >&2
    # shellcheck disable=SC2086
    kill $mine 2>/dev/null || true
    sleep 0.5
    left=""
    for pid in $mine; do [ -d "/proc/$pid" ] && left="$left $pid"; done
    if [ -n "$left" ]; then
        warn "仍未退出，改用 KILL"
        # shellcheck disable=SC2086
        kill -9 $left 2>/dev/null || true
        sleep 0.3
        left=""
        for pid in $mine; do [ -d "/proc/$pid" ] && left="$left $pid"; done
    fi
    if [ -n "$left" ]; then                # 复核后仍在 = 清理失败（多半权限不足）
        warn "仍有残留未清理（权限不足？）：$left"
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------- 子命令
do_start() {
    check_deps || die "依赖检查未通过（执行 ./admin-relay.sh doctor 看详情）"
    build_if_needed
    prepare_dirs
    ensure_relay_token
    prepare_tls

    local n
    n="$(count_agents)"
    if [ "$n" -eq 0 ]; then
        warn "白名单为空，任何 agent 都会被拒。先跑： ./admin-relay.sh add-agent 后跟 64 位指纹"
    fi

    # 先看自己的 pid 文件：已经在跑就幂等跳过（否则端口预检会把自己占的端口报成冲突）
    if is_running "$CTL_PID"; then
        warn "vpn_controller 已在运行 (pid $(cat "$CTL_PID"))，跳过启动"
        info "改了端口/白名单等参数需 restart 才生效： ./admin-relay.sh restart"
    else
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
                       --agents "$AGENTS_FILE" \
                       "${TLS_ARGS[@]}" \
            || die "启动 vpn_controller 失败（见上）"
        # 成功标志用「白名单」——失败信息里不含这三个字，不会被误判
        if ! wait_log_ok "$CTL_LOG" "白名单" "失败" 60; then
            err "vpn_controller 启动失败，日志："
            tail -n 20 "$CTL_LOG" >&2
            do_stop >/dev/null 2>&1
            die "启动失败"
        fi
        ok "vpn_controller 就绪"
        grep -E 'agent 通道|agent 接入|拒绝' "$CTL_LOG" | sed 's/^/    /'
    fi
    printf '\n'
    info "HTTP 入口令牌: $RELAY_TOKEN"
    info "测试： curl -H 'Authorization: Bearer $RELAY_TOKEN' http://$HTTP_BIND:$HTTP_PORT/api/servers"
}

FG_TAIL_PID=""
fg_cleanup() {
    printf '\n'
    info "收到中断，正在停止 ..."
    do_stop
    if [ -n "$FG_TAIL_PID" ]; then kill "$FG_TAIL_PID" 2>/dev/null || true; fi
    ok "已退出"
    exit 0
}

do_fg() {
    # 二进制已就绪时跳过工具链检查：systemd 的 PATH 只有标准目录，
    # cmake/g++ 装在 /opt 或 snap 里就会让服务起不来（install 阶段已经查过一次）
    if [ ! -x "$CTL_BIN" ]; then
        check_deps || die "依赖检查未通过"
    fi
    build_if_needed
    prepare_dirs
    ensure_relay_token
    prepare_tls
    trap fg_cleanup INT TERM

    start_one vpn_controller "$CTL_PID" "$CTL_LOG" \
        "$CTL_BIN" --agent-bind "$AGENT_BIND" --agent-port "$AGENT_PORT" \
                   --http-bind "$HTTP_BIND"  --http-port "$HTTP_PORT" \
                   --admin-token "$RELAY_TOKEN" \
                   --agents "$AGENTS_FILE" \
                   "${TLS_ARGS[@]}" \
        || die "启动 vpn_controller 失败（见上）"
    if ! wait_log_ok "$CTL_LOG" "白名单" "失败" 60; then
        tail -n 20 "$CTL_LOG" >&2; do_stop >/dev/null 2>&1; die "启动失败"
    fi
    info "前台运行中 —— Ctrl+C 会干净退出"
    printf '\n'
    tail -n 0 -f "$CTL_LOG" &
    FG_TAIL_PID=$!

    while is_running "$CTL_PID"; do
        sleep 1
    done
    warn "vpn_controller 已退出，开始收尾"
    do_stop
    if [ -n "$FG_TAIL_PID" ]; then kill "$FG_TAIL_PID" 2>/dev/null || true; fi
    ok "已退出"
    # 关键：systemd 下必须以非 0 退出，否则 Restart=on-failure 不会拉起服务，
    # controller 崩一次就永久躺平，"常驻"名存实亡。
    # INVOCATION_ID 只有 systemd 启动的进程才有，手动跑 fg 时保持退出码 0。
    if [ -n "${INVOCATION_ID:-}" ]; then
        exit 1
    fi
}

do_stop() {
    local rc=0
    stop_one vpn_controller "$CTL_PID" || rc=1
    sweep_orphans "$CTL_BIN"           || rc=1   # 兜底：PID 文件缺失时（旧脚本 / 手动起的）也能清掉
    return "$rc"
}

do_kill() {   # 强制清理：不看 PID 文件，直接按可执行路径杀
    local rc=0
    info "强制清理所有 vpn_controller 进程"
    sweep_orphans "$CTL_BIN" || rc=1
    rm -f "$CTL_PID"
    if [ "$rc" -eq 0 ]; then
        ok "清理完成"
    else
        err "清理未完全成功（见上），如需强制请确认权限后用 sudo"
    fi
    return "$rc"
}

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
    printf 'agent 通道 : %s:%s  (%s)\n' "$AGENT_BIND" "$AGENT_PORT" \
           "$([ -n "$TLS_CERT" ] && [ -n "$TLS_KEY" ] && echo 'TLS' || echo '明文 TCP')"
    printf 'HTTP 入口  : %s:%s\n' "$HTTP_BIND" "$HTTP_PORT"
    if [ -n "$TLS_CERT" ] || [ -n "$TLS_KEY" ]; then
        printf 'TLS 证书   : %s\n' "${TLS_CERT:-<未设置>}"
        printf 'TLS 私钥   : %s\n' "${TLS_KEY:-<未设置>}"
        [ -r "$TLS_CERT" ] && openssl x509 -in "$TLS_CERT" -noout -subject -enddate 2>/dev/null | sed 's/^/  /'
    fi

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

# ---------------------------------------------------------------- systemd
need_root() {
    [ "$(id -u)" -eq 0 ] || die "该操作需要 root：sudo $0 $1"
}

need_systemd() {
    have systemctl || die "未检测到 systemctl（当前系统不是 systemd）"
    [ -d /run/systemd/system ] || die "systemd 未在运行（容器/非 systemd 环境）——请用 start / fg 手动运行"
}

# 生成 unit 内容（不落盘；install 与 unit 子命令共用同一份模板）
render_unit() {
    cat <<UNIT
[Unit]
Description=ScholarVPN Admin Relay (vpn_controller)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# 以安装者身份运行，避免 logs/ run/ 被 root 接管
# （否则之后用普通用户跑本脚本会撞"权限不够"）
User=${UNIT_USER:-root}
# 运行参数从 $UNIT_ENV_FILE 读取；改完 systemctl restart $UNIT_NAME 生效
EnvironmentFile=-$UNIT_ENV_FILE
ExecStartPre=/bin/mkdir -p $LOGS_DIR $RUN_DIR
ExecStart=$SCRIPT_DIR/admin-relay.sh fg
# 只在异常退出时拉起；systemctl stop 不会触发重启
Restart=on-failure
RestartSec=5
# SIGTERM 只发给主进程（本脚本），由它的 trap 优雅停掉 vpn_controller；
# 超时后 systemd 再 SIGKILL 整个 cgroup 兜底，避免留下孤儿
KillMode=mixed
TimeoutStopSec=20

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT
}

# 把当前生效的配置固化进 EnvironmentFile。
# 刻意不写 RELAY_TOKEN：令牌始终由脚本从 $TOKEN_FILE 读取，
# 免得明文落在 /etc/default（那里是 644，任何本地用户可读）。
write_unit_env() {
    cat > "$UNIT_ENV_FILE" <<ENV
# 由 admin-relay.sh install 生成 $(date -Iseconds 2>/dev/null || date)
# 改完执行：systemctl restart $UNIT_NAME
AGENT_BIND=$AGENT_BIND
AGENT_PORT=$AGENT_PORT
HTTP_BIND=$HTTP_BIND
HTTP_PORT=$HTTP_PORT
TLS_CERT=$TLS_CERT
TLS_KEY=$TLS_KEY
AGENTS_FILE=$AGENTS_FILE
LOGS_DIR=$LOGS_DIR
RUN_DIR=$RUN_DIR
ENV
    chmod 644 "$UNIT_ENV_FILE"
}

do_install() {
    need_root install
    need_systemd

    # 服务以安装者身份运行：sudo 场景取 SUDO_USER，直接 root 登录则仍用 root。
    # 目的是让 logs/run/令牌文件的属主保持一致，避免普通用户后续操作撞权限。
    UNIT_USER="${SUDO_USER:-root}"

    # 先把依赖/构建/令牌备齐，否则装完服务也起不来，排查起来更绕
    check_deps || die "依赖检查未通过，修好再安装"
    build_if_needed
    prepare_dirs
    ensure_relay_token
    prepare_tls

    # 目录与令牌交给运行用户，服务才读得动；
    # build/ 也一并交出——否则 root 编译出的产物会让之后普通用户 rebuild 撞权限
    if [ "$UNIT_USER" != "root" ]; then
        chown -R "$UNIT_USER" "$LOGS_DIR" "$RUN_DIR" "$BUILD_DIR" 2>/dev/null \
            || warn "chown 到 $UNIT_USER 失败"
        [ -f "$TOKEN_FILE" ] && chown "$UNIT_USER" "$TOKEN_FILE" 2>/dev/null || true
    fi

    write_unit_env
    render_unit > "$UNIT_FILE"
    chmod 644 "$UNIT_FILE"

    systemctl daemon-reload
    systemctl enable "$UNIT_NAME" >/dev/null 2>&1 || warn "enable 失败（不影响本次启动）"
    systemctl restart "$UNIT_NAME" || die "启动失败：journalctl -u $UNIT_NAME -n 50 --no-pager"

    ok "已安装并设为开机自启：$UNIT_NAME"
    info "运行用户   : $UNIT_USER"
    info "unit 文件  : $UNIT_FILE"
    info "环境变量   : $UNIT_ENV_FILE"
    info "查看状态   : systemctl status $UNIT_NAME"
    info "跟踪日志   : journalctl -u $UNIT_NAME -f"
    info "HTTP 入口令牌: $TOKEN_FILE（cat 查看）"
}

do_uninstall() {
    need_root uninstall
    need_systemd
    systemctl disable --now "$UNIT_NAME" >/dev/null 2>&1 || true
    rm -f "$UNIT_FILE" "$UNIT_ENV_FILE"
    systemctl daemon-reload
    ok "已卸载 $UNIT_NAME"
    info "logs/ run/ agents.txt 保留未删（要彻底清理请手动删）"
}

do_enable() {
    need_root enable
    need_systemd
    systemctl enable "$UNIT_NAME" || die "enable 失败（先执行 install？）"
    ok "已设为开机自启：$UNIT_NAME"
}

do_disable() {
    need_root disable
    need_systemd
    systemctl disable "$UNIT_NAME" || die "disable 失败"
    ok "已取消开机自启：$UNIT_NAME（当前进程仍在跑，要停请用 stop）"
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
    kill)         do_kill ;;
    restart)      do_stop; do_start ;;
    status)       ensure_relay_token >/dev/null 2>&1 || true; do_status ;;
    logs)         do_logs ;;
    doctor)       do_doctor ;;
    install)      do_install ;;      # 装成 systemd 服务：开机自启 + 崩溃自动拉起
    uninstall)    do_uninstall ;;    # 停止 + 取消自启 + 删除 unit
    enable)       do_enable ;;       # 仅设开机自启
    disable)      do_disable ;;      # 仅取消开机自启
    unit)         render_unit ;;     # 打印 unit 内容（不写盘，用于检查）
    add-agent)    do_add_agent "${1:-}" ;;
    del-agent)    do_del_agent "${1:-}" ;;
    list-agents)  do_list_agents ;;
    token)        ensure_relay_token >/dev/null 2>&1; printf '%s\n' "$RELAY_TOKEN" ;;
    help|-h|--help) usage ;;
    *) err "未知子命令: $cmd"; printf '\n'; usage; exit 1 ;;
esac
