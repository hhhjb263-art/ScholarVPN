#!/bin/bash
# ============================================================
# VPN 服务端一键启动脚本（多系统兼容版）
# 兼容：Debian/Ubuntu/CentOS/RHEL/Fedora/Arch/OpenWrt 等
# 防火墙：自动选择 iptables / nftables，并补充 ufw / firewalld 放行端口
#
# 用法：
#   sudo ./start.sh [start]   前台运行（Ctrl+C 退出，便于调试）
#   sudo ./start.sh -d|daemon 后台运行（默认精简日志，重点日志存 logs/）
#                            vpn_server 异常退出时自动重启（watchdog）
#   sudo ./start.sh stop      停止后台服务
#   sudo ./start.sh restart   重启（以后台方式运行）
#   sudo ./start.sh status    查看运行状态
#   sudo ./start.sh logs      实时查看重点日志（tail -f）
#   sudo ./start.sh install   安装为 systemd 服务（关闭终端不断开，推荐）
#   sudo ./start.sh uninstall 卸载 systemd 服务
#   sudo ./start.sh doctor    诊断环境（systemd/服务/进程/日志），排查断开问题
#
# 环境变量可覆盖：TUN_IP=10.8.0.1 VPN_PORT=51820 QUIET=0 ... 等
#   QUIET=1 关闭数据包级次要日志，只保留重点日志（公网服务器推荐）
# ============================================================
set -e

# ===== 可配置项（环境变量可覆盖）=====
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VPN_BIN="${VPN_BIN:-$SCRIPT_DIR/build/vpn_server}"
TUN_NAME="${TUN_NAME:-vpn0}"
TUN_IP="${TUN_IP:-10.8.0.1}"
TUN_PREFIX="${TUN_PREFIX:-24}"
TUN_MTU="${TUN_MTU:-1400}"
TUN_NET="${TUN_NET:-10.8.0.0/24}"
VPN_PORT="${VPN_PORT:-51820}"
LISTEN_IP="${LISTEN_IP:-0.0.0.0}"
KEY_PATH="${KEY_PATH:-$SCRIPT_DIR/keys/server_sig.key}"
MAX_CLIENTS="${MAX_CLIENTS:-0}"     # 最大并发客户端数，0=服务端默认(64)；多用户自动分配虚拟 IP
ENABLE_IPV6="${ENABLE_IPV6:-0}"        # 1=同时开启 IPv6 转发
# ---- 运行 / 日志 ----
LOGS_DIR="${LOGS_DIR:-$SCRIPT_DIR/logs}"        # 重点日志保存目录（按天轮转）
RUN_DIR="${RUN_DIR:-$SCRIPT_DIR/run}"           # PID / 标志文件目录
LOG_FILE="$LOGS_DIR/vpn-server-$(date +%Y%m%d).log"
PID_FILE="$RUN_DIR/vpn_server.watchdog.pid"     # watchdog 守护进程 PID
VPID_FILE="$RUN_DIR/vpn_server.pid"             # 实际 vpn_server 进程 PID
STOP_FLAG="$RUN_DIR/.vpn_server.stop"           # 停止标志（watchdog 据此不再重启）
MAX_RESTARTS="${MAX_RESTARTS:-0}"               # 最大自动重启次数，0=无限
QUIET="${QUIET:-1}"   # 1=精简日志（公网服务器推荐，只记重点），0=完整日志

# ===== 前置检查 =====
if [ "$(id -u)" -ne 0 ]; then
    echo "[错误] 需要 root 权限运行：sudo $0 $*" >&2
    exit 1
fi
if [ ! -x "$VPN_BIN" ]; then
    echo "[错误] 找不到 vpn_server 可执行文件：$VPN_BIN" >&2
    echo "       请先构建：cmake -S . -B build && cmake --build build" >&2
    exit 1
fi
if [ ! -f "$KEY_PATH" ]; then
    echo "[提示] 未找到私钥 $KEY_PATH：首次启动时 vpn_server 会自动生成密钥对" >&2
fi

# ===== 子命令解析 =====
MODE="${1:-start}"
DAEMON=0
case "$MODE" in
    start)        : ;;
    -d|daemon)    MODE=start; DAEMON=1 ;;
    stop|status|logs|restart|install|uninstall|doctor) : ;;
    *) echo "[错误] 未知参数: $MODE（支持 start / -d|daemon / stop / restart / status / logs / install / uninstall / doctor）" >&2
       exit 1 ;;
esac

# ---- 进程管理工具函数 ----
is_running() {
    [ -f "$PID_FILE" ] || return 1
    local pid; pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

do_status() {
    if is_running; then
        local vpid=""
        [ -f "$VPID_FILE" ] && vpid="$(cat "$VPID_FILE")"
        if [ -n "$vpid" ] && kill -0 "$vpid" 2>/dev/null; then
            echo "[*] vpn_server 运行中 (PID $vpid, 守护 $(cat "$PID_FILE"))"
        else
            echo "[*] vpn_server 守护运行中（进程可能正在自动重启）"
        fi
        echo "    日志: $LOG_FILE"
        return 0
    fi
    echo "[*] vpn_server 未运行"
    rm -f "$PID_FILE" "$VPID_FILE" "$STOP_FLAG"
    return 1
}

do_stop() {
    if [ ! -f "$PID_FILE" ] && [ ! -f "$VPID_FILE" ]; then
        echo "[*] vpn_server 未运行，无需停止"
        rm -f "$PID_FILE" "$VPID_FILE" "$STOP_FLAG"
        return 0
    fi
    echo "[*] 停止 vpn_server ..."
    # 1) 置停止标志，通知 watchdog 不要再重启
    touch "$STOP_FLAG" 2>/dev/null || true
    # 2) 优雅停止实际 vpn_server 进程
    if [ -f "$VPID_FILE" ]; then
        local vpid; vpid="$(cat "$VPID_FILE")"
        [ -n "$vpid" ] && kill "$vpid" 2>/dev/null || true
    fi
    # 3) 停止 watchdog 守护进程
    if [ -f "$PID_FILE" ]; then
        local wpid; wpid="$(cat "$PID_FILE")"
        [ -n "$wpid" ] && kill "$wpid" 2>/dev/null || true
    fi
    # 等待全部退出
    for _ in $(seq 1 50); do
        local alive=0
        if [ -f "$VPID_FILE" ]; then vpid="$(cat "$VPID_FILE")"; [ -n "$vpid" ] && kill -0 "$vpid" 2>/dev/null && alive=1; fi
        if [ -f "$PID_FILE" ]; then wpid="$(cat "$PID_FILE")"; [ -n "$wpid" ] && kill -0 "$wpid" 2>/dev/null && alive=1; fi
        [ "$alive" = "0" ] && break
        sleep 0.1
    done
    # 强制清理
    if [ -f "$VPID_FILE" ]; then vpid="$(cat "$VPID_FILE")"; [ -n "$vpid" ] && kill -0 "$vpid" 2>/dev/null && kill -9 "$vpid" 2>/dev/null || true; fi
    if [ -f "$PID_FILE" ]; then wpid="$(cat "$PID_FILE")"; [ -n "$wpid" ] && kill -0 "$wpid" 2>/dev/null && kill -9 "$wpid" 2>/dev/null || true; fi
    rm -f "$PID_FILE" "$VPID_FILE" "$STOP_FLAG"
    echo "[*] 已停止"
}

do_logs() {
    if [ ! -f "$LOG_FILE" ]; then
        echo "[*] 尚无日志文件：$LOG_FILE"
        exit 1
    fi
    echo "[*] 实时查看重点日志（Ctrl+C 退出）：$LOG_FILE"
    tail -f "$LOG_FILE"
}

# 诊断环境：systemd / 服务文件 / 进程 / 日志，用于排查“关闭终端后断开”等问题
do_doctor() {
    echo "========== VPN 服务端环境诊断 =========="
    # 1) 系统与 init
    local os=""
    if [ -r /etc/os-release ]; then
        . /etc/os-release 2>/dev/null || true
        [ -n "$PRETTY_NAME" ] && os="$PRETTY_NAME"
    fi
    [ -z "$os" ] && os="$(uname -s -r)"
    echo "[1] 系统 / init"
    echo "    OS     : $os"
    echo "    PID 1  : $(ps -p 1 -o comm= 2>/dev/null || echo 未知)"
    if command -v systemctl >/dev/null 2>&1; then
        echo "    systemd: 可用 ($(systemctl --version 2>/dev/null | head -1))"
    else
        echo "    systemd: 不可用 → 只能用 daemon 模式（关闭终端可能断开）"
    fi
    echo
    # 2) 可执行文件
    echo "[2] 程序"
    if [ -x "$VPN_BIN" ]; then
        echo "    $VPN_BIN  (存在)"
    else
        echo "    $VPN_BIN  (缺失! 请先 cmake -S . -B build && cmake --build build)"
    fi
    echo
    # 3) systemd 服务
    echo "[3] systemd 服务"
    if [ -f /etc/systemd/system/vpn-server.service ]; then
        echo "    服务文件: /etc/systemd/system/vpn-server.service (存在)"
        grep -E "ExecStart=|StandardOutput=" /etc/systemd/system/vpn-server.service 2>/dev/null | sed 's/^/      /'
        if systemctl is-active --quiet vpn-server 2>/dev/null; then
            echo "    状态    : 运行中 (active) → 关闭终端不会断开"
        else
            echo "    状态    : 未运行 / 失败"
            echo "    最近日志:"
            journalctl -u vpn-server -n 6 --no-pager 2>/dev/null | sed 's/^/      /' || true
            echo "    可重试  : sudo systemctl restart vpn-server  或  sudo ./start.sh install"
        fi
        if systemctl is-enabled --quiet vpn-server 2>/dev/null; then
            echo "    开机自启: 已启用"
        else
            echo "    开机自启: 未启用 (sudo systemctl enable vpn-server)"
        fi
    else
        echo "    未安装! → sudo ./start.sh install"
    fi
    if [ -f /etc/default/vpn-server ]; then
        echo "    环境文件: /etc/default/vpn-server (存在；编辑后 systemctl restart vpn-server 生效)"
        grep -E "^(TUN_IP|VPN_PORT|LISTEN_IP|MAX_CLIENTS|QUIET|KEY_PATH)=" /etc/default/vpn-server 2>/dev/null | sed 's/^/      /'
    else
        echo "    环境文件: 无 (/etc/default/vpn-server 缺失，使用 start.sh 默认参数)"
    fi
    echo
    # 4) 当前进程
    echo "[4] 后台进程"
    local found=0 f p
    for f in "$PID_FILE" "$VPID_FILE"; do
        if [ -f "$f" ]; then
            p="$(cat "$f" 2>/dev/null || true)"
            if [ -n "$p" ] && kill -0 "$p" 2>/dev/null; then
                echo "    $(basename "$f"): PID $p (存活)"
                found=1
            else
                echo "    $(basename "$f"): PID $p (已退出, 残留 PID 文件)"
            fi
        fi
    done
    local vp; vp="$(pgrep -f 'build/vpn_server' 2>/dev/null | head -3 | tr '\n' ' ')"
    [ -n "$vp" ] && echo "    vpn_server 进程: $vp"
    if [ "$found" = "0" ] && [ -z "$vp" ]; then
        echo "    当前无 vpn 相关进程"
    fi
    echo
    # 5) 日志
    echo "[5] 日志文件"
    if [ -d "$LOGS_DIR" ]; then
        ls -lt "$LOGS_DIR" 2>/dev/null | head -4 | sed 's/^/    /'
    else
        echo "    无日志目录 $LOGS_DIR"
    fi
    echo "========== 诊断完成 =========="
    echo "建议: 服务器有 systemd 就用: sudo ./start.sh install（关闭终端不断开）"
}

# 安装为 systemd 服务：独立于 SSH 会话，关闭终端不断开，开机自启 + 崩溃自动重启
do_install() {
    if ! command -v systemctl >/dev/null 2>&1; then
        echo "[错误] 未检测到 systemd（systemctl 不存在），无法安装系统服务" >&2
        echo "       可继续用 daemon 模式：./start.sh -d" >&2
        exit 1
    fi
    # 若有 watchdog 后台任务，先停止避免端口冲突
    do_stop
    mkdir -p "$LOGS_DIR" "$RUN_DIR"
    SERVICE="/etc/systemd/system/vpn-server.service"
    TEMPLATE="$SCRIPT_DIR/vpn-server.service"
    if [ ! -f "$TEMPLATE" ]; then
        echo "[错误] 找不到服务模板: $TEMPLATE" >&2
        exit 1
    fi
    echo "[*] 生成系统服务: $SERVICE"
    # 从模板生成，自动替换路径占位符为实际路径（不写死）
    sed -e "s|__SCRIPT_DIR__|$SCRIPT_DIR|g" \
        -e "s|__LOGS_DIR__|$LOGS_DIR|g" \
        "$TEMPLATE" > "$SERVICE"
    # 生成环境文件：把 install 时的配置固化为 systemd EnvironmentFile（可手动编辑）
    ENV_FILE="/etc/default/vpn-server"
    {
        echo "# 由 start.sh install 生成（$(date '+%F %T')）。可手动修改后执行：systemctl restart vpn-server"
        echo "VPN_BIN=\"$VPN_BIN\""
        echo "TUN_NAME=\"$TUN_NAME\""
        echo "TUN_IP=\"$TUN_IP\""
        echo "TUN_PREFIX=\"$TUN_PREFIX\""
        echo "TUN_MTU=\"$TUN_MTU\""
        echo "TUN_NET=\"$TUN_NET\""
        echo "VPN_PORT=\"$VPN_PORT\""
        echo "LISTEN_IP=\"$LISTEN_IP\""
        echo "KEY_PATH=\"$KEY_PATH\""
        echo "MAX_CLIENTS=\"$MAX_CLIENTS\""
        echo "ENABLE_IPV6=\"$ENABLE_IPV6\""
        echo "QUIET=\"$QUIET\""
        echo "MAX_RESTARTS=\"$MAX_RESTARTS\""
        echo "LOGS_DIR=\"$LOGS_DIR\""
        echo "RUN_DIR=\"$RUN_DIR\""
    } > "$ENV_FILE"
    echo "[*] 已生成环境文件: $ENV_FILE（可编辑后 systemctl restart vpn-server 生效）"
    systemctl daemon-reload
    systemctl enable vpn-server >/dev/null 2>&1 || true
    systemctl restart vpn-server
    sleep 2
    if systemctl is-active --quiet vpn-server; then
        echo "[*] 已安装并启动 vpn-server 系统服务（开机自启 + 崩溃自动重启，SSH 断开不影响）"
        echo "    状态: systemctl status vpn-server   停止: systemctl stop vpn-server"
        echo "    日志: journalctl -u vpn-server -f   或: ./start.sh logs"
    else
        echo "[错误] 服务启动失败，请查看: journalctl -u vpn-server -e" >&2
        exit 1
    fi
}

do_uninstall() {
    if [ -f /etc/systemd/system/vpn-server.service ]; then
        systemctl disable vpn-server >/dev/null 2>&1 || true
        systemctl stop vpn-server >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/vpn-server.service
        systemctl daemon-reload
        echo "[*] 已卸载 vpn-server 系统服务"
    else
        echo "[*] 未安装 vpn-server 系统服务"
    fi
    if [ -f /etc/default/vpn-server ]; then
        rm -f /etc/default/vpn-server
        echo "[*] 已删除环境文件 /etc/default/vpn-server"
    fi
}

# ===== 主流程：stop / status / logs 无需网络配置 =====
case "$MODE" in
    stop)      do_stop;   exit 0 ;;
    status)    do_status; exit 0 ;;
    logs)      do_logs;   exit 0 ;;
    doctor)    do_doctor; exit 0 ;;
    install)   do_install;   exit 0 ;;
    uninstall) do_uninstall; exit 0 ;;
    restart)   do_stop;   DAEMON=1 ;;
    start)     : ;;
esac

# ===== 系统识别 =====
detect_os() {
    if [ -r /etc/os-release ]; then
        . /etc/os-release
        echo "$PRETTY_NAME"
    else
        uname -s -r
    fi
}
echo "[*] 系统: $(detect_os)"

# ===== 1. 内核 IP 转发 =====
echo "[*] 开启 IP 转发"
echo 1 > /proc/sys/net/ipv4/ip_forward
# 持久化：优先 sysctl.d（现代发行版），回退 /etc/sysctl.conf
if [ -d /etc/sysctl.d ]; then
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-vpn.conf
else
    grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf 2>/dev/null || \
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
if [ "$ENABLE_IPV6" = "1" ]; then
    echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-vpn.conf
fi

# ===== 2. 检测出口网卡（iproute2，回退 ip addr）=====
detect_iface() {
    local iface
    iface=$(ip route 2>/dev/null | awk '/^default/ {print $5; exit}')
    if [ -z "$iface" ]; then
        iface=$(ip -4 addr show 2>/dev/null | awk '/^[0-9]+:/ {gsub(":","",$2); if ($2!="lo") {print $2; exit}}')
    fi
    [ -z "$iface" ] && iface="eth0"
    echo "$iface"
}
IFACE="${IFACE:-$(detect_iface)}"
echo "[*] 出口网卡: $IFACE"

# ===== 3. 防火墙 / NAT（自动选择 iptables 或 nftables）=====
setup_firewall() {
    # 3.1 优先 iptables（多数系统都有，即使后端是 nft）
    if command -v iptables >/dev/null 2>&1; then
        echo "[*] 使用 iptables 配置 NAT / 转发 / 端口"
        iptables -t nat -C POSTROUTING -s "$TUN_NET" -o "$IFACE" -j MASQUERADE 2>/dev/null || \
            iptables -t nat -A POSTROUTING -s "$TUN_NET" -o "$IFACE" -j MASQUERADE
        iptables -C FORWARD -i "$TUN_NAME" -o "$IFACE" -j ACCEPT 2>/dev/null || \
            iptables -A FORWARD -i "$TUN_NAME" -o "$IFACE" -j ACCEPT
        iptables -C FORWARD -i "$IFACE" -o "$TUN_NAME" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
            iptables -A FORWARD -i "$IFACE" -o "$TUN_NAME" -m state --state ESTABLISHED,RELATED -j ACCEPT
        iptables -C INPUT -p udp --dport "$VPN_PORT" -j ACCEPT 2>/dev/null || \
            iptables -A INPUT -p udp --dport "$VPN_PORT" -j ACCEPT
        return 0
    fi
    # 3.2 回退 nftables（先删旧表保证幂等）
    if command -v nft >/dev/null 2>&1; then
        echo "[*] 使用 nftables 配置 NAT / 转发 / 端口"
        nft delete table inet vpn 2>/dev/null || true
        nft -f - <<EOF
table inet vpn {
    chain forward {
        type filter hook forward priority 0; policy accept;
        iifname "$TUN_NAME" oifname "$IFACE" accept
        oifname "$TUN_NAME" ct state established,related accept
    }
    chain input {
        type filter hook input priority 0; policy accept;
        udp dport $VPN_PORT accept
    }
    chain postrouting {
        type nat hook postrouting priority 100;
        ip saddr $TUN_NET oifname "$IFACE" masquerade
    }
}
EOF
        return 0
    fi
    echo "[警告] 未找到 iptables / nftables，NAT 可能未生效" >&2
}
setup_firewall

# ===== 4. 补充：ufw / firewalld 放行端口（若存在）=====
if command -v ufw >/dev/null 2>&1; then
    echo "[*] ufw 放行 UDP/$VPN_PORT"
    ufw allow "$VPN_PORT/udp" >/dev/null 2>&1 || true
fi
if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active firewalld >/dev/null 2>&1; then
    echo "[*] firewalld 放行 UDP/$VPN_PORT"
    firewall-cmd --permanent --add-port="$VPN_PORT/udp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
fi

# ===== 5. 启动 vpn_server =====
ARGS=(-l "$LISTEN_IP" -p "$VPN_PORT" -n "$TUN_NAME" -a "$TUN_IP"
      --prefix "$TUN_PREFIX" --mtu "$TUN_MTU" -k "$KEY_PATH")
if [ -n "$MAX_CLIENTS" ] && [ "$MAX_CLIENTS" -gt 0 ] 2>/dev/null; then
    ARGS+=(--max-clients "$MAX_CLIENTS")
fi
if [ "$QUIET" = "1" ]; then
    ARGS+=(--quiet)
    LOG_DESC="精简（仅重点日志）"
else
    LOG_DESC="完整（含数据包级日志）"
fi

if [ "$DAEMON" = "1" ]; then
    mkdir -p "$LOGS_DIR" "$RUN_DIR"
    if is_running; then
        echo "[错误] vpn_server 已在运行（守护 PID $(cat "$PID_FILE")），请先执行 stop" >&2
        exit 1
    fi
    rm -f "$STOP_FLAG" "$VPID_FILE"
    ARGS_STR="-l $LISTEN_IP -p $VPN_PORT -n $TUN_NAME -a $TUN_IP --prefix $TUN_PREFIX --mtu $TUN_MTU -k $KEY_PATH"
    if [ -n "$MAX_CLIENTS" ] && [ "$MAX_CLIENTS" -gt 0 ] 2>/dev/null; then
        ARGS_STR="$ARGS_STR --max-clients $MAX_CLIENTS"
    fi
    [ "$QUIET" = "1" ] && ARGS_STR="$ARGS_STR --quiet"
    # 生成 watchdog 守护脚本：vpn_server 异常退出时自动重启
    cat > "$RUN_DIR/watchdog.sh" <<WDE
#!/bin/bash
# 自动生成的 vpn_server 守护脚本：异常退出自动重启（由 start.sh 管理）
set +e
VPN_BIN="$VPN_BIN"
LOG_FILE="$LOG_FILE"
VPID_FILE="$VPID_FILE"
STOP_FLAG="$STOP_FLAG"
ARGS_STR="$ARGS_STR"
RESTARTS=0
# 收到 TERM/INT：置停止标志，让主循环安全退出
TSTAMP(){ date '+%F %T'; }
trap '[ -f "$STOP_FLAG" ] || touch "$STOP_FLAG"' TERM INT
while true; do
    rm -f "$STOP_FLAG"
    "\$VPN_BIN" \$ARGS_STR >> "\$LOG_FILE" 2>&1 &
    VPID=\$!
    echo "\$VPID" > "\$VPID_FILE"
    wait "\$VPID"
    code=\$?
    if [ -f "\$STOP_FLAG" ]; then
        break
    fi
    RESTARTS=\$((RESTARTS+1))
    if [ "\$MAX_RESTARTS" != "0" ] && [ "\$RESTARTS" -ge "\$MAX_RESTARTS" ]; then
        echo "[watchdog] \$(TSTAMP) 已达最大重启次数 \$MAX_RESTARTS，放弃自动重启" >> "\$LOG_FILE"
        break
    fi
    echo "[watchdog] \$(TSTAMP) vpn_server 异常退出 (code=\$code, 第 \$RESTARTS 次)，3 秒后自动重启" >> "\$LOG_FILE"
    sleep 3
done
rm -f "\$STOP_FLAG" "\$VPID_FILE"
WDE
    chmod +x "$RUN_DIR/watchdog.sh"
    export MAX_RESTARTS
    echo "[*] 后台启动 vpn_server（异常退出将自动重启）..."
    echo "    日志模式: $LOG_DESC"
    echo "    重点日志: $LOG_FILE"
    # 彻底脱离当前 SSH 终端：新会话 + 忽略挂断 + 解除 job 关联
    cd /
    umask 022
    nohup setsid "$RUN_DIR/watchdog.sh" > /dev/null 2>&1 < /dev/null &
    disown
    echo $! > "$PID_FILE"
    sleep 2
    if is_running && [ -f "$VPID_FILE" ] && kill -0 "$(cat "$VPID_FILE")" 2>/dev/null; then
        echo "[*] 已后台运行"
        echo "    vpn_server PID: $(cat "$VPID_FILE")   守护 PID: $(cat "$PID_FILE")"
        echo "    状态: ./start.sh status   日志: ./start.sh logs   停止: ./start.sh stop"
        echo "    [提示] 若关闭 SSH 后仍会断开，请改用 systemd 服务: ./start.sh install"
    else
        echo "[错误] vpn_server 未能正常启动，请查看日志: $LOG_FILE" >&2
        do_stop
        exit 1
    fi
else
    echo "[*] 前台启动 vpn_server: listen=$LISTEN_IP:$VPN_PORT tun=$TUN_NAME($TUN_IP/$TUN_PREFIX mtu=$TUN_MTU)"
    echo "    key=$KEY_PATH"
    echo "    日志模式: $LOG_DESC"
    echo "    [按 Ctrl+C 退出]"
    exec "$VPN_BIN" "${ARGS[@]}"
fi

