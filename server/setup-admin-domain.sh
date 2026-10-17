#!/usr/bin/env bash
# ============================================================================
# setup-admin-domain.sh —— 后台管理“域名 + 正式证书”一键配置
# ----------------------------------------------------------------------------
# 做的事：
#   1) 检查域名是否已解析、80 端口是否可用
#   2) 用 certbot（Let's Encrypt）申请/续期证书
#   3) 把证书复制到 server/tls/（权限 644/600）
#   4) 生成 server/admin-domain.env（脚本自动读取）
#   5) 重启中转、VPN 管理端和中转网页，并注册 certbot 续期钩子
#
# 用法：
#   sudo ./setup-admin-domain.sh                 # 默认 scholarvpn.homes
#   sudo ./setup-admin-domain.sh example.com
#   sudo ./setup-admin-domain.sh --check         # 只检查 DNS/端口/certbot
#   sudo ./setup-admin-domain.sh --reload-only   # 证书已存在时只复制+重启
#
# 注意：
#   - 域名必须已经有 A 记录指向本机公网 IP，且公网能访问 80 端口；
#     域名审核中/未解析时 --check 会直接告诉你缺什么。
#   - 证书签发/续期全部交给 certbot；本脚本不实现 ACME，也不生成自签证书。
#   - 不想用 80 端口（HTTP-01）时，改用 certbot 的 DNS-01 插件，然后把
#     证书路径写进 admin-domain.env，再执行 --reload-only。
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_DOMAIN="scholarvpn.homes"
WEB_DIR="$(cd "$SCRIPT_DIR/../tools/webadmin" && pwd)"
TLS_DIR="$SCRIPT_DIR/tls"
ENV_FILE="$SCRIPT_DIR/admin-domain.env"
RUN_DIR="$SCRIPT_DIR/run"
LOG_DIR="$SCRIPT_DIR/logs"
WEB_PORT_DEFAULT=8443

MODE="full"
case "${1:-}" in
    --check)       MODE="check"; shift ;;
    --reload-only) MODE="reload"; shift ;;
    -h|--help)     sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
esac
DOMAIN="${1:-$DEFAULT_DOMAIN}"

say()  { printf '[*] %s\n' "$*"; }
ok()   { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die()  { printf '[x] %s\n' "$*" >&2; exit 1; }

# 必须是 root：certbot/80 端口/写 /etc/letsencrypt 都需要
if [ "$(id -u)" -ne 0 ]; then
    die "请用 sudo 运行： sudo $0 $*"
fi

RUN_USER="${SUDO_USER:-$(stat -c '%U' "$SCRIPT_DIR")}"
[ -n "$RUN_USER" ] && [ "$RUN_USER" != "root" ] \
    || die "无法确定运行用户（请用普通用户 + sudo 运行，不要直接 root 登录）"

CERT_DIR="/etc/letsencrypt/live/$DOMAIN"
PUBLIC_IP=""

check_dns() {
    say "检查域名解析：$DOMAIN"
    local ips
    ips="$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ' || true)"
    [ -n "$ips" ] || die "DNS 尚未解析：$DOMAIN 没有 A 记录。等注册局审核通过/添加 A 记录后再运行。"
    ok "DNS: $DOMAIN -> $ips"

    PUBLIC_IP="$(curl -4 -sS --max-time 6 https://api.ipify.org 2>/dev/null || true)"
    if [ -n "$PUBLIC_IP" ]; then
        say "本机公网出口：$PUBLIC_IP"
        if ! printf '%s\n' "$ips" | grep -qw "$PUBLIC_IP"; then
            warn "DNS 解析结果里没有本机公网出口 $PUBLIC_IP；"
            warn "如果服务器在 NAT/端口映射后面，请确认域名指向的是对外公网 IP。"
        fi
    else
        warn "取不到本机公网出口 IP（不影响继续，但请自行确认 DNS 指向正确）。"
    fi
}

check_port80() {
    say "检查 80 端口"
    if ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE '[:.]80$'; then
        die "80 端口已被占用。certbot --standalone 需要空闲的 80；请先停掉占用进程，或改用 DNS-01。"
    fi
    ok "80 端口空闲"
}

ensure_certbot() {
    if command -v certbot >/dev/null 2>&1; then
        ok "certbot: $(command -v certbot)"
        return 0
    fi
    command -v apt-get >/dev/null 2>&1 \
        || die "未安装 certbot，且不是 apt 系统；请先安装 certbot 再运行。"
    say "安装 certbot ..."
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq certbot
    command -v certbot >/dev/null 2>&1 || die "certbot 安装失败"
    ok "certbot 安装完成"
}

issue_cert() {
    local email="${LETSENCRYPT_EMAIL:-}"
    if [ -z "$email" ]; then
        if [ -t 0 ]; then
            read -r -p "Let's Encrypt 通知邮箱: " email
        fi
    fi
    [ -n "$email" ] || die "缺少邮箱。请设置 LETSENCRYPT_EMAIL=you@example.com 后重试。"

    say "申请/续期证书：$DOMAIN"
    certbot certonly --standalone --non-interactive --agree-tos \
        --email "$email" -d "$DOMAIN" --keep-until-expiring
    [ -f "$CERT_DIR/fullchain.pem" ] && [ -f "$CERT_DIR/privkey.pem" ] \
        || die "certbot 成功返回但找不到证书：$CERT_DIR"
    ok "证书就绪：$CERT_DIR"
}

install_certs() {
    [ -f "$CERT_DIR/fullchain.pem" ] && [ -f "$CERT_DIR/privkey.pem" ] \
        || die "证书不存在：$CERT_DIR（先申请证书，或检查 --reload-only 的域名）"
    say "复制证书到 $TLS_DIR"
    install -d -m 700 -o "$RUN_USER" -g "$RUN_USER" "$TLS_DIR"
    install -m 644 -o "$RUN_USER" -g "$RUN_USER" \
        "$CERT_DIR/fullchain.pem" "$TLS_DIR/fullchain.pem"
    install -m 600 -o "$RUN_USER" -g "$RUN_USER" \
        "$CERT_DIR/privkey.pem" "$TLS_DIR/privkey.pem"
    openssl x509 -in "$TLS_DIR/fullchain.pem" -noout -checkend 0 >/dev/null \
        || die "复制后的证书已过期/不可解析"
    ok "证书已复制（fullchain 644，privkey 600）"
}

write_env() {
    say "写入 $ENV_FILE"
    umask 077
    cat > "$ENV_FILE" <<EOF
# 由 setup-admin-domain.sh 生成（$(date '+%F %T')）
# 公共 CA（Let's Encrypt）：agent 用系统 CA 校验，不写 RELAY_TLS_CA。
DOMAIN=$DOMAIN

TLS_CERT=$TLS_DIR/fullchain.pem
TLS_KEY=$TLS_DIR/privkey.pem

RELAY_HOST=$DOMAIN
RELAY_TLS=1
RELAY_TLS_NAME=$DOMAIN

WEBADMIN_BIND=0.0.0.0
WEBADMIN_PORT=$WEB_PORT_DEFAULT
WEBADMIN_TLS_CERT=$TLS_DIR/fullchain.pem
WEBADMIN_TLS_KEY=$TLS_DIR/privkey.pem
CONTROLLER_URL=http://127.0.0.1:18081
EOF
    chown "$RUN_USER:$RUN_USER" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    umask 022
    ok "配置已写入"
}

as_user() {
    if command -v runuser >/dev/null 2>&1; then
        runuser -u "$RUN_USER" -- bash -c "$*"
    else
        su -s /bin/bash "$RUN_USER" -c "$*"
    fi
}

restart_relay() {
    say "重启中转端（agent TLS）..."
    as_user "cd '$SCRIPT_DIR' && ./admin-relay.sh restart"
}

restart_vpn() {
    say "重启 VPN 管理端（用域名回连中转）..."
    as_user "cd '$SCRIPT_DIR' && ./admin-vpn.sh restart"
}

stop_webadmin() {
    local p cwd
    if [ -f "$RUN_DIR/webadmin.pid" ]; then
        p="$(cat "$RUN_DIR/webadmin.pid" 2>/dev/null || true)"
        if [ -n "$p" ] && kill -0 "$p" 2>/dev/null; then
            kill "$p" 2>/dev/null || true
            sleep 1
            kill -0 "$p" 2>/dev/null && kill -9 "$p" 2>/dev/null || true
        fi
        rm -f "$RUN_DIR/webadmin.pid"
    fi
    # 兼容手工启动的 python3 app.py：只杀 cwd 在 tools/webadmin 的进程
    for p in $(pgrep -f 'python3 app.py' 2>/dev/null || true); do
        cwd="$(readlink -f "/proc/$p/cwd" 2>/dev/null || true)"
        if [ "$cwd" = "$(readlink -f "$WEB_DIR")" ]; then
            kill "$p" 2>/dev/null || true
        fi
    done
    sleep 0.5
}

start_webadmin() {
    say "启动中转网页（HTTPS :$WEB_PORT_DEFAULT）..."
    mkdir -p "$RUN_DIR" "$LOG_DIR"
    chown "$RUN_USER:$RUN_USER" "$RUN_DIR" "$LOG_DIR" 2>/dev/null || true
    as_user "nohup '$SCRIPT_DIR/start-admin-web.sh' >> '$LOG_DIR/webadmin.log' 2>&1 < /dev/null & echo \$! > '$RUN_DIR/webadmin.pid'"
    local i
    for i in $(seq 1 20); do
        if ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$WEB_PORT_DEFAULT$"; then
            ok "网页已监听 :$WEB_PORT_DEFAULT"
            return 0
        fi
        sleep 0.5
    done
    warn "网页没有在 5s 内监听；日志末尾："
    tail -n 20 "$LOG_DIR/webadmin.log" >&2 || true
    die "启动失败"
}

write_renew_hook() {
    local hook="/etc/letsencrypt/renewal-hooks/deploy/scholarvpn-admin.sh"
    install -d -m 755 /etc/letsencrypt/renewal-hooks/deploy
    cat > "$hook" <<EOF
#!/bin/sh
exec "$SCRIPT_DIR/setup-admin-domain.sh" --reload-only "$DOMAIN"
EOF
    chmod 755 "$hook"
    ok "已注册续期钩子：$hook"
}

print_summary() {
    printf '\n'
    ok "后台管理域名配置完成：$DOMAIN"
    say "网页：  https://$DOMAIN:$WEB_PORT_DEFAULT/"
    say "agent： $DOMAIN:19090（TLS）"
    say "证书：  $TLS_DIR/fullchain.pem"
    say "配置：  $ENV_FILE"
    printf '\n'
    say "防火墙/安全组需要放行：19090/tcp、$WEB_PORT_DEFAULT/tcp"
    say "VPN 端 18080 与中转 18081 仍只监听 127.0.0.1，不要对外放行。"
}

# -------------------------------------------------------------------- main
case "$MODE" in
    check)
        check_dns
        check_port80
        if command -v certbot >/dev/null 2>&1; then ok "certbot 已安装"; else warn "certbot 未安装"; fi
        [ -f "$CERT_DIR/fullchain.pem" ] && ok "证书已存在：$CERT_DIR" \
            || warn "证书尚不存在（运行不带 --check 的脚本申请）"
        ;;
    reload)
        install_certs
        write_env
        restart_relay
        stop_webadmin
        start_webadmin
        print_summary
        ;;
    full)
        check_dns
        check_port80
        ensure_certbot
        issue_cert
        install_certs
        write_env
        write_renew_hook
        restart_relay
        restart_vpn
        stop_webadmin
        start_webadmin
        print_summary
        ;;
esac
