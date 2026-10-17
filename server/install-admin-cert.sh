#!/usr/bin/env bash
# ============================================================================
# install-admin-cert.sh —— 安装手工上传的证书（域名 + 正式证书）
# ----------------------------------------------------------------------------
# 适用：云厂商/CA 下载的证书，不是 Let's Encrypt 自动续期那套。
#
# 用法：
#   sudo ./install-admin-cert.sh <域名> <证书链.pem> <私钥.pem> [中间证书.pem]
#
# 例：
#   sudo ./install-admin-cert.sh scholarvpn.homes \
#        tls/scholarvpn.homes.pem tls/scholarvpn.homes.key
#
#   # 如果证书文件只有叶证书，单独给中间证书：
#   sudo ./install-admin-cert.sh scholarvpn.homes cert.pem key.pem chain.pem
#
# 脚本会：校验域名/私钥/证书链 → 备份旧证书 → 安装为 tls/fullchain.pem
#        和 tls/privkey.pem → 停用 acme.sh 对该域名的自动续期 → 重启服务。
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TLS_DIR="$SCRIPT_DIR/tls"
BACKUP_DIR="$TLS_DIR/backup"

say()  { printf '[*] %s\n' "$*"; }
ok()   { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die()  { printf '[x] %s\n' "$*" >&2; exit 1; }

if [ $# -lt 3 ]; then
    sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
fi

DOMAIN="$1"
CERT="$2"
KEY="$3"
CHAIN="${4:-}"

[ "$(id -u)" -eq 0 ] || die "请用 sudo 运行： sudo $0 $*"
command -v openssl >/dev/null 2>&1 || die "缺少 openssl"
[ -r "$CERT" ] || die "证书不可读: $CERT"
[ -r "$KEY" ]  || die "私钥不可读: $KEY"
[ -z "$CHAIN" ] || [ -r "$CHAIN" ] || die "中间证书不可读: $CHAIN"

TMP_FULLCHAIN=""
cleanup() { [ -n "$TMP_FULLCHAIN" ] && rm -f "$TMP_FULLCHAIN" || true; }
trap cleanup EXIT
if [ -n "$CHAIN" ]; then
    TMP_FULLCHAIN="$(mktemp)"
    cat "$CERT" "$CHAIN" > "$TMP_FULLCHAIN"
    INSTALL_CERT="$TMP_FULLCHAIN"
else
    INSTALL_CERT="$CERT"
fi

say "校验证书域名：$DOMAIN"
openssl x509 -in "$INSTALL_CERT" -noout -checkhost "$DOMAIN" >/dev/null 2>&1 \
    || die "证书不包含域名 $DOMAIN（检查 SAN）"

say "校验私钥与证书是否匹配"
A="$(openssl x509 -in "$INSTALL_CERT" -pubkey -noout 2>/dev/null \
     | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
B="$(openssl pkey -in "$KEY" -pubout -outform DER 2>/dev/null \
     | sha256sum | awk '{print $1}')"
[ -n "$A" ] && [ "$A" = "$B" ] || die "私钥与证书不匹配（或私钥有密码）"
ok "域名与私钥匹配"

COUNT="$(grep -c 'BEGIN CERTIFICATE' "$INSTALL_CERT" || true)"
[ "$COUNT" -ge 2 ] || warn "证书文件里只有 1 张证书；如果客户端报链不完整，请再传中间证书"

if openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt \
        -untrusted "$INSTALL_CERT" "$INSTALL_CERT" >/dev/null 2>&1; then
    ok "证书链已被系统 CA 验证通过"
else
    warn "系统 CA 未验通（私有 CA/自签正常）；agent 端需要配置对应信任根"
fi

mkdir -p "$TLS_DIR" "$BACKUP_DIR"
chmod 700 "$TLS_DIR"
TS="$(date +%Y%m%d%H%M%S)"
[ -f "$TLS_DIR/fullchain.pem" ] && cp -a "$TLS_DIR/fullchain.pem" "$BACKUP_DIR/fullchain-$TS.pem" || true
[ -f "$TLS_DIR/privkey.pem" ]   && cp -a "$TLS_DIR/privkey.pem"   "$BACKUP_DIR/privkey-$TS.pem"   || true

install -m 644 "$INSTALL_CERT" "$TLS_DIR/fullchain.pem"
install -m 600 "$KEY"          "$TLS_DIR/privkey.pem"
ok "已安装到 $TLS_DIR/fullchain.pem 和 privkey.pem"

# 手工证书不应被 acme.sh 覆盖：停用该域名的续期配置（保留证书文件）
for conf in "/root/.acme.sh/${DOMAIN}/${DOMAIN}.conf" \
            "/root/.acme.sh/${DOMAIN}_ecc/${DOMAIN}.conf"; do
    if [ -f "$conf" ]; then
        mv "$conf" "$conf.disabled"
        ok "已停用 acme.sh 自动续期: $conf"
    fi
done

say "重启管理服务"
if systemctl cat scholarvpn-admin-relay.service >/dev/null 2>&1; then
    systemctl restart scholarvpn-admin-relay.service
    systemctl restart scholarvpn-admin-web.service
else
    "$SCRIPT_DIR/reload-admin-tls.sh"
fi
sleep 2

echo
ok "证书安装完成"
openssl x509 -in "$TLS_DIR/fullchain.pem" -noout -subject -issuer -dates
echo
say "服务状态："
for s in scholarvpn-admin-relay scholarvpn-admin-vpn scholarvpn-admin-web; do
    if systemctl cat "$s.service" >/dev/null 2>&1; then
        printf '  %-28s %s\n' "$s" "$(systemctl is-active "$s" || true)"
    fi
done
say "HTTPS 检查："
CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 "https://$DOMAIN/" 2>/dev/null || true)"
printf '  https://%s/ -> %s\n' "$DOMAIN" "${CODE:-连接失败}"
say "续期：证书到期前重新上传新证书，再执行本脚本即可。"
