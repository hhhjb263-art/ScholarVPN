#!/bin/bash
# ============================================================
# 生成浏览器插件（HTTPS 代理入口）用的自签证书
#
# 用途：没有域名、只有公网 IP 时，给 --https-proxy-port 提供 TLS 证书。
#       证书把 IP 写进 subjectAltName（IP:x.x.x.x），客户端导入信任存储后，
#       浏览器↔代理全程 TLS 且能校验服务器身份。
#
# 用法：
#   ./gen-self-signed-cert.sh <IP或域名> [输出目录，默认 ./keys]
#   例：./gen-self-signed-cert.sh 154.36.166.113
#       ./gen-self-signed-cert.sh vpn.example.com /etc/scholargvpn
#
# 产物：
#   <输出目录>/proxy.cert.pem   证书（**分发给每台客户端**导入信任存储）
#   <输出目录>/proxy.key.pem    私钥（只留服务端，0600，切勿外传）
#
# 注意：自签证书有效期默认 825 天，到期需重新生成并重新分发。
# ============================================================
set -e

TARGET="${1:?用法: $0 <IP或域名> [输出目录]}"
OUTDIR="${2:-$PWD/keys}"
DAYS="${DAYS:-825}"

# Git Bash（Windows）会把 "/CN=..." 误当路径转换，这里关掉
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

if ! command -v openssl >/dev/null 2>&1; then
    echo "[错误] 未找到 openssl（Debian/Ubuntu: apt install openssl；CentOS: yum install openssl）" >&2
    exit 1
fi

mkdir -p "$OUTDIR"
CERT="$OUTDIR/proxy.cert.pem"
KEY="$OUTDIR/proxy.key.pem"
if [ -e "$KEY" ] || [ -e "$CERT" ]; then
    echo "[错误] 已存在 $KEY 或 $CERT，先备份/删除再重新生成" >&2
    exit 1
fi

# 是 IP 还是域名：IP 用 IP: 前缀，域名用 DNS:
case "$TARGET" in
    *[!0-9.]*|"") SAN="DNS:$TARGET" ;;
    *)            SAN="IP:$TARGET" ;;
esac

echo "[*] 生成自签证书：SAN=$SAN（有效期 $DAYS 天）"
umask 077
openssl req -x509 -newkey rsa:2048 -nodes -days "$DAYS" \
    -keyout "$KEY" -out "$CERT" \
    -subj "/CN=ScholarVPN" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,digitalSignature,keyCertSign" \
    -addext "extendedKeyUsage=serverAuth" \
    -addext "subjectAltName=$SAN" 2>/dev/null
chmod 600 "$KEY"
chmod 644 "$CERT"

echo
echo "[*] 证书自检："
openssl x509 -in "$CERT" -noout -subject -dates -ext subjectAltName | sed 's/^/    /'

cat <<EOF

============================================================
下一步：

1) 启动服务端（HTTPS 代理入口，需配认证）：
   sudo ./build/vpn_server -a 10.8.0.1 -p 51820 \\
        --https-proxy-port 8443 \\
        --https-proxy-cert $CERT \\
        --https-proxy-key  $KEY \\
        --proxy-user <用户名> --proxy-pass '<强密码>'

   或 start.sh 环境变量方式：
   sudo HTTPS_PROXY_PORT=8443 HTTPS_CERT=$CERT HTTPS_KEY=$KEY \\
        PROXY_USER=<用户名> PROXY_PASS='<强密码>' ./start.sh -d

2) 防火墙/云安全组放行 TCP 8443（start.sh 会自动放行本机防火墙）

3) 每台客户端导入证书（只传 $CERT，切勿传私钥）：
   Windows : certutil -addstore -f Root proxy.cert.pem  （管理员命令行，之后重启浏览器）
   macOS   : sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain proxy.cert.pem
   Linux   : sudo cp proxy.cert.pem /usr/local/share/ca-certificates/scholargvpn.crt && sudo update-ca-certificates
             （Chrome/Chromium 使用 NSS 库时：certutil -d sql:\$HOME/.pki/nssdb -A -t "C,," -n ScholarVPN proxy.cert.pem）

4) 浏览器扩展（browser-extension/）里填：
   代理协议 = HTTPS 代理（TLS 加密，推荐）
   服务器地址 = $TARGET
   端口       = 8443
   用户名/密码 = 与服务端 --proxy-user/--proxy-pass 一致

5) 自检（任意客户端机器，-k 跳过证书校验只看连通性；导入证书后去掉 -k）：
   curl -k -x https://<用户名>:<密码>@$TARGET:8443 https://api.ipify.org
   返回服务器 IP 即为成功。
============================================================
EOF
