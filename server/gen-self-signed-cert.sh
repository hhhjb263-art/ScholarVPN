#!/bin/bash
# ============================================================
# 生成浏览器插件（HTTPS 代理入口）用的证书
#
# 默认（推荐）：CA + 叶证书两级签发
#   ca.key.pem / ca.cert.pem     自建 CA（客户端只导入 ca.cert.pem）
#   proxy.key.pem / proxy.cert.pem  服务器用的叶证书（CA:FALSE，serverAuth，SAN=IP/域名）
#   为什么这样更安全：服务器上只放叶证书私钥，即使该私钥泄露也无法用它
#   签发任意域名的证书；CA 私钥可离线保存/用完删除。
#
# 兼容模式：--self-signed（旧的单张自签证书，CA:TRUE 直接当服务器证书，
#   客户端导入它本身）——私钥泄露等于可伪造任意站点证书，仅建议临时使用。
#
# 用法：
#   ./gen-self-signed-cert.sh <IP或域名> [输出目录，默认 ./keys] [--self-signed]
#     --name-constraints   给 CA 加名称约束（只允许为该 IP/域名签发，进一步限制
#                          CA 私钥泄露的影响面；部分老客户端可能不兼容）
#   例：./gen-self-signed-cert.sh 154.36.166.113
#       ./gen-self-signed-cert.sh vpn.example.com /etc/scholargvpn --name-constraints
#
# 产物分发：
#   ca.cert.pem   → 每台客户端导入"受信任的根证书颁发机构"（公开文件）
#   proxy.*.pem   → 只留服务器（proxy.key.pem 0600，切勿外传）
# ============================================================
set -e

TARGET="${1:?用法: $0 <IP或域名> [输出目录] [--self-signed] [--name-constraints]}"
OUTDIR="${2:-$PWD/keys}"
DAYS="${DAYS:-825}"
SELF_SIGNED=0
NAME_CONSTRAINTS=0
for a in "$@"; do
    case "$a" in
        --self-signed)      SELF_SIGNED=1 ;;
        --name-constraints) NAME_CONSTRAINTS=1 ;;
    esac
done

# Git Bash（Windows）会把 "/CN=..." 误当路径转换，这里关掉
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

if ! command -v openssl >/dev/null 2>&1; then
    echo "[错误] 未找到 openssl（Debian/Ubuntu: apt install openssl；CentOS: yum install openssl）" >&2
    exit 1
fi

mkdir -p "$OUTDIR"
CA_CERT="$OUTDIR/ca.cert.pem"
CA_KEY="$OUTDIR/ca.key.pem"
CERT="$OUTDIR/proxy.cert.pem"
KEY="$OUTDIR/proxy.key.pem"

# 是 IP 还是域名：IP 用 IP: 前缀，域名用 DNS:
case "$TARGET" in
    *[!0-9.]*|"") SAN="DNS:$TARGET"; IS_IP=0 ;;
    *)            SAN="IP:$TARGET";  IS_IP=1 ;;
esac

if [ "$SELF_SIGNED" = "1" ]; then
    # ---------- 兼容模式：单张自签证书（CA:TRUE，客户端导入它本身） ----------
    if [ -e "$KEY" ] || [ -e "$CERT" ]; then
        echo "[错误] 已存在 $KEY 或 $CERT，先备份/删除再重新生成" >&2
        exit 1
    fi
    echo "[*] 生成自签证书（兼容模式）：SAN=$SAN（有效期 $DAYS 天）"
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
    IMPORT_FILE="$CERT"
    echo "[!] 注意：兼容模式下客户端导入的是服务器正在用的那张证书，"
    echo "    其私钥一旦泄露可被用来伪造任意站点证书——建议改用默认的 CA 模式。"
else
    # ---------- 默认：CA + 叶证书 ----------
    for f in "$CA_CERT" "$CA_KEY" "$CERT" "$KEY"; do
        if [ -e "$f" ]; then
            echo "[错误] 已存在 $f，先备份/删除再重新生成" >&2
            exit 1
        fi
    done

    umask 077
    echo "[*] 1/3 生成自建 CA（有效期 10 年）"
    NC_EXT=""
    if [ "$NAME_CONSTRAINTS" = "1" ]; then
        if [ "$IS_IP" = "1" ]; then
            NC_EXT="-addext nameConstraints=critical,permitted;IP:$TARGET/255.255.255.255"
        else
            NC_EXT="-addext nameConstraints=critical,permitted;DNS:$TARGET"
        fi
        echo "    已启用名称约束：只允许为该目标签发证书"
    fi
    # shellcheck disable=SC2086
    openssl req -x509 -newkey rsa:4096 -nodes -days 3650 \
        -keyout "$CA_KEY" -out "$CA_CERT" \
        -subj "/CN=ScholarVPN CA" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        $NC_EXT 2>/dev/null
    chmod 600 "$CA_KEY"
    chmod 644 "$CA_CERT"

    echo "[*] 2/3 生成叶证书密钥与 CSR"
    openssl req -newkey rsa:2048 -nodes \
        -keyout "$KEY" -out "$OUTDIR/proxy.csr.pem" \
        -subj "/CN=ScholarVPN" 2>/dev/null
    chmod 600 "$KEY"

    echo "[*] 3/3 用 CA 签发叶证书（有效期 $DAYS 天）"
    EXT_FILE="$OUTDIR/proxy.ext.cnf"
    cat > "$EXT_FILE" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$SAN
EOF
    openssl x509 -req -in "$OUTDIR/proxy.csr.pem" \
        -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
        -days "$DAYS" -sha256 -extfile "$EXT_FILE" \
        -out "$CERT" 2>/dev/null
    chmod 644 "$CERT"
    rm -f "$OUTDIR/proxy.csr.pem" "$EXT_FILE" "$OUTDIR/ca.srl"
    IMPORT_FILE="$CA_CERT"

    # 链校验自检（含目标名匹配）
    echo
    echo "[*] 链校验自检："
    if [ "$IS_IP" = "1" ]; then
        openssl verify -CAfile "$CA_CERT" -verify_ip "$TARGET" "$CERT" | sed 's/^/    /' || true
    else
        openssl verify -CAfile "$CA_CERT" -verify_hostname "$TARGET" "$CERT" | sed 's/^/    /' || true
    fi
fi

echo
echo "[*] 证书信息："
openssl x509 -in "$CERT" -noout -subject -issuer -dates -ext subjectAltName | sed 's/^/    /'

cat <<EOF

============================================================
下一步：

1) 启动服务端（HTTPS 代理入口，需配认证；密码建议放文件）：
   echo '你的强密码' > $OUTDIR/proxy.pass && chmod 600 $OUTDIR/proxy.pass
   sudo ./build/vpn_server -a 10.8.0.1 -p 51820 \\
        --https-proxy-port 8443 \\
        --https-proxy-cert $CERT \\
        --https-proxy-key  $KEY \\
        --proxy-user <用户名> --proxy-pass-file $OUTDIR/proxy.pass

   或 start.sh 环境变量方式（推荐装成服务）：
   sudo HTTPS_PROXY_PORT=8443 HTTPS_CERT=$CERT HTTPS_KEY=$KEY \\
        PROXY_USER=<用户名> PROXY_PASS_FILE=$OUTDIR/proxy.pass ./start.sh install

2) 防火墙/云安全组放行 TCP 8443（start.sh 会自动放行本机防火墙）

3) 每台客户端导入【$IMPORT_FILE】（只传这一个文件，切勿传任何 *.key.pem）：
   Windows : certutil -addstore -f Root $(basename "$IMPORT_FILE")  （管理员；之后完全重启浏览器）
   macOS   : sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $(basename "$IMPORT_FILE")
   Linux   : sudo cp $(basename "$IMPORT_FILE") /usr/local/share/ca-certificates/scholargvpn.crt && sudo update-ca-certificates

4) 浏览器扩展（browser-extension/）里填：
   代理协议 = HTTPS 代理（TLS 加密，推荐）
   服务器地址 = $TARGET
   端口       = 8443
   用户名/密码 = 与服务端 --proxy-user/--proxy-pass-file 一致

5) 自检（任意客户端机器）：
   curl --proxy-cacert $(basename "$IMPORT_FILE") -x https://<用户名>:<密码>@$TARGET:8443 https://api.ipify.org
   返回服务器 IP 即为成功（不加 --proxy-insecure 也能过 = 证书链被正确信任）。

6) 续期（叶证书到期前，CA 不变，客户端无需重新导入）：
   重新执行本脚本到新目录生成叶证书，或：
   openssl x509 -req -in <新CSR> -CA ca.cert.pem -CAkey ca.key.pem -days 825 -sha256 -extfile <ext> -out proxy.cert.pem

安全提示：
- ca.key.pem 是"能签发该目标证书"的最高权限私钥：签完可离线保存或删除；
  启用 --name-constraints 时即使泄露也只能签该目标名。
- 切勿把任何 *.key.pem 传到客户端。
============================================================
EOF
