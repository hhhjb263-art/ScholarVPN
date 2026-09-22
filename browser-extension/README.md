# ScholarVPN 浏览器代理（浏览器插件）

**只在浏览器里生效**的代理客户端：不安装系统级 VPN、不改系统路由、不影响其他应用。
启用后浏览器流量经 ScholarVPN 服务端出口，可与整机版客户端并存。

> 与服务端主隧道（UDP/TCP + 三阶段认证 + AES-GCM）是**两个独立入口**：
> 主隧道保护整机流量；本插件只代理浏览器流量。

## 加密方式（扩展内可切换）

| 协议 | 链路加密 | 服务端参数 | 说明 |
| --- | --- | --- | --- |
| **HTTPS 代理** | ✅ TLS（浏览器 ↔ 代理全程） | `--https-proxy-port` | **推荐**。浏览器校验服务器证书 |
| SOCKS5 | ❌ 明文（凭据也是明文） | `--socks5-port` | 最快；仅内网/可信链路或前置 SSH/stunnel |
| HTTP 代理 | ❌ 明文 | `--http-proxy-port` | 仅内网，或前面已有 TLS/SSH 隧道时用 |

三种方式都需要在服务端设置 `--proxy-user/--proxy-pass`（公网暴露必须）。
HTTPS 代理的加密范围：浏览器 ↔ 代理之间；HTTPS 网站内容本来就由网站 TLS 保护
（SOCKS5/HTTP 方式下网站内容同样安全，但凭据、目标域名、HTTP 站点内容会暴露）。

> 本项目仅限学习、研究和教育用途，请遵守所在国家/地区法律法规（见仓库根 README 的法律声明）。

## 一、服务端准备（Linux）

三个入口默认全部关闭，需要时显式开启（可与主隧道同机运行）：

```bash
# 推荐：HTTPS 代理（TLS 加密）+ Basic 认证
sudo ./build/vpn_server -a 10.8.0.1 -p 51820 \
     --https-proxy-port 8443 \
     --https-proxy-cert /etc/letsencrypt/live/example.com/fullchain.pem \
     --https-proxy-key  /etc/letsencrypt/live/example.com/privkey.pem \
     --proxy-user alice --proxy-pass '换成强密码'

# 或者：SOCKS5（明文，最快）
sudo ./build/vpn_server -a 10.8.0.1 -p 51820 \
     --socks5-port 1080 --proxy-user alice --proxy-pass '换成强密码'
```

| 参数 | 说明 |
| --- | --- |
| `--https-proxy-port <n>` | HTTPS 代理（TLS 加密），**推荐** |
| `--https-proxy-cert <p>` | TLS 证书链 PEM（Let's Encrypt 的 `fullchain.pem` 等） |
| `--https-proxy-key <p>` | TLS 私钥 PEM |
| `--socks5-port <n>` | SOCKS5 端口（明文） |
| `--http-proxy-port <n>` | HTTP CONNECT 端口（明文；内网或前置 stunnel 用） |
| `--proxy-user <u>` | 三个入口共用的用户名/密码认证（公网强烈建议） |
| `--proxy-pass <p>` | 与 `--proxy-user` 配套（`--socks5-user/pass` 为历史别名） |
| `--proxy-allow-private` | 允许代理连接服务端内网/回环目标（**默认禁止**，仅内网自用开启） |

也可以走环境变量（`start.sh` 会自动放行防火墙端口并写入 systemd 环境文件）：

```bash
sudo SOCKS5_PORT=1080 HTTPS_PROXY_PORT=8443 \
     HTTPS_CERT=/path/fullchain.pem HTTPS_KEY=/path/privkey.pem \
     PROXY_USER=alice PROXY_PASS='强密码' ./start.sh -d
```

### 证书要点（HTTPS 代理）

浏览器会校验代理证书，二选一：

1. **有域名**：用 Let's Encrypt 最省事，例如
   `certbot certonly --standalone -d vpn.example.com`，证书在
   `/etc/letsencrypt/live/<域名>/`（用 `fullchain.pem` + `privkey.pem`）。
2. **自签**：必须把证书**导入操作系统信任存储**，否则 Chrome 报
   `ERR_PROXY_CERTIFICATE_INVALID`。生成与导入示例：

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
  -keyout key.pem -out cert.pem -subj "/CN=vpn.example.com" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "subjectAltName=DNS:vpn.example.com,IP:1.2.3.4"
```

Windows 端导入：`certmgr.msc` → 受信任的根证书颁发机构 → 导入 `cert.pem`
（或 `certutil -addstore -f Root cert.pem`），重启浏览器生效。

### 其他要点

- 监听地址跟随 `--listen`（默认 `0.0.0.0`）；出口为**服务端主机直连**目标（不经 TUN）；
- 每入口并发上限 256，空闲 5 分钟回收；目标连接失败回 HTTP 502 / SOCKS5 错误码；
- **目标 ACL（默认开启）**：代理默认拒绝访问"服务端内网"目标——回环 `127.0.0.1`、
  私网 `10/8`、`172.16/12`、`192.168/16`、链路本地、CGNAT、组播/保留段，以及
  IPv6 的 `::1`/ULA/链路本地等。这样浏览器侧无法借代理访问服务端本机管理服务、
  内网主机，或 TUN 网段（`10.8.0.x` = 其他 VPN 客户端的虚拟 IP）。
  被拒时 SOCKS5 回 `0x02`（not allowed by ruleset）、HTTP/HTTPS 回 `403`；
  **内网自用**需要放行时加 `--proxy-allow-private`（或 `PROXY_ALLOW_PRIVATE=1`）；
- 明文入口（SOCKS5/HTTP）不加密且凭据可被嗅探重放：公网务必配认证 + 防火墙来源限制，
  或只绑内网（`--listen 127.0.0.1`）配合 SSH 隧道；
- 服务端日志会记录目标 `host:port`（运维可审计，注意隐私留存策略）。

## 二、浏览器安装（Chrome / Edge，MV3）

1. 打开 `chrome://extensions`（Edge 为 `edge://extensions`）；
2. 打开右上角 **开发者模式**；
3. 点 **加载已解压的扩展程序**，选择本目录（`browser-extension/`）；
4. 工具栏出现图标（盾形），点开即可配置。

> Firefox 需要额外的 MV3 适配（`browser_specific_settings`），当前版本未提供。

## 三、使用

1. 选 **代理协议**：`HTTPS 代理（TLS 加密，推荐）` / `SOCKS5` / `HTTP 代理`，
   填服务器地址与**对应入口的端口**；
2. 服务端配了认证就填 **用户名/密码**（三个入口共用同一份凭据）；
3. 选**代理范围**：
   - `全部流量走代理`：下方列表里的域名**直连**（例如内网/本地服务）；
   - `只有下方列表的域名走代理`：列表外的直连；
   - 列表支持 `example.com`（含子域）与 `*.example.com` 两种写法，等价；
4. 右上角开关 **启用**；图标角标 `ON` 表示代理已生效；
5. 「检测出口 IP」会经当前代理请求 `api.ipify.org`，显示实际出口地址。

改任意一项即自动保存并生效；关闭开关立即恢复直连。

## 四、目录结构

```
browser-extension/
├── manifest.json      # MV3 清单（proxy / storage / webRequest 权限）
├── background.js      # service worker：chrome.proxy 落配置 + 代理认证回调
├── popup.html/.css/.js# 弹窗界面（协议、服务器、认证、范围、域名列表）
├── icons/             # 16/48/128 图标（make_icons.py 生成）
├── make_icons.py      # 图标生成脚本（无需 Pillow）
└── tests/verify.mjs   # Node 测试：三种协议的代理配置/PAC/认证回调
```

服务端三个入口的运行期自测（Windows 开发机即可跑，含真实 TLS 握手用例）见
[../server/tests/README.md](../server/tests/README.md)。

## 五、自测

```bash
node tests/verify.mjs     # 全部通过会打印「全部通过」
python make_icons.py      # 需要重新生成图标时
```

测试覆盖：清单合法性、未启用即清除代理、三种协议各写入正确的
`fixed_servers(socks5|http|https)` 配置、仅列表模式 PAC 行为
（精确/子域/大小写/后缀边界）、缺省协议按 https（TLS）处理、认证回调回填凭据。

## 六、故障排查

| 现象 | 检查 |
| --- | --- |
| 开关打开但网页打不开 | 服务端是否开了对应端口；云安全组/防火墙是否放行 |
| 一直弹认证框 | 用户名/密码是否与服务端 `--proxy-user/--proxy-pass` 一致 |
| `ERR_PROXY_CERTIFICATE_INVALID` | 证书未被系统信任：换 Let's Encrypt 证书，或导入自签证书到受信任根存储 |
| HTTPS 端口连不上 | 服务端日志 `[HTTPS] … TLS 握手失败: <OpenSSL 原因>` 会给出具体错误 |
| 访问内网/本机地址被拒（403 / SOCKS5 0x02） | 这是默认目标 ACL 在起作用；内网自用场景服务端加 `--proxy-allow-private` |
| `chrome.proxy` 报错 | 扩展页点「重新加载」，在 `chrome://extensions` 查看 service worker 报错 |
| 只有部分站点异常 | 检查代理范围与域名列表；列表项不要带 `http://` 或路径 |
