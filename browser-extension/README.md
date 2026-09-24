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
| `--proxy-pass-file <p>` | 从 0600 文件读密码（**推荐**：密码不进 `ps`/history/环境文件） |
| `--proxy-allow-private` | 允许代理连接服务端内网/回环目标（默认禁止，仅内网自用开启） |
| `--proxy-allow-noauth` | 允许无认证代理监听非回环地址（默认拒绝，防误开开放代理） |

也可以走环境变量（`start.sh` 会自动放行防火墙端口并写入 systemd 环境文件）：

```bash
sudo SOCKS5_PORT=1080 HTTPS_PROXY_PORT=8443 \
     HTTPS_CERT=/path/fullchain.pem HTTPS_KEY=/path/privkey.pem \
     PROXY_USER=alice PROXY_PASS='强密码' ./start.sh -d
```

### 证书要点（HTTPS 代理）

浏览器会校验代理证书，两种方式：

1. **有域名**：用 Let's Encrypt 最省事，例如
   `certbot certonly --standalone -d vpn.example.com`，证书在
   `/etc/letsencrypt/live/<域名>/`（用 `fullchain.pem` + `privkey.pem`）。
2. **没有域名（只有 IP）**：用仓库脚本生成 **CA + 叶证书**（推荐）：

```bash
cd server
./gen-self-signed-cert.sh 1.2.3.4                          # ca.cert.pem + proxy.cert.pem/key.pem
./gen-self-signed-cert.sh vpn.example.com /etc/scholargvpn --name-constraints
```

脚本默认生成 **CA + 叶证书**（服务器只放叶证书，客户端导入 CA），也可用
`--self-signed` 生成单张自签证书。

**客户端导入哪一张，取决于服务端证书是怎么生成的**（两张模式产出的文件不同）：

| 生成方式 | 服务端产物 | **客户端要导入** |
| --- | --- | --- |
| **CA + 叶证书**（`./gen-self-signed-cert.sh <IP>` 默认） | `ca.cert.pem` `ca.key.pem` `proxy.cert.pem` `proxy.key.pem` | **`ca.cert.pem`**（不是服务器在用的 `proxy.cert.pem`） |
| **单张自签**（`./gen-self-signed-cert.sh <IP> --self-signed`） | 只有 `proxy.cert.pem` `proxy.key.pem`，**没有 ca.cert.pem** | **`proxy.cert.pem` 本身**（证书即根） |

判断方法：看服务器 `keys/` 目录里有没有 `ca.cert.pem`。没有就是自签模式。

```powershell
certutil -addstore -f Root ca.cert.pem      # CA 模式（管理员；导入后完全重启浏览器）
certutil -addstore -f Root proxy.cert.pem   # 自签模式
```

> 也可以直接用仓库里的 `导入证书(管理员运行).bat`：它会**自动识别**同目录下是
> `ca.cert.pem` 还是 `proxy.cert.pem` 并导入正确的那个。

脚本会做链校验自检（`openssl verify -verify_ip …`）并打印续期方法：叶证书
到期只需重新签发叶证书，CA 不变、客户端**无需重新导入**。此前导入过旧自签
证书的，建议从信任存储删除（`certutil -delstore Root ScholarVPN`）。

### 其他要点

- 监听地址跟随 `--listen`（默认 `0.0.0.0`）；出口为服务端主机直连（不经 TUN）；
- 目标连接失败时返回明确错误（HTTP 502 / SOCKS5 错误码）；
- **目标 ACL（默认开启）**：代理默认拒绝访问"服务端内网"目标——回环 `127.0.0.1`、
  私网 `10/8`、`172.16/12`、`192.168/16`、链路本地、CGNAT、组播/保留段，以及
  IPv6 的 `::1`/ULA/链路本地等。这样浏览器侧无法借代理访问服务端本机管理服务、
  内网主机，或 TUN 网段（`10.8.0.x` = 其他 VPN 客户端的虚拟 IP）。
  被拒时 SOCKS5 回 `0x02`（not allowed by ruleset）、HTTP/HTTPS 回 `403`；
  **内网自用**需要放行时加 `--proxy-allow-private`（或 `PROXY_ALLOW_PRIVATE=1`）；
- 明文入口（SOCKS5/HTTP）不加密且凭据可被嗅探重放：公网务必配认证 + 防火墙来源限制，
  或只绑内网（`--listen 127.0.0.1`）配合 SSH 隧道；
- 密码连续猜错会被临时拒绝；证书过期服务端会拒绝启动并给出告警；
- 密码建议放 0600 文件（`--proxy-pass-file`）而不是写在命令行参数里；
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
browser-extension/   扩展本体（manifest / background / popup / 图标 / 测试）
```
服务端三个入口的说明见仓库根 README 与 `server/`。

## 五、无人值守配置（config.json，可选）

**默认不启动代理**：装好后开关是关的，需要时在弹窗里手动打开（手动设置会保留，
重启浏览器不丢）。若不想每次手动填服务器/账号，可在扩展目录放一份 `config.json`
预填这些字段（含密码，已在 `.gitignore` 中，不会提交；模板见 `config.json.example`）：

```json
{
  "applyOnStartup": true,
  "enabled": true,
  "protocol": "https",
  "host": "1.2.3.4",
  "port": 8443,
  "user": "alice",
  "pass": "你的代理密码",
  "mode": "global",
  "list": []
}
```

| 字段 | 说明 |
| --- | --- |
| `applyOnStartup` | `false`（默认）= 启动时不按本文件强制开关，**完全由弹窗手动控制**；`true` = 每次启动都按这里的值强制应用（无人值守部署，或"每次启动强制关闭"：`true` + `enabled: false`） |
| `applyOnce` | `true` = 仅在从未保存过设置时应用一次 |
| 其余字段 | 与弹窗一一对应：`protocol` = `https`/`socks5`/`http`；`mode` = `global`/`whitelist`；`list` = 域名数组 |

生效方式：改完 `config.json` 后**重启浏览器**（或到 `chrome://extensions`/`edge://extensions`
点该扩展的「重新加载」）。

弹窗状态行会显示**实际生效的代理**；检测失败时会给出具体错误码与处置建议。

## 六、分发（打包给别人用）

```bash
python package.py            # 产物: ../dist/ScholarVPN-browser-extension-v<版本>.zip
```

zip 内含：扩展本体 + [安装说明.md](安装说明.md)（给使用者的四步图文说明）+
`config.json.example` + `导入证书(管理员运行).bat`（一键导入服务器证书）。
产物在 `dist/`（已在 `.gitignore` 中：仓库只提交代码，zip 等二进制不入库，请自行打包分发）。
**打包脚本会显式排除 `config.json`**（含代理密码，绝不入包），并做安全自检。

分发给别人时，除了 zip 还要一并给出：**服务器地址/端口、代理账号密码**；
若服务器用的是自签证书，再附上 `ca.cert.pem`（对方跑一次批处理即可，之后完全重启浏览器）。
若服务器用正规证书（如 Let's Encrypt），则无需任何证书操作。

更新版本：改 `manifest.json` 的 `version` → 重跑 `package.py` → 对方用新文件夹替换后，
在扩展页点「重新加载」即可（配置与证书都不用重做）。

## 七、故障排查

| 现象 | 检查 |
| --- | --- |
| 开关打开但网页打不开 | 服务端是否开了对应端口；云安全组/防火墙是否放行 |
| 一直弹认证框 | 用户名/密码是否与服务端 `--proxy-user/--proxy-pass` 一致 |
| `ERR_PROXY_CERTIFICATE_INVALID` | 证书未被系统信任：换 Let's Encrypt 证书，或导入自签证书到受信任根存储 |
| HTTPS 端口连不上 | 服务端日志 `[HTTPS] … TLS 握手失败: <OpenSSL 原因>` 会给出具体错误 |
| 访问内网/本机地址被拒（403 / SOCKS5 0x02） | 这是默认目标 ACL 在起作用；内网自用场景服务端加 `--proxy-allow-private` |
| `chrome.proxy` 报错 | 扩展页点「重新加载」，在 `chrome://extensions` 查看 service worker 报错 |
| 只有部分站点异常 | 检查代理范围与域名列表；列表项不要带 `http://` 或路径 |
