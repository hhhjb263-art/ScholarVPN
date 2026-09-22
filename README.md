
---

## ⚠️ 法律声明（Legal Notice）

**本项目仅限学习、研究和教育用途**，用于理解 VPN / 隧道 / 加密协议的工作原理。**禁止**以任何形式将本项目用于以下用途：

- ❌ **禁止私自搭建、运营或提供 VPN 服务**，包括但不限于：商业运营、对外提供付费/免费 VPN 服务、为他人转发流量、搭建跨境代理通道等；
- ❌ 禁止用于**绕过网络监管、突破防火墙、非法访问境外网络**或规避任何国家/地区的法律法规；
- ❌ 禁止用于任何非法目的，包括但不限于：网络攻击、数据窃取、侵犯他人隐私、传播违法信息等。

**合规责任声明：**

1. 使用者必须遵守**所在国家/地区的全部法律法规**。
2. 在中国境内，**私自搭建/运营 VPN 服务**可能违反《中华人民共和国计算机信息网络国际联网管理暂行规定》等法律法规，使用者需自行承担全部法律责任。
3. 项目作者与维护者**不对任何使用者的行为及其后果承担责任**；下载、编译、运行或分发本项目即视为接受本声明。

**合规使用示例（仅供学习）：**

- ✅ 用于课堂教学、学术研究与代码阅读。

> 若你无法确保使用方式合法合规，请勿下载、编译或运行本项目。

---

## 项目介绍

用于学习 VPN / 隧道 / 加密协议原理的完整示例，包含四个部分：

| 组成部分 | 说明 |
| --- | --- |
| **Linux 服务端** | 多用户并发（自动分配虚拟 IP、同身份互踢、失联自动清理），一键部署脚本 |
| **Windows 客户端** | Qt 图形界面，虚拟网卡接管本机流量，实时速率曲线，多服务器管理 |
| **Android 客户端** | VpnService 客户端（Kotlin），功能与 Windows 端一致 |
| **浏览器插件** | Chrome/Edge 扩展，**只在浏览器里生效**：不改系统网络、不装系统组件 |

整机客户端走自研加密隧道（UDP/TCP 双传输、三阶段身份认证、AES-256-GCM 认证加密、
前向安全会话密钥、心跳保活与自动重连）；浏览器插件则把浏览器流量指向服务端代理入口，
可选 **HTTPS 代理（TLS 加密，推荐）** / SOCKS5 / HTTP 三种方式。

## 快速开始

### 服务端（Linux）

依赖：CMake ≥ 3.16、C++17 编译器、OpenSSL、pthread。

```bash
cd server
cmake -S . -B build && cmake --build build

# 一键部署（自动配置转发/NAT/防火墙，推荐装成系统服务）
sudo ./start.sh install
```

其他子命令：`./start.sh`（前台调试）、`-d`（后台守护，异常自动重启）、`status`、`logs`、
`doctor`（环境诊断）、`uninstall`。

首次启动会生成服务器身份密钥 `keys/server_sig.key` / `.pub`：把 `.pub` 内容填入客户端
（或在客户端服务器条目里粘贴），客户端据此验证服务器身份、防中间人。

### Windows 客户端

环境：Visual Studio 2022 + Qt 6.9.1（msvc2022_64；Qt 装在别处需改 `VPN_.vcxproj` 路径）。
用 VS 打开 `VPN_.sln` 生成 x64 配置即可，OpenSSL 与 Wintun 已内置，构建后自动拷贝运行所需 DLL。

### Android 客户端

源码在 `android/`，用 Gradle 构建：`cd android && ./gradlew assembleRelease`，产物在
`android/app/build/outputs/apk/release/app-release.apk`（仓库只提交代码，不存放 APK 等二进制）。

### 浏览器插件

把 `browser-extension/` 目录在 Chrome/Edge 里「加载已解压的扩展程序」加载即可，**无需编译**。
服务端需先开启对应入口（`--https-proxy-port` 等），证书与配置步骤见
[browser-extension/README.md](browser-extension/README.md)。

## 使用

### 首次注册

1. 客户端首次运行会生成身份密钥，把 `%APPDATA%\ScholarVPN\client.id.pub` 交给服务器管理员；
2. 管理员生成一次性注册令牌：`sudo ./build/vpn_server --gen-token 5`（输出形如
   `register_token: <64 位十六进制>`）；
3. 客户端「+ 添加服务器」填 IP / 端口 / ClientID / 令牌，点「连接」即完成注册；
   令牌一次性使用，注册成功后客户端自动清空，之后即为登录模式。

### 日常使用

- 主界面卡片显示服务器与连接状态，点「连接」/「断开」；断线自动重连，无需手动干预；
- 卡片下方为实时速率曲线；底部「Switch Server」管理多台服务器，点击卡片即切换；
- 「编辑」可修改名称 / IP / ClientID / 令牌 / 公钥，也可删除服务器。

### 浏览器插件

1. 扩展内选择协议（`HTTPS 代理` = TLS 加密，推荐）、填服务器地址、端口、账号密码；
2. 打开开关，图标角标显示 `ON` 即生效；
3. 代理范围可选「全部流量走代理（域名可例外）」或「仅代理指定域名」。

## 配置

### 客户端

配置由图形界面自动维护（`%APPDATA%\ScholarVPN\config.ini`），也可手动编辑：

```ini
[Server]
Count=1

[Server1]
Name=公司服务器            # 显示名（留空自动命名）
ServerIP=1.2.3.4
ServerPort=51820
Transport=0                # 0=UDP（默认） 1=TCP（运营商丢 UDP 时用）
ClientID=user1             # 该服务器上的身份标识
RegisterToken=             # 首次注册填令牌；注册成功后留空即登录模式
ServerPubKey=              # 可选：该服务器公钥；留空用客户端内置公钥

[Network]
VirtualIP=                 # 留空 = 自动采用服务端分配的虚拟 IP（推荐）
VirtualPrefix=24
DNS=8.8.8.8,1.1.1.1
MTU=1400
Metric=5
```

### 服务端

常用参数：

| 参数 | 说明 |
| --- | --- |
| `-l/--listen`、`-p/--port` | 监听地址与端口（默认 `0.0.0.0:51820`） |
| `-a/--addr`、`--prefix`、`--mtu` | 隧道内网地址 / 网段前缀 / MTU（默认 `10.8.0.1` / 24 / 1400） |
| `--max-clients` | 最大并发客户端数（默认 64，自动分配虚拟 IP） |
| `--transport both\|udp\|tcp` | 传输开关（默认 both：同端口双栈） |
| `-g/--gen-token [n]` | 生成 n 个一次性注册令牌后退出 |
| `--quiet` | 精简日志（公网服务器推荐） |
| `--https-proxy-port` / `--socks5-port` / `--http-proxy-port` | 浏览器插件的三个代理入口（默认全关） |
| `--proxy-user` / `--proxy-pass-file` | 代理入口的账号与密码（密码放 0600 文件更安全） |

`start.sh` 支持用环境变量覆盖这些配置（如 `VPN_PORT`、`MAX_CLIENTS`、`HTTPS_PROXY_PORT`、
`PROXY_USER`、`PROXY_PASS_FILE` 等），`install` 会把当前配置固化到 `/etc/default/vpn-server`，
之后编辑该文件再 `systemctl restart vpn-server` 即可。

## 常见问题

- **客户端连不上**：确认服务端在运行、端口在云安全组与防火墙都已放行；运营商丢 UDP 时可改用
  TCP 传输（`Transport=1`，服务端需 `--transport both|tcp`）。
- **浏览器插件报证书不受信任**：把服务端生成的 `ca.cert.pem` 导入系统"受信任的根证书颁发机构"，
  然后**完全退出并重开浏览器**。
- **日志在哪看**：前台运行看终端输出；`./start.sh -d` 写入 `logs/vpn-server-YYYYMMDD.log`；
  systemd 模式用 `journalctl -u vpn-server -f`。
- **多客户端共享服务端出口**：需要内核转发 + NAT，`start.sh` 会自动配置。

## 待完善

- **智能分流**：按规则分流流量（如国内直连、国外走隧道），避免全局代理；
- **日志窗口与流量统计**：界面内查看连接日志、累计流量统计与限速；
- **系统托盘**：最小化到托盘、开机自启；
- **性能**：客户端收发后续可引入 I/O 完成端口（IOCP）模型，提升高并发场景吞吐。

## 许可证

MIT License（见 `LICENSE`）。第三方组件许可见 `docs/LICENSE.txt` 与 `third_party/` 下对应文件
（注意 Wintun 源码为 GPLv2、预编译二进制使用单独许可）。

---
