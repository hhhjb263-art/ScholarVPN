# ScholarVPN

> ⚠️ **仅供学习研究使用** —— 请先阅读下方的「法律声明」，确认你的使用方式合法合规。

ScholarVPN 是一个**学习实验性质**的项目，用于理解网络通信、加密协议与 VPN 的工作原理。包含 **Windows 客户端**（Wintun 虚拟网卡 + UDP 隧道）与 **Linux 服务端**（TUN 虚拟网卡 + UDP 隧道）。隧道使用自研三阶段身份认证协议：Ed25519 签名防中间人 + 临时 X25519 前向安全密钥交换 + HKDF 密钥派生 + AES-256-GCM 认证加密，客户端/服务器身份均需注册准入。

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

- ✅ 在**自有、可控的实验环境**（本机虚拟机 / 实验室局域网）中学习 TUN/Wintun 虚拟网卡与 UDP 隧道原理；
- ✅ 研究加密协议（Ed25519 / X25519 / HKDF / AES-256-GCM）与身份认证流程的实现细节；
- ✅ 用于课堂教学、学术研究与代码阅读。

> 若你无法确保使用方式合法合规，请勿下载、编译或运行本项目。

---

## 项目介绍

### 架构

客户端与服务端通过 UDP 建立隧道：客户端创建 Wintun 虚拟网卡，把本机流量封装进自定义 UDP 报文发往服务器；服务器从 TUN 网卡转发到真实网络，回程流量再反向封装回客户端。两端使用同一套自研隧道协议（自定义报文头 + 三阶段身份认证 + 心跳保活），加密层基于 OpenSSL 标准算法。

### 目录结构

```
ScholarVPN/
├── src/                       客户端源码
│   ├── main.cpp               入口：读取 config.ini，桥接 TUN <-> UDP
│   ├── tun.cpp                 Wintun 虚拟网卡读写
│   ├── UDP.cpp                 UDP 隧道（三阶段身份认证、心跳、收发线程）
│   ├── Crypt.cpp               Ed25519 + 临时X25519 + HKDF-SHA256 + AES-256-GCM 加密
│   ├── AdapterConfig.cpp       网卡 IP / DNS / MTU / 路由度量配置
│   ├── route_manager.cpp       路由管理（服务器绕过路由 + 默认路由）
│   ├── reconnect_manager.cpp   断线自动重连
│   └── tunnel_protoco.h        隧道协议头定义
├── server/                    Linux 服务端（CMake 工程，各模块功能如下）
│   ├── main.cpp               服务端入口（CLI 解析 + --gen-token）
│   ├── Buffer/                数据缓冲（PacketBuffer / QueueBuffer）与隧道协议头
│   ├── UDP/                   传输层：Session 多用户会话模型 + 三阶段认证 / 心跳 / 收发线程
│   │   └── Session.h          会话模型（每个客户端一个 Session，含认证状态与密钥）
│   ├── tun/                   TUN 虚拟网卡读写
│   ├── LinuxAdapter/          网卡 IP / MTU / 路由配置
│   ├── core/                  VpnCore 转发层（TUN ↔ UDP 桥接，认证通过前禁止转发）
│   ├── Crypt/                 加密层（Ed25519 / 临时 X25519 / HKDF / AES-256-GCM）
│   ├── keys/                  身份密钥与客户端准入数据库（不入库，说明见 keys/README.txt）
│   └── start.sh / vpn-server.service   部署脚本与 systemd 服务模板
├── include/                    公共头文件
├── third_party/                OpenSSL 3.5.6、Wintun 0.14.1
├── Config.cpp / Config.h       客户端 INI 配置读写
├── docs/                       项目文档
└── x64/                        Visual Studio 构建输出
```

### 隧道协议与加密（概述）

- 客户端与服务端通过自研 **UDP 隧道协议**通信（自定义报文头，含魔数、版本、类型、序号），具体线格式属于实现细节，不在此展开；
- **三阶段身份认证**：包含防中间人校验（服务器身份签名验证）与客户端身份准入（注册/登录），**身份未验证通过前服务端禁止转发任何流量**；
- **加密**：基于 OpenSSL 标准算法，会话密钥支持前向安全，数据面使用认证加密（AES-256-GCM）；
- **心跳保活**：认证通过后周期发送心跳，对端失联时自动重连；
- **密钥体系**：持久身份密钥为 Ed25519（服务器公钥内置于客户端；客户端私钥经 Windows DPAPI 加密存储，磁盘不落明文）。

### 多用户支持（服务端）

服务端基于 **Session（会话）模型** 支持多客户端并发：

- 每个客户端（按 UDP 源 IP+端口 识别）对应一个独立 `Session`，认证状态、会话密钥、发送队列与心跳完全隔离；
- **虚拟 IP 自动分配**：客户端认证通过后，服务端在 TUN 网段内自动分配唯一地址并通告给客户端，客户端连接成功后自动采用；
- **同身份互踢**：同一 `ClientID` 重复登录时旧的在线会话自动下线；
- **会话上限与清理**：`--max-clients` 限制并发数（默认 64），未认证会话与失联会话按超时自动清理；
- TUN 下行按**目的虚拟 IP** 查表转发到对应客户端。

> **多用户部署（NAT 模式）**：多客户端共享服务端出口时，开启内核转发 + NAT（请仅在自有实验环境中使用）：
>
> ```bash
> # 1. 开启 IPv4 转发（持久化写入 /etc/sysctl.conf）
> sysctl -w net.ipv4.ip_forward=1
> # 2. NAT：客户端网段访问外网（按实际外网网卡调整 eth0）
> iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
> # 3. 启动服务端（默认即多用户，自动分配 10.8.0.2、10.8.0.3 ...）
> sudo ./build/vpn_server -a 10.8.0.1 -p 51820 --max-clients 100
> ```
>
> `start.sh` 可通过环境变量 `MAX_CLIENTS=100` 传入 `--max-clients`。

### 配置

客户端运行参数通过 INI 文件配置，首次运行自动生成：

- 路径：`%APPDATA%\ScholarVPN\config.ini`
- 默认服务器：`    请自行填写      `（Debug 构建默认 `192.168.1.12`）

```ini
[Server]
ServerIP= 请自行填写          # Release 构建使用（必填）
DebugServerIP=192.168.1.12   # 仅 Debug 构建使用：本地测试服务器，Release 构建忽略
ServerPort=51820

[Network]
VirtualIP=                   # 可选：留空 = 自动采用服务端分配的虚拟 IP（推荐）
VirtualPrefix=24
DNS=8.8.8.8,1.1.1.1
MTU=1400
Metric=5

[Identity]
ClientID=user1              # 客户端标识（登录/注册时使用）
RegisterToken=              # 首次注册填管理员下发的令牌，注册成功后清空即登录模式
```

> 服务器选择规则：**Debug 构建**按 `DebugServerIP` → `ServerIP` → 默认 `192.168.1.12` 的顺序取服务器；**Release 构建**只用 `ServerIP`，完全忽略 `DebugServerIP`。Debug 构建同样读取本配置文件（无 ini 时才用默认值）。

## 项目依赖

### 客户端（Windows）

| 依赖 | 说明 |
|------|------|
| Visual Studio 2022（v143）+ Windows SDK 10.0 | 构建环境，C++17 |
| OpenSSL 3.5.6 | 已内置 `third_party/openssl`；链接 `libcrypto.lib`，运行需要 `libcrypto-3-x64.dll` |
| Wintun 0.14.1 | 已内置 `third_party/wintun-0.14.1`；运行需要 `wintun.dll` |
| Windows API | WinSock2（ws2_32）、IP Helper（iphlpapi）等 |

### 服务端（Linux）

| 依赖 | 说明 |
|------|------|
| Linux 内核头文件 | `linux/if_tun.h`、`linux/route.h` 等，仅支持 Linux |
| CMake >= 3.16 + C++17 编译器 | GCC / Clang 均可 |
| Threads（pthread） | 收发线程、重连状态机 |
| OpenSSL | X25519 / HKDF / AES-256-GCM（`OpenSSL::Crypto`） |

> 许可注意：Wintun 源码为 GPLv2，预编译二进制使用单独许可（见 `third_party/wintun-0.14.1/prebuilt-binaries-license.txt`）；OpenSSL 许可见 `third_party/openssl/LICENSE`。分发前请确认许可证兼容性。

## 项目构建

### 客户端（Windows）

1. 用 Visual Studio 2022 打开 `VPN_.sln`，选择 **x64** 与 **Debug / Release** 配置；
2. 直接生成解决方案即可，构建后会自动把 `libcrypto-3-x64.dll`、`wintun.dll` 复制到输出目录；
3. 命令行构建：

```powershell
msbuild VPN_.sln /p:Configuration=Debug /p:Platform=x64
```

> 构建配置区分服务器身份公钥：**Debug** 用本地测试服务器公钥，**Release** 用正式服务器公钥（见 `src/main.cpp` 的 `kServerSigPubPem`，请自行更换）。

### 服务端（Linux）

```bash
cd server
cmake -S . -B build
cmake --build build
```

生成 `build/vpn_server`，以 root 运行（创建 TUN 网卡需要权限）：

```bash
sudo ./build/vpn_server -a 10.8.0.1 -p 51820
```

服务端常用参数：`-l/--listen`（监听 IP）、`-p/--port`（端口）、`-a/--addr`（隧道内网 IP）、`--prefix`（网段前缀）、`--mtu`、`-k/--key`（Ed25519 身份私钥，默认 `keys/server_sig.key`）、`--max-clients`（最大并发客户端数，默认 64，自动分配虚拟 IP）、`-g/--gen-token [n]`（生成 n 个一次性注册令牌）、`--quiet`（精简日志）。

**一键部署（start.sh / systemd）**：兼容 Debian/Ubuntu/CentOS/RHEL/Fedora/Arch/OpenWrt，自动选择 iptables / nftables 并配合 ufw / firewalld 放行端口：

```bash
cd server
sudo ./start.sh            # 前台运行（Ctrl+C 退出，便于调试）
sudo ./start.sh -d         # 后台守护运行（异常自动重启 watchdog，重点日志存 logs/）
sudo ./start.sh install    # 安装为 systemd 服务（推荐，关闭终端不断开）
sudo ./start.sh status     # 查看运行状态
sudo ./start.sh logs       # 实时查看重点日志
sudo ./start.sh uninstall  # 卸载 systemd 服务
sudo ./start.sh doctor     # 诊断环境，排查断开问题
```

- 脚本内关键项可用环境变量覆盖：`TUN_IP`、`TUN_PREFIX`、`TUN_MTU`、`VPN_PORT`、`LISTEN_IP`、`KEY_PATH`（默认 `keys/server_sig.key`）、`MAX_CLIENTS`（最大并发客户端数，0=默认 64）、`QUIET`（1=精简日志）等；
- **systemd 运行参数透传**：`install` 会把当前配置固化为 `/etc/default/vpn-server`（systemd `EnvironmentFile`），使 `--max-clients` 等参数在 systemd 模式下同样生效；可直接编辑该文件后 `systemctl restart vpn-server`；
- 日志：`logs/vpn-server-YYYYMMDD.log`（按天轮转）；systemd 模式下写 `logs/systemd.log`，也可 `journalctl -u vpn-server -f` 查看。

首次启动会自动生成服务器身份密钥对 `keys/server_sig.key` / `keys/server_sig.pub`，请把 `server_sig.pub` 内容硬编码进客户端 `src/main.cpp` 的 `kServerSigPubPem` 常量（客户端用它验证服务器签名，防中间人）。密钥与客户端准入数据库（`register_tokens.txt` / `registered_clients.txt`）说明见 `server/keys/README.txt`。

### 身份认证与注册

- 给新用户发注册令牌（服务端管理员操作）：

```bash
sudo ./build/vpn_server --gen-token 5
# 输出形如 register_token: <64位十六进制>，并追加到 keys/register_tokens.txt
```

- 客户端把令牌填入 `config.ini` 的 `[Identity] RegisterToken` 并设置 `ClientID` 后首次连接即完成注册（令牌一次性使用，作废后即从令牌文件移除）；之后清空令牌即为登录模式；
- 已注册客户端公钥保存在 `keys/registered_clients.txt`（每行一个 64 位十六进制 Ed25519 公钥），**私钥/令牌/注册表文件均不得提交到 Git**（`keys/*` 已在 .gitignore 忽略）；
- 身份验证通过前，`VpnCore` 不会把 TUN 流量转发进隧道（防止未注册客户端接入）。

### 运行客户端

1. 以管理员身份运行（程序清单已设置管理员权限）；
2. 首次运行自动生成 Ed25519 身份密钥：`client.id.pub`（明文公钥）+ `client.id.enc`（DPAPI 加密的私钥，绑定当前 Windows 用户，磁盘不落明文）；
3. 把 `client.id.pub` 交给服务器管理员；管理员在服务器执行 `./build/vpn_server --gen-token` 生成一次性注册令牌发给你；
4. 在 `config.ini` 的 `[Identity] RegisterToken` 填入令牌并设置 `ClientID`，重启客户端完成**注册**；注册成功后清空 `RegisterToken`，之后即为**登录**模式；
5. 命令行参数 `客户端.exe <服务器IP> <端口>` 可临时覆盖配置文件。

## 待完善

- **客户端 IOCP 模型**：UDP 收发目前为线程模型，后续可引入 I/O 完成端口（IOCP），提升高并发、高吞吐场景下的性能
- **服务端 epoll**：Linux 服务端目前为线程收发模型，后续改用 epoll 事件驱动，支撑更多并发客户端
- **UI 界面**：目前是命令行程序，后续增加图形界面与系统托盘，提供更直观的配置与状态展示
- **智能分流**：按规则分流流量，如国内直连、国外走隧道，避免全局代理
- **日志与流量统计**：统一日志系统，以及实时流量统计与限速

## 许可证

MIT License（见 `LICENSE`）。第三方组件许可见 `docs/LICENSE.txt` 与 `third_party/` 下对应文件。

---

> ⚠️ 再次提醒：本项目**仅限学习研究**，**禁止私自搭建/运营 VPN 服务**。请遵守所在地法律法规，合法合规地使用。
