# ScholarVPN

ScholarVPN 是一个用于学习网络通信、加密协议和 VPN 工作原理的实验性项目，包含 **Windows 客户端**（Wintun 虚拟网卡 + UDP 隧道）与 **Linux 服务端**（TUN 虚拟网卡 + UDP 隧道）。隧道使用自研三阶段身份认证协议：Ed25519 签名防中间人 + 临时 X25519 前向安全密钥交换 + HKDF 密钥派生 + AES-256-GCM 认证加密，客户端/服务器身份均需注册准入，项目持续完善中。

## 项目介绍

### 架构

客户端与服务端通过 UDP 建立隧道：客户端创建 Wintun 虚拟网卡，把本机流量封装进自定义 UDP 报文发往服务器；服务器从 TUN 网卡转发到真实网络，回程流量再反向封装回客户端。两端使用同一套自研隧道协议（魔数 `MVPN`，12 字节报文头 + 三阶段身份认证 + 心跳保活），加密层基于 OpenSSL 标准算法。

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
├── server/                    Linux 服务端（CMake 工程：TUN + UDP + 转发 + 加密）
├── include/                    公共头文件
├── third_party/                OpenSSL 3.5.6、Wintun 0.14.1
├── Config.cpp / Config.h       客户端 INI 配置读写
├── docs/                       项目文档
└── x64/                        Visual Studio 构建输出
```

### 隧道协议与加密

- 报文头 12 字节：`magic(4) + version(1) + type(1) + payload_len(2) + sequence(4)`，魔数 `0x4D56504E`（"MVPN"）
- **三阶段身份认证**（防中间人 + 身份准入，身份未验证前服务器禁止 TUN 转发）：
  1. **阶段1（明文）**：客户端发 `nonce_c` → 服务器回 `nonce_s ‖ DH_SRV_EPHEM_PUB ‖ sig_srv`（用持久身份私钥 `SIG_SRV_PRI` 对 `nonce_c‖nonce_s‖DH_SRV_EPHEM_PUB` 签名）→ 客户端用内置的 `SIG_SRV_PUB` 验签，**失败即断开（中间人攻击）** → 客户端生成临时 X25519 密钥对并回 `DH_CLI_EPHEM_PUB`
  2. **阶段2**：双方 X25519 ECDH 计算共享秘密 → `HKDF-Extract(salt = nonce_c ‖ nonce_s)` → `HKDF-Expand` 派生方向性会话密钥 `key_tx`（客户端→服务端）/ `key_rx`（服务端→客户端），加密隧道开启
  3. **阶段3（AES-GCM 密文）**：客户端发送身份报文（全部会话上下文 + `client_id` + `SIG_CLI_PUB` + `SIG_CLI_PRI` 签名，注册模式附带一次性 `register_token`）→ 服务器解密 + GCM 校验 → 重建同一身份负载并验签 → 会话绑定检查 → **注册分支**（校验令牌、写入注册表、令牌作废）/ **登录分支**（比对已注册公钥）→ 通过才回复 `identity_ok` 并放行 TUN 流量
- 心跳保活：认证通过后每 1s 发送，5s 未收到对端任何报文判定失联并自动重连
- 密钥体系：持久身份密钥为 **Ed25519**（服务器 `SIG_SRV` 硬编码进客户端；客户端 `SIG_CLI` 私钥经 Windows DPAPI 加密存储）；每次会话的加密密钥由**临时 X25519** 派生（前向安全，断开即销毁）

### 配置

客户端运行参数通过 INI 文件配置，首次运行自动生成：

- 路径：`%APPDATA%\ScholarVPN\config.ini`
- 默认服务器：`    请自行填写      `（Debug 构建默认 `192.168.1.12`）

```ini
[Server]
ServerIP= 请自行填写          # Release 构建使用（必填）
DebugServerIP=192.168.1.12   # 仅 Debug 构建使用：本地测试服务器，Release 构建忽略
ServerPort=51820

[General]
Timeout=5000

[Network]
VirtualIP=10.8.0.2
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

### 服务端（Linux）

```bash
cd server
cmake -S . -B build
cmake --build build
```

生成 `build/vpn_server`，以 root 运行（创建 TUN 网卡需要权限）：

```bash
sudo ./build/vpn_server -a 10.8.0.1 -p 51820 --default-route
```

服务端常用参数：`-l/--listen`（监听 IP）、`-p/--port`（端口）、`-a/--addr`（隧道内网 IP）、`--prefix`（网段前缀）、`--mtu`、`--default-route`（默认路由指向 TUN）、`-k/--key`（Ed25519 身份私钥，默认 `keys/server_sig.key`）、`-g/--gen-token [n]`（生成 n 个一次性注册令牌）、`--quiet`（精简日志）。

首次启动会自动生成服务器身份密钥对 `keys/server_sig.key` / `keys/server_sig.pub`，请把 `server_sig.pub` 内容硬编码进客户端 `src/main.cpp` 的 `kServerSigPubPem` 常量（客户端用它验证服务器签名，防中间人）。

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