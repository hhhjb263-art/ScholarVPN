# VPN_（ScholarVPN）

学习网络通信、加密协议与 VPN 工作原理的实验性项目：**Windows 客户端**（Wintun 虚拟网卡 + UDP 隧道）
与 **Linux 服务端**（TUN + UDP 隧道），隧道使用自研三阶段身份认证协议（Ed25519 + 临时 X25519 +
HKDF + AES-256-GCM）。详细说明见根目录 `README.md`。

## 目录结构

- `src/`：Windows 客户端源码（main / UDP 隧道 / Wintun 网卡 / 路由 / 重连 / 配置）
- `server/`：Linux 服务端（CMake 工程：TUN + UDP + 转发 + 加密 + 注册/登录准入）
- `include/`：公共头文件（`tun_macro.h` 日志/断言宏）
- `third_party/`：第三方依赖（OpenSSL 3.5.6、Wintun 0.14.1）
- `Config.cpp / Config.h`：客户端 INI 配置读写
- `Crypt.cpp / Crypt.h`：客户端加密层
- `docs/`：项目文档与说明
- `x64/`：Visual Studio 构建输出

> 注：根目录下的 `Buffer/ core/ Crypt/ UDP/` 为早期服务端模块快照（未被任何工程引用），
> 现行服务端代码以 `server/` 为准。

## 构建依赖与环境

- **客户端（Windows）**
  - Visual Studio 2022（v143）+ Windows SDK 10.0，C++17，x64 Debug / Release
  - OpenSSL 3.5.6：链接 `libcrypto.lib`，运行需要 `libcrypto-3-x64.dll`（构建后自动复制到输出目录）
  - Wintun 0.14.1：运行需要 `wintun.dll`（构建后自动复制到输出目录）
  - Windows API：WinSock2（`ws2_32.lib`）、IP Helper（`iphlpapi.lib`）、DPAPI（`crypt32.lib`），
    均通过 `#pragma comment(lib, ...)` 引用
- **服务端（Linux）**
  - Linux 内核头文件（`linux/if_tun.h`、`linux/route.h` 等），仅支持 Linux
  - CMake >= 3.16 + C++17 编译器（GCC / Clang）
  - Threads（pthread）、OpenSSL（`OpenSSL::Crypto`）

## 运行要求

- 客户端程序清单已设置 **RequireAdministrator**，创建/配置 Wintun 虚拟网卡与修改路由表需要管理员权限
- 确保输出目录中的 `wintun.dll` 与项目内置 `third_party/wintun-0.14.1` 版本匹配，
  否则可能因符号缺失导致动态加载失败
- 服务端创建 TUN 网卡需要 root 权限

## 客户端运行流程（简要）

1. 首次运行在 `%APPDATA%\ScholarVPN\` 生成 `config.ini` 与身份密钥
   （`client.id.pub` 明文公钥 + `client.id.enc` DPAPI 加密私钥，绑定当前 Windows 用户）；
2. 在 `config.ini` 填写 `[Server] ServerIP`（Release 必填）、`[Identity] ClientID`；
3. 把 `client.id.pub` 交给服务器管理员，管理员 `./build/vpn_server --gen-token` 生成一次性注册令牌，
   填入 `[Identity] RegisterToken` 后连接即完成注册，成功后令牌自动清空转为登录模式；
4. 也可用命令行参数临时覆盖服务器：`客户端.exe <服务器IP> <端口>`。

## 测试指引

1. 确认 `wintun.dll`、`libcrypto-3-x64.dll` 位于可执行文件同目录（构建后已自动复制）；
2. 以管理员身份运行客户端，确认能成功创建 Wintun 适配器并完成三阶段认证（观察日志）；
3. 服务端 `sudo ./build/vpn_server -a 10.8.0.1 -p 51820 --default-route` 联调；
4. 用 Wireshark（Npcap）监听 Wintun 虚拟网卡，或使用 `Get-NetAdapter` / `Get-NetIPAddress`
   验证地址与路由配置。

## 注意事项

- 项目中包含来自 Wintun 的源代码与示例，应遵守对应许可证（Wintun 原始代码通常为 GPLv2；
  预编译二进制有不同许可），详见 `third_party/wintun-0.14.1/prebuilt-binaries-license.txt`；
  OpenSSL 许可见 `third_party/openssl/LICENSE`。分发或合并代码前请确认许可证兼容性。
- 服务端 `keys/` 目录（身份私钥、注册令牌、已注册客户端表）**绝不提交到 Git**。
- 建议在仓库根目录补充 `.editorconfig` 与 `CONTRIBUTING.md`，统一编码风格与贡献流程。

## 其他信息

如需更多信息或支持，请查看根目录 `README.md`、`server/README.md` 或联系维护者。
