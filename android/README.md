# ScholarVPN Android 客户端（骨架）

纯 Kotlin 实现（零 native 依赖），与现有 Windows 客户端 / Linux 服务端走同一套隧道协议。

## 线格式规格

**实现与联调的唯一验收标准：[`docs/ANDROID_PROTOCOL_SPEC.md`](../docs/ANDROID_PROTOCOL_SPEC.md)**
（从两端 C++ 代码逐字节提取，含字节序混合、GCM 封装布局、HKDF 派生、身份报文结构）。

## 模块状态

| 文件 | 状态 | 说明 |
|------|------|------|
| `tunnel/Protocol.kt` | ✅ 完成 | 帧头编解码（magic 小端 / len+seq 大端）、消息类型、身份报文组装 |
| `tunnel/TunnelCrypto.kt` | ✅ 完成 | AES-256-GCM（平台 Conscrypt 硬件加速）、HKDF-SHA256（手写 RFC 5869）、Ed25519/X25519（BouncyCastle 轻量 API） |
| `tunnel/Framing.kt` | ✅ 完成 | TCP 分帧状态机（先吃缓冲语义，对齐 C++ 端优化后实现） |
| `tunnel/TunnelClient.kt` | ✅ 完成 | 三阶段认证状态机（5s 超时/500ms 重传/10 次上限，对齐 C++ 端）、心跳保活（1s/5s）、收发循环、心跳超时死亡回调 |
| `vpn/ScholarVpnService.kt` | ✅ 完成 | 三阶段认证 → establish 建 tun（MTU 1400 + 全路由 + DNS）→ fd↔隧道双向桥接 → 前台通知；**M4 指数退避重连已实现** |
| `vpn/IdentityStore.kt` | ✅ 完成 | Ed25519 身份密钥：EncryptedSharedPreferences（Keystore 硬件后备）加密存储，首次运行自动生成 |
| `vpn/VpnSettings.kt` | ✅ 完成 | 服务器配置；公钥接受 raw base64 或 PEM 两种格式；**受管卡片整体替换（applyManagedServers）** |
| `service/ServiceClient.kt` | ✅ 完成 | 受管服务 HTTP 客户端：申请试用 / 状态同步 / 服务器列表下发，**全部响应 Ed25519 验签**（对齐 Windows service_client.cpp） |
| `service/MachineInfo.kt` | ✅ 完成 | 机器指纹 = SHA-256("ScholarVPN-Service-v1" \| ANDROID_ID)，与 C++ fingerprint_of 逐字节一致 |
| `MainActivity.kt` | 🚧 可用 | 卡片式服务器列表 + 抽屉内受管服务面板（申请/刷新）；速率曲线等 TODO(M3) |

## 构建

1. Android Studio 打开 `android/` 目录（Gradle Wrapper 已内置，Gradle 8.13 本地缓存可用，无需联网下载发行版；依赖走阿里云镜像）；
2. `minSdk 29`（Android 10+），`targetSdk 35`；
3. 无需 NDK/CMake——全部 Kotlin + 平台 API + BouncyCastle 一个依赖；
4. 命令行构建：`gradlew.bat assembleDebug`。

## 开发里程碑

- ✅ **M0**：VpnService 授权 + establish 通路
- ✅ **M1**：TunnelClient 三阶段认证实现（已与现有 Linux 服务端联调）
- ✅ **M2**：fd↔隧道桥接（真机验证隧道内 ping 通 / 可上网，TCP 传输切换）
- ✅ **M4**：弱网重连（指数退避状态机 + 网络事件提前唤醒，2026-11-01 确认已实现）
- ✅ **受管服务**（2026-11-01）：申请试用 → 状态同步 → 服务器列表下发（验签）→ 卡片自动生成，
  对接 broker `/trial/*` 与 `/svc/server-list.ini`；fp = SHA-256(salt | ANDROID_ID)
- 🚧 **M3**：完整 Compose UI（速率曲线、DataStore 配置迁移）、专用通知图标

## 联调步骤（M1/M2）

1. 服务端 `sudo ./build/vpn_server -a 10.8.0.1 -p 51820`（先 `--gen-token` 取令牌）；
2. 把服务端 `keys/server_sig.pub` 的完整 PEM 内容粘贴进 App 的「服务器公钥」栏；
3. 填服务器 IP / 端口 / ClientID / 注册令牌（首次注册），点「保存并连接」；
4. 观察服务端日志逐阶段比对（`[UDP][AUTH]` 已回复签名 ServerHello → 加密隧道已建立 → 客户端注册/登录成功 → 放行 TUN 流量）；
5. 注册成功后令牌清空重连即为登录模式；App 内身份公钥可由 `adb logcat` 获取（TODO：UI 显示，交给服务端管理员登记）。

## 安全设计

- 客户端 Ed25519 私钥（32 字节 seed）存 EncryptedSharedPreferences，密钥由 Android Keystore 硬件后备；
- 服务器公钥固定（防中间人）：内置默认 + 每服务器条目可覆盖，格式为 32 字节 raw（由服务端 `server_sig.pub` PEM 转换一次）；
- 数据面 AES-256-GCM（nonce‖ct‖tag，AAD=帧头），会话密钥前向安全（临时 X25519，会话结束即弃）。
