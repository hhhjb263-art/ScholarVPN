# VPN Server（Linux 服务端）

基于 **TUN 虚拟网卡 + UDP 隧道** 的 VPN 服务端。

> 本分支为 **server（服务端）** 版本，运行于 Linux。
> 客户端版本请参考仓库其他分支（如 `dev` 的 Windows/Wintun 实现）。

## 目录结构

```
Buffer/         数据缓冲（PacketBuffer / QueueBuffer）与隧道协议头
UDP/            UDP 传输层（三阶段身份认证 / 心跳保活 / 收发线程）
tun/            TUN 虚拟网卡读写
LinuxAdapter/   网卡 IP / MTU / 路由配置
core/           VpnCore 转发层（TUN ↔ UDP 桥接，身份验证通过前禁止转发）
main.cpp        服务端入口（CLI 解析 + 信号处理 + --gen-token）
```

## 构建

```bash
cmake -S . -B build
cmake --build build
```

## 运行（需要 root 权限创建 TUN）

```bash
sudo ./build/vpn_server -a 10.8.0.1 -p 51820 --default-route
```

### 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-l, --listen <ip>` | 监听 IP | `0.0.0.0` |
| `-p, --port <port>` | 监听端口 | `51820` |
| `-n, --name <name>` | TUN 网卡名 | `vpn0` |
| `-a, --addr <ip>` | 隧道内网 IP | `10.8.0.1` |
| `--prefix <n>` | 隧道网段前缀 | `24` |
| `--mtu <n>` | TUN MTU | `1400` |
| `--default-route` | 把默认路由指向 TUN | 关 |
| `-k, --key <path>` | 服务器 Ed25519 身份私钥 | `keys/server_sig.key` |
| `-g, --gen-token [n]` | 生成 n 个一次性注册令牌（默认 1）后退出 | 关 |
| `--quiet` | 关闭数据包级日志，只输出重点日志 | 关 |

## 隧道协议

- 报文头：`magic(4) + version(1) + type(1) + payload_len(2) + sequence(4)`
- **三阶段身份认证**：
  1. 阶段1（明文）：收到客户端 `nonce_c` → 生成 `nonce_s` 与临时 X25519 密钥对 → 用 `SIG_SRV_PRI` 对 `nonce_c‖nonce_s‖DH_SRV_EPHEM_PUB` 签名 → 回 `nonce_s ‖ DH_SRV_EPHEM_PUB ‖ sig_srv` → 收客户端 `DH_CLI_EPHEM_PUB`
  2. 阶段2：X25519 ECDH → `HKDF-Extract(salt=nonce_c‖nonce_s)` → `HKDF-Expand` 派生 `key_tx`/`key_rx`，加密隧道开启
  3. 阶段3（AES-GCM 密文）：解密客户端身份报文 → 重建身份负载验签 → 会话绑定检查 → **注册分支**（校验 `register_token`，写入 `keys/registered_clients.txt`，令牌作废）/ **登录分支**（比对已注册公钥）→ 通过才回复 `identity_ok` 并放行 TUN 流量
- 心跳保活：认证通过后每 10s 发送，30s 未响应判定失联

## 身份认证与注册（三阶段协议）

- 首次启动自动生成服务器持久身份密钥 `keys/server_sig.key` / `keys/server_sig.pub`（Ed25519），**请把 `server_sig.pub` 硬编码进客户端程序**（客户端用它验证服务器签名，防中间人攻击）。
- 给新用户发注册令牌：

```bash
sudo ./build/vpn_server --gen-token 5
# 输出形如 register_token: <64位十六进制>，并追加到 keys/register_tokens.txt
```

- 客户端把令牌填入 `config.ini` 的 `[Identity] RegisterToken` 并设置 `ClientID` 后首次连接即完成注册（令牌一次性使用，作废后即从令牌文件移除）；之后清空令牌即为登录模式。
- 已注册客户端公钥保存在 `keys/registered_clients.txt`（每行一个 64 位十六进制 Ed25519 公钥），**私钥/令牌/注册表文件均不得提交到 Git**（`keys/*` 已在 .gitignore 忽略）。
- 身份验证通过前，`VpnCore` 不会把 TUN 流量转发进隧道（防止未注册客户端接入）。
