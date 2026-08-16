# 密钥与身份数据库目录

本目录存放服务端的持久身份密钥与客户端准入数据（**绝不**提交到 Git：
`server/.gitignore` 已忽略 `keys/*`，仅保留本说明文件）：

| 文件 | 说明 |
|------|------|
| `server_sig.key` | 服务器持久 Ed25519 身份私钥（SIG_SRV_PRI，敏感）。首次启动服务端时自动生成 |
| `server_sig.pub` | 服务器身份公钥（SIG_SRV_PUB）。**请把其内容（含 BEGIN/END 行）硬编码进客户端** `src/main.cpp` 的 `kServerSigPubPem` 常量，客户端用它验证服务器签名、防中间人攻击 |
| `register_tokens.txt` | 一次性注册令牌库。管理员执行 `./build/vpn_server --gen-token [n]` 生成追加；客户端注册成功后自动移除作废 |
| `registered_clients.txt` | 已注册客户端 Ed25519 公钥（每行一个 64 位十六进制）。登录模式下服务端据此比对放行 |

## 备份 / 迁移

私钥请用 `scp` 等安全方式从本地传输到服务器：

```bash
scp keys/server_sig.key keys/server_sig.pub user@服务器IP:/path/server/keys/
```

> 注意：本目录文件名与早期 X25519 方案的 `server.key` / `server.pub` / `client.pub` 不同，
> 当前实现使用 Ed25519 持久身份密钥（`server_sig.key` / `server_sig.pub`），请勿混用旧文件名。
