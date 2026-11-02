# broker —— 受管服务发号 API

与 vpn-server 同机部署。职责与设计见 `docs/受管服务与试用授权方案.md` 第 8 节。

## 一次性初始化

```bash
# 1. service 密钥对（与 release.key 同格式，独立目录 = 独立信任根，绝不复用发布密钥）
python scripts/sign-update-policy.py gen-keys --out-dir keys-service
#   → keys-service/release.key      # 私钥，妥善保管，不入仓库
#   → keys-service/release_pub.pem  # 公钥，内置进客户端

# 2. 建库（默认路径可用 SERVICE_DB 覆盖）
python tools/broker/broker.py init-db --db /var/lib/scholarvpn/service.db

# 3. 生成并签名服务器列表（数据从参数来，禁止手写）
python tools/broker/broker.py server-list --db /var/lib/scholarvpn/service.db \
    --key keys-service/release.key --out-dir /var/lib/scholarvpn/svc \
    --server 203.0.113.7:51820 \
    --pubkey <服务器SPKI-DER-base64> \
    --remark "HK-01"
```

## 启动服务

```bash
SERVICE_TOKENS_FILE=/path/to/register_tokens.txt \
SERVICE_LIST_DIR=/var/lib/scholarvpn/svc \
python tools/broker/broker.py serve \
    --db /var/lib/scholarvpn/service.db \
    --key keys-service/release.key \
    --bind 127.0.0.1 --port 18082
# 生产：前置 nginx 反代到 443 前台域名（如 /svc/、/trial/ 路径）+ TLS
```

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `SERVICE_TOKENS_FILE` | （空=不落令牌文件） | 追加进现有 `register_tokens.txt`（flock 通道） |
| `SERVICE_LIST_DIR` | （空=不下发列表） | `server-list.ini(.sig)` 目录 |
| `SERVICE_IP_LIMIT` | 3 | 同 IP 24h 最多新申请数 |
| `SERVICE_TRIAL_DAYS` / `SERVICE_TRIAL_QUOTA` | 3 / 2GB | 试用参数 |
| `SERVICE_DB` / `SERVICE_BIND` / `SERVICE_PORT` / `SERVICE_KEY` | 见源码 | 同名命令行参数可覆盖 |
| `SERVICE_TLS_CERT` / `SERVICE_TLS_KEY` | （空=纯 HTTP） | 生产直供 HTTPS：复用同域证书独立端口对外（189 部署即此模式，8445） |

## 接口（客户端调用面）

| 路径 | 说明 |
|---|---|
| `GET /trial/register?fp=&os=&cpu=&ram=&mac=` | 申请/换发试用；响应 INI + `X-Service-Signature` 头（对响应原始字节的 Ed25519 签名） |
| `GET /trial/status?fp=` | 凭据状态（不含明文令牌），同样带签名 |
| `GET /svc/server-list.ini` / `.sig` | 静态服务器列表 + 分离签名 |

## 运维命令

```bash
python tools/broker/broker.py list    --db ...        # 列出试用/授权
python tools/broker/broker.py approve --db ... --fp <64hex>   # 转正式（解除配额/到期）
python tools/broker/broker.py reject  --db ... --fp <64hex>   # 停用
```

黑名单/审计表由 webadmin 页面维护（读写同一个库，SQL 只在 `db.py`）。

## 测试

```bash
python tools/broker/test_broker.py   # 端到端：注册/验签/换发/限频/审批/篡改拒绝
```

## 已部署（2026-10-31，189.24.71.179）

- 目录：`/opt/scholarvpn-broker/`（broker.py / db.py / keys/ / svc/ / service.db）
- 服务：`scholarvpn-broker.service`，**0.0.0.0:8445 直供 HTTPS**（证书复用
  `/root/ScholarVPN/server/tls/scholarvpn.homes.{pem,key}`，与 443/8444 同域同链）
- 令牌下发：`SERVICE_TOKENS_FILE=/root/ScholarVPN/server/keys/register_tokens.txt`
  （vpn-server 同机，flock 通道与 --gen-token 一致）
- 对外地址：`https://scholarvpn.homes:8445`（客户端内置于 service_bootstrap.h）
- 上线自检：server-list/register 签名验证 OK；register_tokens 追加 OK；
  8444 更新源与全部既有服务未受影响（各自 systemctl active + 200）
