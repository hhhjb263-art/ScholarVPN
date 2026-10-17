# 后台管理 Web 客户端

给 `vpn_controller` 的极简 JSON API 套一层网页。协议依据 `docs/客户端实现方案接口.md`。

**零依赖**：只用 Python 3 标准库，不需要 `pip install`。

---

## 为什么需要这层代理

网页不能直接 `fetch` controller 的 18081：

1. controller **不返回 CORS 头**，浏览器会拦；
2. 管理令牌不该进浏览器——放在服务端环境变量里，前端永远看不到；
3. controller 的 HTTP 入口是**单线程、每请求短连接**，集中代理更好控制超时和错误提示。

```
浏览器 ──▶ 本服务(:8080) ──▶ vpn_controller(:18081) ──▶ admin_agent ──▶ admin_server(:18080)
            注入 Bearer            JSON API              19090 通道        业务执行
```

---

## 运行

```bash
cd tools/webadmin

# 推荐：令牌走环境变量，浏览器看不到
ADMIN_TOKEN=<controller 的 ADMIN_TOKEN> python3 app.py

# 然后打开 http://127.0.0.1:8080/
```

远程管理（本服务默认只绑环回）：

```bash
# 在管理机上
ssh -L 8080:127.0.0.1:8080 user@中转服务器
# 然后在本地浏览器开 http://127.0.0.1:8080/
```

### 参数

| 参数 | 环境变量 | 默认 |
|---|---|---|
| `--listen` | `WEBADMIN_BIND` | `127.0.0.1` |
| `--port` | `WEBADMIN_PORT` | `8080` |
| `--controller` | `CONTROLLER_URL` | `http://127.0.0.1:18081` |
| `--token` | `ADMIN_TOKEN` | 空（可在网页里输入） |

令牌也可以不配：点页面右上「令牌」输入，存在浏览器 `sessionStorage`，每次请求经
`X-Admin-Token` 头转给本服务。**适合临时排查，长期用请走环境变量。**

---

## 功能

- 服务器列表（`GET /api/servers`），在线状态、来源 IP、指纹前缀
- 公钥与监听信息（`GET /api/servers/{id}/info`），一键复制指纹 / PEM
- 未消费令牌列表，逐条复制、删除
- 申请 N 个令牌（1–1000）
- 一键导出 JSON（服务器信息 + 当前未消费令牌）
- 每 15 秒自动刷新列表

---

## 排障

### 页面能开，但所有接口都 502

**八成是系统代理。** 服务器上常见 `http_proxy=http://...`（给 apt/docker 用的），
Python 的 `urllib` 会把它套到连 `127.0.0.1` 的请求上，于是代理替我们回一个 502。

本程序已经对 controller 的请求**显式禁用代理**（`ProxyHandler({})`），所以正常不会中招。
如果你自己改代码，别把这一行去掉。

### 401 有两种来源，别搞混

| 谁返回的 | 原因 | 怎么查 |
|---|---|---|
| controller | 本服务用的管理令牌不对 | 页面上「令牌」，或 `ADMIN_TOKEN` 环境变量 |
| agent 侧 admin_server | agent 启动时的 `--token` 与其本机 admin_server 不一致 | 看 `admin_agent` 日志 |

### 503 agent offline

该服务器当前没有在线连接，controller **不排队**。检查：

1. `admin_agent` 在跑吗？
2. 指纹登记了吗？`./admin-relay.sh add-agent <64hex>`
3. 登记后**重启 controller 了吗**？白名单只在启动时读一次。

### 服务器列表为空

同上，外加一条：**一期 controller 只支持单 agent 连接**（见接口文档 6.8），
第二台服务器会一直等第一台断开。这不是配置错误。

### 令牌数量上不去 / agent 反复断开

单帧上限 64KB，约 **950 个令牌**触顶（接口文档 6.1）。申请后尽快分发。

---

## 已知限制（继承自 controller）

| 限制 | 说明 |
|---|---|
| `last_seen` 不是墙钟时间 | 是 controller 的单调时钟毫秒，**不能格式化成日期**；页面只把它放进 tooltip |
| 请求体 ≤ 8KB | 超过直接 413（本服务提前挡掉） |
| controller 单线程、无读超时 | 客户端必须尽快发完整请求；慢客户端会拖住整个管理面 |
| agent 通道明文 TCP | 握手能证明身份但不加密，必须置于内网/VPN/防火墙之后 |
| 无 controller 侧审计 | 审计只在 admin_server 那一侧有 |

---

## 文件

| 文件 | 说明 |
|---|---|
| `app.py` | 代理 + 静态服务（单文件，标准库） |
| `index.html` | 管理界面（原生 JS，无框架） |
