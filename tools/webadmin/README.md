# 后台管理 Web 客户端

给 `vpn_controller` 的 JSON API（默认 `127.0.0.1:18081`）套一层网页。
协议依据 `docs/客户端实现方案接口.md`。

**零依赖**：只用 Python 3 标准库，不需要 `pip install`。

## 快速开始

```bash
cd tools/webadmin
ADMIN_TOKEN="$(cd ../../server && ./admin-relay.sh token)" python3 app.py
# 打开 http://127.0.0.1:8080/
# 不开放注册：首个管理员在服务器执行
# python3 manage.py create-admin <用户名>
# 之后在 /login 用管理员账号登录
```

远程管理用 SSH 隧道，别把服务绑到 `0.0.0.0`：

```bash
ssh -L 8080:127.0.0.1:8080 user@<中转服务器IP>
```

没部署 controller 也想看界面？先初始化管理员再登录：

```bash
python3 mock_controller.py                                    # 终端 1：假数据
python3 app.py --port 8080 --controller http://127.0.0.1:19998 --token goodtoken   # 终端 2
```

## 功能

管理员登录/登出/修改密码 · 管理员账号管理 · 服务器列表 · 公钥与监听信息 ·
未消费令牌增删复制 · 申请令牌 · 一键导出 JSON

## 文档

**完整使用说明见 [`使用说明.md`](使用说明.md)** —— 启动方式、界面操作、
错误对照表、排障（含"页面能开但接口全 502"的系统代理坑）、安全注意、已知限制。

## 文件

| 文件 | 说明 |
|---|---|
| `app.py` | HTTP/HTTPS 服务、认证路由 + 反向代理 |
| `auth.py` | SQLite 管理员、scrypt 密码、会话、CSRF、限速、审计 |
| `login.html` | 登录页 |
| `index.html` | 管理界面（原生 JS，无框架） |
| `manage.py` | 账号恢复 CLI（list/create-admin/reset-password） |
| `data/webadmin.db` | 管理员/会话/审计数据库（自动生成，勿提交） |
| `mock_controller.py` | 演示用假 controller，**不要用于生产** |
| `使用说明.md` | 完整手册 |
