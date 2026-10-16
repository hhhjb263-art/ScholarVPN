# ServerAdmin HTTP 改造计划书（基于 epoll 客户端）

> 状态：待实现
> 日期：2026-09-29
> 对象：`server/ServerAdmin/`（epoll 版 TCP 客户端，收发闭环已跑通并验证）
> 目标：在现有事件循环之上加一层 HTTP/1.1 报文构造与解析，成为可调管理 API 的命令行客户端
> 上位文档：`docs/后台管理服务计划书.md`（服务端 AdminServer / 18080 / API 四接口由该计划负责）

---

## 1. 现状：传输层已经就位

当前 `ServerAdmin` 是一个 epoll 事件驱动的 TCP 客户端，每个已有部件都正好是 HTTP 需要的：

| 已有能力 | 现有实现 | 对 HTTP 改造的意义 |
|---|---|---|
| 非阻塞连接 + 超时 | `start()`：connect → EINPROGRESS → `EPOLLOUT` → SO_ERROR | 直接复用，不用动 |
| 可靠发送 | `sendMsg()`：EPOLLOUT 循环发送，EAGAIN/EINTR 重试，sendbuf 部分发送 | 用来发 HTTP 请求报文 |
| 接收累积 | 同一循环的 EPOLLIN 分支，recv 追加进 `recvbuf` | 用来收 HTTP 响应报文 |
| 回合终止 | recv 返回 0（对端关闭）或 5 秒超时 | **配上 `Connection: close` 后，这就是 HTTP 的正确结束条件**（见第 3 节） |
| 防自杀 | `MSG_NOSIGNAL` | 服务端提前断开时不被 SIGPIPE 杀死 |
| 超时常量 | `constexpr int kTimeoutMs = 5000` | 读写超时复用 |

**结论：这次改造零行传输层代码，只加"协议层"。**

## 2. 目标形态

```bash
./ServerAdmin info                 # GET    /api/info                公钥/IP/端口
./ServerAdmin list                 # GET    /api/tokens              （带 Bearer）
./ServerAdmin gen 5                # POST   /api/tokens {"count":5}
./ServerAdmin del <token>          # DELETE /api/tokens/{token}
```

- 默认目标 `127.0.0.1:18080`（AdminServer，见上位计划）；
- 管理令牌从环境变量 `ADMIN_TOKEN` 读取（避免进 shell history）；
- 输出：`HTTP <状态码>` + body 原样打印（JSON 解析留给 Web/Qt 管理端，本客户端不做）。

## 3. 核心设计：一次 HTTP 请求 = 构造 + 现有循环 + 解析

```
httpRequest(method, path, body)
   │
   ├─ buildRequest()      拼报文字符串
   ├─ sendMsg(request)    ★ 现有 epoll 事件循环，原样使用
   └─ parseResponse(recvbuf) → HttpResponse{status, headers, body}
```

**为什么现有的"recv 到对端关闭才结束"天然正确**：请求带 `Connection: close`，合规的 HTTP 服务端发完响应就关闭连接，客户端 `recv` 返回 0、回合结束——和现在的事件循环出口完全一致。**阶段 1~3 不需要改事件循环的任何一行。**

代价：每个请求新建一条连接。对管理工具完全够用（上位计划的 AdminServer 同样按短连接设计）。

## 4. 需要写哪里（改动清单）

| 位置 | 动作 | 内容 |
|---|---|---|
| `ServerAdmin.h` | 修改 | ① `struct HttpResponse { int status = 0; std::string reason; std::map<std::string,std::string> headers; std::string body; };`（C++11 类内初始化）② 新增成员 `std::string admin_token;` ③ 新方法声明：`HttpResponse httpRequest(const std::string& method, const std::string& path, const std::string& body);`，私有辅助 `std::string buildRequest(...)`、`bool parseResponse(const std::string& raw, HttpResponse& out)` |
| `ServerAdmin.cpp` | 修改（主要工作量） | ① `buildRequest`：拼请求行 + headers（约 20 行）② `parseResponse`：切状态行 / headers / body（约 50 行）③ `httpRequest`：串联三者（约 10 行）④ `main`：`argc/argv` 子命令分发（约 30 行） |
| `start()` / `sendMsg()` 事件循环 | **不动** | 传输层保持现状 |

预计净新增 120~150 行，全部是字符串处理——真正的网络代码已经写完了。

## 5. 分阶段实施

### 阶段 1：buildRequest —— 构造请求报文

```
POST /api/tokens HTTP/1.1\r\n
Host: 127.0.0.1:18080\r\n            ← 从 m_ip:m_port 拼
Content-Type: application/json\r\n   ← 有 body 才带
Content-Length: 9\r\n                ← 一律 body.size()，字节数！中文 UTF-8 别数字符
Authorization: Bearer <token>\r\n    ← admin_token 非空才带
Connection: close\r\n                ← 必带，理由见第 3 节
\r\n
{"count":5}
```

要点：行尾一律 `\r\n`（不是 `\n`）；GET/DELETE 无 body 时 `Content-Length: 0` 也发上，服务端好处理。

### 阶段 2：parseResponse —— 解析响应

1. 找到第一个 `\r\n\r\n`，之前是头部、之后是 body；
2. 状态行 `HTTP/1.1 200 OK` → 切出 `status=200`、`reason="OK"`；格式不对返回失败，报"非 HTTP 响应"（对端是裸 TCP 服务时就会走到这里，不会死循环）；
3. headers 逐行 `Key: Value` 切分，**key 统一转小写**存 map（HTTP 头大小写不敏感）；
4. body 直接取头部之后全部——`Connection: close` 下对端关连接才结束，收到的就是完整 body；
5. 防御：`recvbuf` 总大小超过 8KB 就在事件循环里报错退出（上位计划服务端限制对称）；遇 `transfer-encoding: chunked` 显式报"暂不支持"。

### 阶段 3：httpRequest 串联 + main 子命令

```cpp
HttpResponse ServerAdmin::httpRequest(const std::string& method,
                                      const std::string& path,
                                      const std::string& body){
    HttpResponse resp;
    if(m_fd < 0){ /* 未连接 */ return resp; }
    if(!sendMsg(buildRequest(method, path, body))) return resp;   // 现有事件循环
    parseResponse(recvbuf, resp);
    return resp;
}
```

`main` 用 if/else 分发 `info/list/gen/del`（初学者友好，不引入 getopt）：

- `info` → `httpRequest("GET", "/api/info", "")`
- `gen N` → `httpRequest("POST", "/api/tokens", "{\"count\":" + std::to_string(N) + "}")`
- `del T` → `httpRequest("DELETE", "/api/tokens/" + T, "")`
- Bearer：`std::getenv("ADMIN_TOKEN")` 填进 `admin_token`（需 `<cstdlib>`）
- 错误码中文提示：401 令牌无效、404 路径/令牌不存在、其他状态码原样打印 body

### 阶段 4（可选进阶，做完上面再说）：按 Content-Length 提前结束

现在的循环要等对端关闭才返回。若将来对接不主动关闭的服务（keep-alive），把 EPOLLIN 分支改成：每收到一段就检查"头部已齐 + body 达到 Content-Length"→ 满足就 `break`。这是事件循环唯一可能动的行数（EPOLLIN 分支内加约 10 行）。

### 明确不做

chunked 编码、重定向、HTTPS、JSON 解析、连接复用、URL 编码。本客户端是学习/调试工具；正式管理端按上位计划 5.2 用 Qt `QNetworkAccessManager` / 浏览器 `fetch`。

## 6. 测试方案（不依赖 AdminServer 完成）

1. **验证请求格式**（肉眼检查）：

   ```bash
   socat TCP-LISTEN:18080,reuseaddr -     # 屏幕上应看到完整请求行/headers/\r\n
   # 另一终端：echo | ./ServerAdmin info
   ```

2. **验证响应解析**（404 也算通过——能解析出状态行和 body）：

   ```bash
   cd /tmp && python3 -m http.server 18080 &
   ./ServerAdmin info        # 预期：HTTP 404 + python 的 404 页面
   ```

3. **验证带 body 的 POST 与 Bearer**：写 10 行 Python 假 API（读 Content-Length、回 `{"ok":true}`、无令牌回 401），覆盖 200/401 两条路。

4. **对接真 AdminServer**：按上位计划第 11 节验收。

## 7. 风险与注意

| 风险 | 对策 |
|---|---|
| `Content-Length` 数错（中文 UTF-8） | 一律 `body.size()`，不手数 |
| 对端不是 HTTP（裸 TCP） | 状态行解析失败即报错，不重试不死等 |
| 服务端响应 chunked | 阶段 2 显式报"暂不支持" |
| 忘带 `Connection: close` | 现有循环会傻等 5 秒超时——测试时若每请求都等 5 秒，先检查这个头 |
| 令牌泄露 | 用环境变量不用命令行参数；服务端侧对策见上位计划第 7 节 |

## 8. 与上位计划的边界

| 事项 | 归属 |
|---|---|
| AdminServer / 18080 / API 四接口 / 鉴权 / TokenStore | `docs/后台管理服务计划书.md`（服务端） |
| 本客户端 HTTP 协议层 + CLI | 本计划（`server/ServerAdmin/`） |
| 正式管理端（Web 单页 / Qt） | 上位计划第 5 节 |
