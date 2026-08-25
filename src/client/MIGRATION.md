# ClientApp 迁移清单（从 src/main.cpp 提取）

> 目标：把 `src/main.cpp`（控制台版，680 行）的全部业务逻辑迁移到 `src/client/ClientApp`，
> 删除控制台相关代码，GUI 只负责展示与交互。
> 源文件位置以当前 `src/main.cpp` 行号标注。

## 一、静态工具函数（原样搬到 ClientApp.cpp 文件级，`static`）

| 来源 | 函数 | 说明 |
|---|---|---|
| L33-36 | `to_wstring(const std::string&)` | 窄→宽（逐字符，ASCII 够用） |
| L38-48 | `narrow(const std::wstring&)` | 宽→UTF-8 窄串（WideCharToMultiByte） |
| L151-172 | `get_exe_dir()` | 取 exe 目录（管理员运行 cwd 会变） |
| L175-190 | `find_key_file(...)` | 在 AppData keys 目录 / exe 目录查找密钥文件 |
| L195-207 | `dpapi_protect(...)` | DPAPI 加密（CryptProtectData） |
| L209-222 | `dpapi_unprotect(...)` | DPAPI 解密（CryptUnprotectData） |
| L228-238 | `kServerSigPubPem` | Debug/Release 两个公钥（常量，原样保留） |

## 二、全局状态 → ClientApp 成员变量

| 来源（main.cpp 匿名 namespace） | 变量 | 迁移为 |
|---|---|---|
| L52 | `g_running` | `std::atomic<bool> m_running` |
| L53 | `g_shutdownFlag` | 删除（stop() 可重复调用即可，用 m_running 判断） |
| L54 | `g_route` | `RouteManager* m_route`（或成员对象） |
| L55 | `g_mgr` | `ReconnectManager* m_mgr`（或成员对象） |
| L57-60 | `g_tx_pkts/g_tx_bytes/g_rx_pkts/g_rx_bytes` | 同名字段（供 UI 流量统计） |
| L64-84 | `format_bytes()` | 静态工具或移到 UI 侧 |

## 三、`main()` 流程 → 方法拆分（核心）

| 来源行 | 原逻辑 | 迁移到 |
|---|---|---|
| L251-252 | `SetConsoleOutputCP/SetConsoleCP` | ❌ 删除（UI 无控制台） |
| L254 | `Logger::Init()` | `init()` 开头 |
| L257-266 | config 路径/目录/keys 目录创建 | `init()`：`Config::GetAppDataRoaming() + "\\ScholarVPN"`，`CreateDir` |
| L268-307 | **Ed25519 首次生成**：`generate_ed25519_keypair` → 读临时私钥 → DPAPI 加密写 `client.id.enc` | `init()` 中 `ensure_identity_keys()`（若 `client.id.pub` 不存在） |
| L308-329 | **Ed25519 加载**：读 enc → `dpapi_unprotect` → `load_ed25519_private_key_pem` → `shared_ptr<EVP_PKEY>` | `init()` 中，失败返回错误（UI 可弹窗） |
| L331-350 | **服务器公钥**：`server_sig_pub_pem = kServerSigPubPem`；为空回退读 `keys\server.pub` | `init()` 原样保留 |
| L352-366 | Release 首次运行生成 config.ini | `init()`（保留，生成后提示填 ServerIP） |
| L367-384 | `config.LoadClientConfig(cfg)` | `init()` |
| L386-418 | **服务器地址解析**：Release 用 `ServerIP`+校验；Debug 用 `DebugServerIP→ServerIP→默认 192.168.1.12` | `init()` 抽成 `resolve_server(remote, port)` |
| L419-434 | 命令行参数覆盖 IP/端口 | ❌ 删除（改为 MainWindow 输入框写入 cfg 后保存） |
| L436 | `LOG_KEY("VPN starting...")` | `start()` 开头 |
| L438 | `SetConsoleCtrlHandler` | ❌ 删除（Qt 关闭事件替代） |
| L442-447 | `WintunTun::init_tun("MyTunAdapter","MyTunnel")` | `init()`；网卡名可考虑参数化（多实例） |
| L449-467 | `AdapterConfig`：`set_IPv4_address(cfg.VirtualIP)` / `set_MTU` / `set_metric` / `set_DNS_IPv4` | `init()`；**注意**：`VirtualIP` 已改为可留空，留空时跳过设置，等连接后按通告 IP 配置 |
| L469-480 | `RouteManager`：bypass + default route（`g_route = &route`） | `init()` 创建并保存成员；路由在 `connected_callback` 里再加一次 |
| L482-484 | `ReconnectManager mgr(remote, port, 256)` + `set_identity(...)` | `start()` 创建（成员），`set_identity` 传 ed_priv / server_sig_pub / ClientID / RegisterToken |
| L485-488 | `set_state_callback`：打印状态 | `start()` 注册；`LOG_KEY` 保留 + 转发给 UI 回调 |
| L489-530 | **connected_callback**：加路由 → 通告 IP 覆盖网卡 → 注册成功清 RegisterToken | `start()` 注册；逻辑原样，cfg 读写保留 |
| L531-539 | **token rejected 回调**：清 RegisterToken | `start()` 注册 |
| L540-544 | `mgr.start()` | `start()` |
| L546-575 | **桥接线程 tun_to_udp**（TUN→UDP，10ms/5ms 轮询） | `start()` 启动线程（成员 `std::thread m_tunToUdp`），循环条件 `m_running` |
| L577-602 | **桥接线程 udp_to_tun**（UDP→TUN） | `start()` 启动（成员 `m_udpToTun`） |
| L604-615 | 启动提示输出（printf/cout） | ❌ 删除（UI 状态标签显示） |
| L617-638 | **status_logger 线程**（Release，5s 打印统计） | 可选：保留为成员线程，或删掉让 UI 定时器读计数器 |
| L640-652 | **控制台输入循环**（'r' 重连 / 退出） | ❌ 删除；"重连"改为调用 `m_mgr->force_disconnect_for_test()` 的按钮 |
| L654-669 | `request_shutdown()` + join 三个线程 + `LOG("VPN stopped")` | `stop()`：置 m_running=false → `m_mgr->stop()` → `m_route->clear_routes()` → join 桥接线程 |
| L671-679 | try/catch + `Logger::Shutdown()` | `stop()` 内 try/catch；`Logger::Shutdown()` 由 main 调用 |

## 四、需要改造的点（不照搬）

| 原逻辑 | 改造 |
|---|---|
| 命令行参数（argv[1]/argv[2]） | MainWindow 输入框 → 写入 `ClientConfig` 并 `SaveClientConfig` 后调用 `start()` |
| `console_ctrl_handler` | Qt `closeEvent` → `m_app->stop()` |
| `'r'` 强制重连 | 按钮 → `m_app->force_reconnect()`（暴露 `m_mgr->force_disconnect_for_test()`） |
| 状态打印 | `set_state_callback` 同时转发给 UI 回调 |
| `VirtualIP` 留空逻辑 | `init()` 时若 cfg.VirtualIP 为空：跳过 `set_IPv4_address`，只配 MTU/DNS/Metric；`connected_callback` 收到通告 IP 后再配网卡 |

## 五、ClientApp 公开接口（建议，最终以你实现为准）

```cpp
class ClientApp {
public:
    bool init();                       // 一次性：config/身份/公钥/网卡/路由（耗时）
    bool start();                      // 启动 ReconnectManager + 桥接线程
    void stop();                       // 停止隧道/清路由/join 线程（可重复调用）
    // 查询
    ConnState state() const;
    std::string assigned_ip() const;
    uint64_t tx_bytes() const;  uint64_t rx_bytes() const;   // 流量统计
    // 回调（worker 线程触发，UI 需 QueuedConnection 切线程）
    void set_state_callback(std::function<void(ConnState)>);
    void set_connected_callback(std::function<void()>);
    void set_register_token_rejected_callback(std::function<void()>);
};
```

## 六、验证方式（不依赖 Qt）

写一个临时 `main()`（或保留旧 main.cpp 作对照）：
```
ClientApp app;
app.set_state_callback(...);  // 打印状态
if (!app.init()) return 1;
app.start();
std::this_thread::sleep_for(...);  // 观察日志
app.stop();
```
编译链接通过后，再接 Qt 界面。
