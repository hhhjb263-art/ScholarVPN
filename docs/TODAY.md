日期: 今天

概要：
本日完成的工作集中在修复与网络接口配置相关的编译问题与运行时错误，并实现/改进了虚拟网卡（Wintun）配置逻辑。主要变更包括：

1. 修复并实现 AdapterConfig 的 IPv4 地址管理与接口配置
   - 实现 `AdapterConfig::set_IPv4_address`：解析字符串 IPv4、填充 `MIB_UNICASTIPADDRESS_ROW` 并调用 `CreateUnicastIpAddressEntry`。
   - 实现 `AdapterConfig::remove_IPv4_address`：使用 `DeleteUnicastIpAddressEntry` 删除单播地址。
   - 修改并加固 `set_MTU`：通过 `GetIpInterfaceEntry` 获取当前 `MIB_IPINTERFACE_ROW`，修改 `NlMtu` 并调用 `SetIpInterfaceEntry`，在必要时通过 `ConvertInterfaceLuidToIndex` 填充 `InterfaceIndex`，并在失败时尝试以 `InterfaceIndex` 为准的替代调用以兼容不同平台的行为。
   - 修复并调整头文件包含顺序与版本宏，确保 Windows SDK 类型与函数在编译时可用（例如 `MIB_UNICASTIPADDRESS_ROW`, `MIB_IPINTERFACE_ROW` 等）。
   - 增加日志与调试输出，方便定位 `SetIpInterfaceEntry` 返回 `ERROR_INVALID_PARAMETER`（87）的问题。

2. 修复 route_manager 头文件的问题
   - 修正版本宏为数值常量，保证新版 ip helper 类型可见（如 `MIB_IPFORWARD_ROW2`）。
   - 修复 `Ipv4RouteParam` 的语法，改为合法 `struct Ipv4RouteParam` 占位类型。

3. 代码风格与小修正
   - 调整了若干包含顺序（例如在包含 `windows.h` 之前包含 `winsock2.h`/`ws2tcpip.h`），添加必要的 pragma comment lib 以确保链接。
   - 修复日志位置与错误处理逻辑（例如将已存在的地址视为成功的返回值逻辑）。

测试与构建：
- 本地构建通过（在开发环境中使用 Windows SDK）。
- 在运行时观察到 `CreateUnicastIpAddressEntry` 返回成功，但 `SetIpInterfaceEntry` 一开始返回 87（ERROR_INVALID_PARAMETER）；已加入额外诊断信息并尝试替代调用以规避该问题。后续可根据诊断日志继续修正字段设置。

后续建议：
- 在管理员权限下运行测试，确保修改接口配置的权限充足。
- 根据诊断输出进一步检查 `MIB_IPINTERFACE_ROW` 中哪些字段被驱动层视为非法（必要时只写入允许修改的字段）。
- 为 `RouteManager` 补充具体路由参数结构与实现路由创建/删除逻辑。 

修改的主要文件：
- `AdapterConfig.cpp`  （实现/修复多处网络配置函数）
- `AdapterConfig.h`   （无大改动，但被包含顺序影响）
- `route_manager.h`   （修复宏与结构体声明）
- 其他：若干头包含顺序调整


---

## 更新记录：文档同步（随代码现状）

概要：
将项目文档整体同步到当前代码状态，并统一文档编码。

1. 文档内容同步
   - `server/keys/README.txt`：原描述旧版 X25519 密钥（`server.key`/`server.pub`/`client.pub`），
     更新为现行 Ed25519 身份密钥（`server_sig.key`/`server_sig.pub`）+ 准入数据库
     （`register_tokens.txt`/`registered_clients.txt`），并提醒勿混用旧文件名。
   - `server/README.md`：补充 `keys/`、`Crypt/` 目录说明，新增「一键部署（start.sh / systemd）」小节
     （`-d` 守护、`install`、`status`/`logs`/`doctor` 等子命令与环境变量覆盖）。
   - 根 `README.md`：目录树展开 `server/` 子结构；服务端构建小节补充 `start.sh` 部署用法；
     密钥说明指向 `server/keys/README.txt`。
   - `docs/README.md`：重写为与当前项目一致（客户端/服务端双端、依赖、运行流程、测试指引），
     并注明根目录 `Buffer/ core/ Crypt/ UDP/` 为早期服务端模块快照、以 `server/` 为准。

2. 编码统一
   - `docs/README.md`、`docs/TODAY.md` 由 GBK 转为 UTF-8（无 BOM），消除中文乱码隐患。

3. 脚本与代码默认值对齐
   - `server/start.sh`：`KEY_PATH` 默认值由 `keys/server.key`（旧文件名）改为
     `keys/server_sig.key`，与 `vpn_server` 默认值（`VpnCore.h`）及文档一致。

4. 待办（未改动，仅记录）
   - 根目录 `Buffer/ core/ Crypt/ UDP/` 旧模块快照是否删除，由维护者决定；
   - `.editorconfig` / `CONTRIBUTING.md` 建议补充（见 docs/README.md）。

修改的主要文件：
- `server/keys/README.txt`
- `server/README.md`
- `README.md`
- `docs/README.md`
- `docs/TODAY.md`
- `server/start.sh`


