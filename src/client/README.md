# src/client/ —— 客户端核心逻辑（纯业务，无 UI）

> ⚠️ 本目录只写**业务逻辑**，禁止 include 任何 Qt 头——保证可单独编译测试。

## 文件
| 文件 | 状态 | 职责 |
|---|---|---|
| `ClientApp.h` | 占位（仅注释） | 核心逻辑类声明：init / start / stop / 状态查询 / 回调接口 |
| `ClientApp.cpp` | 占位（仅注释） | 实现：从 `src/main.cpp`（控制台版）提取全部业务逻辑 |

## 实现顺序建议
1. 先在 `ClientApp.h` 定好公开接口（init/start/stop/回调）
2. 再从 `src/main.cpp` 把 DPAPI、公钥分支、Wintun/路由、ReconnectManager、桥接线程逐段搬进 `ClientApp.cpp`
3. 用旧的 `src/main.cpp` 编译链接做对照验证（不依赖 Qt 也能编译）

## 依赖（均已有）
`Config` / `Crypt` / `tun`(WintunTun) / `AdapterConfig` / `route_manager` / `reconnect_manager` / `logger`
