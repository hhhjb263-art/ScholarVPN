# src/gui/ —— Qt 图形界面

> ⚠️ 本目录只写 UI：展示状态/日志、接收用户操作；网络逻辑一律调 `ClientApp`。

## 文件
| 文件 | 状态 | 职责 |
|---|---|---|
| `qt_test.cpp` | ✅ 可用 | Qt 6.9.1 环境验证（QApplication + QLabel），已编译通过 |
| `MainWindow.h` | 占位（仅注释） | 主窗口类声明：控件成员、槽函数 |
| `MainWindow.cpp` | 占位（仅注释） | 界面组装、按钮逻辑、跨线程日志/状态更新 |

## 实现顺序建议
1. 先让 `MainWindow` 空窗口跑起来（只含设置输入框 + 状态标签 + 日志框）
2. 接 `Logger::SetSink` → 日志框能滚动输出（验证跨线程 QueuedConnection）
3. 接 `ClientApp` 回调 → 状态标签随 ConnState 变化
4. 实现连接/断开按钮（后台线程 init + start / stop）

## 工程集成（vcxproj 需要你补）
- `<ClCompile>` 加：`src\gui\MainWindow.cpp`、`src\client\ClientApp.cpp`
- `<ClInclude>` 加：`src\gui\MainWindow.h`、`src\client\ClientApp.h`
- Qt 的 include/lib/DLL 复制配置你已配好（qt_test.cpp 已验证）

## 关键约束
- **跨线程**：ClientApp 回调 / Logger sink 在 worker 线程触发，
  更新控件一律 `QMetaObject::invokeMethod(..., Qt::QueuedConnection)` 切回 UI 线程
- **关闭**：`closeEvent` 先 `ClientApp::stop()` 再退出，避免残留线程
- **moc**：若 MainWindow 用 `Q_OBJECT`/自定义信号，需要在 vcxproj 加 QtMoc（Qt VS Tools）；
  不用 Q_OBJECT 则无需 moc
