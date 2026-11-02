// ============================================================================
// main.cpp —— Qt 入口：创建 QApplication 并显示主窗口
// ============================================================================

#if defined(_WIN32)
#include <winsock2.h>
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

#include <QApplication>
#include <QLockFile>
#include <QMessageBox>
#include <QCoreApplication>
#include <QFile>

#include "gui/QtWidgetsClass.h"
#include "platform/cfgstr.h"
#include "util/utf.h"   // narrow / cfg_app_dir
#include "logger.h"

#if defined(_DEBUG)
#include <crtdbg.h>
#include <cstdlib>   // getenv
#include <cstring>   // strcmp
#endif

int main(int argc, char* argv[])
{
#if defined(_DEBUG)
    // Debug 专属堆校验——**默认关闭**，按需用环境变量开启。
    //
    // ⚠️ 不要默认开 _CRTDBG_CHECK_ALWAYS_DF：它让每次 malloc/free 都遍历整个堆，
    // 与 DnsProxy 加载 11 万条域名表叠加后是 O(n²)。2026-11-01 实测（/MTd /O2）：
    //     2 万条 = 32 秒；11 万条 = 十几分钟；关掉后同样的加载只要 109 毫秒。
    // 表现是"分流模式连上后界面彻底卡死、日志停在 [Split] 自校验通过"，
    // 极易误判成死锁或崩溃（踩过一次，排查花了半小时）。
    //
    // 需要追堆损坏时再显式打开（会很慢，只用于定位）：
    //   set SV_DEBUG_HEAP=always   → 每次分配都校验（最狠，能精确到出错那次操作）
    //   set SV_DEBUG_HEAP=1024     → 每 1024 次分配校验一次（11 万条约 4 秒）
    // 上线构建（NDEBUG）完全不受影响。
    if (const char* heapMode = std::getenv("SV_DEBUG_HEAP"))
    {
        int flags = _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG);
        if (std::strcmp(heapMode, "always") == 0)
            flags |= _CRTDBG_CHECK_ALWAYS_DF;
        else if (std::strcmp(heapMode, "1024") == 0)
            flags |= _CRTDBG_CHECK_EVERY_1024_DF;
        _CrtSetDbgFlag(flags);
        std::printf("[DEBUG] 堆校验已开启: %s（会显著拖慢启动与加载）\n", heapMode);
    }
#endif
    QApplication a(argc, argv);

#if defined(_WIN32)
    // 控制台输出统一为 UTF-8（Logger 输出的中文在 GBK 控制台会乱码）
    ::SetConsoleOutputCP(CP_UTF8);
    ::SetConsoleCP(CP_UTF8);
#endif

    // 加载全局样式表（exe 同目录 style.qss；用 exe 目录而非工作目录，
    // 避免 VS 调试/管理员运行时 cwd 不同导致读不到文件）
    const QString qssPath = QCoreApplication::applicationDirPath() + "/style.qss";
    QFile qssFile(qssPath);
    if (qssFile.open(QIODevice::ReadOnly))
    {
        a.setStyleSheet(QString::fromUtf8(qssFile.readAll()));
    }

    // 单实例互斥：锁文件放 cfg_app_dir()（与 config.ini 同目录）。
    // QLockFile 记录持有进程 PID——程序崩溃后残留的锁会被新实例自动接管，
    // 不需要手工清理。锁对象不释放，RAII 覆盖整个进程生命周期。
    static QLockFile* instanceLock = new QLockFile(
        QString::fromStdString(narrow(cfg_app_dir())) + QStringLiteral("/scholarvpn.lock"));
    instanceLock->setStaleLockTime(0);
    if (!instanceLock->tryLock(0))
    {
        QMessageBox::information(nullptr, QStringLiteral("ScholarVPN"),
            QStringLiteral("ScholarVPN 已经在运行中。\n请从系统托盘或任务栏找到已打开的窗口。"));
        return 0;
    }

    // 初始化日志（写 exe 同目录 log\ScholarVPN_<时间戳>.log）
    Logger::Init();

    // 创建并显示主窗口（UI 由 QtWidgetsClass.ui 设计，uic 生成 ui_QtWidgetsClass.h）
    QtWidgetsClass w;
    w.show();

    // 进入 Qt 事件循环；退出时清理日志
    const int rc = a.exec();
    Logger::Shutdown();
    return rc;
}
