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
#endif

int main(int argc, char* argv[])
{
#if defined(_DEBUG)
    // Debug 专属：每次 malloc/free 都做完整堆一致性校验。
    // 作用：堆被越界写坏时，崩溃点会精确落在"发生损坏的那次操作"，
    // 而不是之后某个无辜的 free（下载按钮的崩溃就是后一种情况，
    // 真凶在更早的代码里写坏了堆，package_path 的临时串只是踩雷的）。
    // 上线构建（NDEBUG）完全不受影响。
    _CrtSetDbgFlag(_CrtSetDbgFlag(_CRTDBG_REPORT_FLAG) | _CRTDBG_CHECK_ALWAYS_DF);
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
