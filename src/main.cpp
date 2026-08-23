// ============================================================================
// main.cpp —— Qt 入口：创建 QApplication 并显示主窗口
// ============================================================================

#include <winsock2.h>
#include <windows.h>

#include <QApplication>
#include <QCoreApplication>
#include <QFile>

#include "gui/QtWidgetsClass.h"
#include "logger.h"

int main(int argc, char* argv[])
{
    QApplication a(argc, argv);

    // 控制台输出统一为 UTF-8（Logger 输出的中文在 GBK 控制台会乱码）
    ::SetConsoleOutputCP(CP_UTF8);
    ::SetConsoleCP(CP_UTF8);

    // 加载全局样式表（exe 同目录 style.qss；用 exe 目录而非工作目录，
    // 避免 VS 调试/管理员运行时 cwd 不同导致读不到文件）
    const QString qssPath = QCoreApplication::applicationDirPath() + "/style.qss";
    QFile qssFile(qssPath);
    if (qssFile.open(QIODevice::ReadOnly))
    {
        a.setStyleSheet(QString::fromUtf8(qssFile.readAll()));
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
