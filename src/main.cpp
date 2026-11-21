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
#include "gui/agreement_dialog.h"
#include "platform/cfgstr.h"
#include "platform/ini_doc.h"
#include "Config.h"
#include "util/utf.h"
#include "logger.h"

#if defined(_DEBUG)
#include <crtdbg.h>
#include <cstdlib>
#include <cstring>
#endif

int main(int argc, char* argv[])
{
#if defined(_DEBUG)
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
    ::SetConsoleOutputCP(CP_UTF8);
    ::SetConsoleCP(CP_UTF8);
#endif

    const QString qssPath = QCoreApplication::applicationDirPath() + "/style.qss";
    QFile qssFile(qssPath);
    if (qssFile.open(QIODevice::ReadOnly))
    {
        a.setStyleSheet(QString::fromUtf8(qssFile.readAll()));
    }

    static QLockFile* instanceLock = new QLockFile(
        QString::fromStdString(narrow(cfg_app_dir())) + QStringLiteral("/scholarvpn.lock"));
    instanceLock->setStaleLockTime(0);
    if (!instanceLock->tryLock(0))
    {
        QMessageBox::information(nullptr, QStringLiteral("ScholarVPN"),
            QStringLiteral("ScholarVPN 已经在运行中。\n请从系统托盘或任务栏找到已打开的窗口。"));
        return 0;
    }

    Logger::Init();

    {
        const cfgstr agreeIni = cfg_path_join(cfg_app_dir(), CS("config.ini"));
        if (scholini::IniGetStr(agreeIni, CS("General"), CS("AgreementAccepted"), CS("0"))
            != CS("1"))
        {
            if (!show_user_agreement(nullptr))
            {
                LOG_ERR("[Agreement] 用户拒绝用户协议，退出");
                Logger::Shutdown();
                return 0;
            }
            scholini::IniSetStr(agreeIni, CS("General"), CS("AgreementAccepted"), CS("1"));
        }
    }

    QtWidgetsClass w;
    w.show();

    const int rc = a.exec();
    Logger::Shutdown();
    return rc;
}
