#include <QLockFile>
#include <QCoreApplication>
#include <QThread>

#include <cstdio>
#include <string>

#if defined(_WIN32)
#include <windows.h>
#endif

int main(int argc, char* argv[])
{
    QCoreApplication app(argc, argv);
    const QString mode = (argc > 1) ? QString::fromLocal8Bit(argv[1]) : QStringLiteral("try");
    const QString lockPath = (argc > 2) ? QString::fromLocal8Bit(argv[2])
                                        : QStringLiteral("/tmp/scholarvpn-inst-test.lock");

    QLockFile lf(lockPath);
    lf.setStaleLockTime(0);

    if (mode == QStringLiteral("hold"))
    {
        if (!lf.tryLock(0))
        {
            std::printf("hold: FAIL (lock rejected)\n");
            std::fflush(stdout);
            return 2;
        }
        std::printf("hold: locked\n");
        std::fflush(stdout);
        for (int i = 0; i < 30; ++i)
        {
            QThread::sleep(1);
        }
        std::printf("hold: timeout released\n");
        return 0;
    }

    if (lf.tryLock(0))
    {
        std::printf("try: acquired\n");
        return 0;
    }
    std::printf("try: rejected\n");
    return 1;
}
