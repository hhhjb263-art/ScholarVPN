// ============================================================================
// tests/test_single_instance.cpp —— QLockFile 单实例语义的跨进程测试
//
// 用法（两个进程配合）：
//   test_single_instance hold   # 进程 A：持锁 30 秒（后台运行）
//   test_single_instance try    # 进程 B：应被拒绝（exit 1）
//   （A 退出后）B 再 try         # 应成功（exit 0）
//
// 编译：
//   Linux:  g++ -std=c++17 -I. -Isrc tests/test_single_instance.cpp \
//             -o tst $(pkg-config --cflags --libs Qt6Core) -fPIC
//   Win:    cl /std:c++20 /EHsc /I. /Isrc tests\test_single_instance.cpp \
//             /link Qt6Core.lib
// ============================================================================

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
        for (int i = 0; i < 30; ++i)   // 持锁 30 秒（可被 kill 提前终止）
        {
            QThread::sleep(1);
        }
        std::printf("hold: timeout released\n");
        return 0;
    }

    // try 模式：拿到锁 = exit 0；被拒 = exit 1
    if (lf.tryLock(0))
    {
        std::printf("try: acquired\n");
        return 0;
    }
    std::printf("try: rejected\n");
    return 1;
}
