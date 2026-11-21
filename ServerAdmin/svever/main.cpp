#include <QCoreApplication>
#include "server.h"
int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    ServerAdmin s;
    s.start(18889);
    return a.exec();
}
