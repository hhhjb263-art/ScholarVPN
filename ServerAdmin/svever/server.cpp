#include "server.h"
#include <QDebug>
#include <QHostAddress>

ServerAdmin::ServerAdmin(QObject *parent)
    : QObject(parent),
    m_ser(new QTcpServer(this))
{
    connect(m_ser, &QTcpServer::newConnection,
            this, &ServerAdmin::onNewConnection);
}

bool ServerAdmin::start(quint16 port)
{
    bool ok = m_ser->listen(QHostAddress::AnyIPv4, port);
    if(!ok){
        qDebug() << "listen is failed:" << m_ser->errorString();
        return false;
    }
    qDebug() << "Server start, port:" << port;
    return true;
}

void ServerAdmin::onNewConnection()
{
    QTcpSocket *clientSocket = m_ser->nextPendingConnection();
    QString client_ip = clientSocket->peerAddress().toString();
    m_clients[clientSocket] = client_ip;

    connect(clientSocket, &QTcpSocket::readyRead,this, &ServerAdmin::onReadyRead);
    //connect(clientSocket, &QTcpSocket::disconnected, this, &ServerAdmin::onDisconnected);
    for(auto it = m_clients.begin();it != m_clients.end();++it){
        QTcpSocket *sock = it.key();
        QString name = it.value();
        qDebug() << "IP:" << sock->peerAddress().toString() << "  Tag:" << name;
    }
}

void ServerAdmin::onReadyRead()
{
    QTcpSocket *sock = qobject_cast<QTcpSocket*>(sender());
    QByteArray data = sock->readAll();
    QString sendIp = sock->peerAddress().toString();
    qDebug() << "from IP:" << sendIp << " | receive data:" << data;
}
