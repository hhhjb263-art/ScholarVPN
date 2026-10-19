#ifndef SERVER_H
#define SERVER_H
#include <QObject>
#include <QTcpServer>
#include <QTcpSocket>
#include<QMap>
class ServerAdmin : public QObject
{
    Q_OBJECT
public:
    explicit ServerAdmin(QObject *parent = nullptr);
    bool start(quint16 port);

private slots:
    void onNewConnection();
    void onReadyRead();

private:
    QTcpServer *m_ser;
    QMap<QTcpSocket*, QString> m_clients; // Store clients and their identifiers
};
#endif // SERVER_H
