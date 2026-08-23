

#pragma once
#include <QObject>
#include <QString>
#include "../client/ClientApp.h"

class AppBridge  : public QObject
{
	Q_OBJECT

public:
	explicit AppBridge(QObject* parent = nullptr);
	~AppBridge() override ;
public slots:
	void start();
	void stop();
	// 多服务器：连接指定服务器（自动 init + 设置服务器/身份 + start）
	void connect_to_server(const ServerEntry& entry);
signals:
	void stateChanged(ConnState  s);
	void connected(const QString& ip);
	void logappend(const QString &line);
	void tokenRejected();
private:
	ClientApp* m_app;
	bool m_inited = false;   // 是否已 init（首次连接时自动初始化）
};

