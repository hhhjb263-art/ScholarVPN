

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
	// 流量统计（采样用，原子量跨线程读取安全）
	uint64_t rx_bytes() const { return m_app->rx_bytes(); }   // 下载累计
	uint64_t tx_bytes() const { return m_app->tx_bytes(); }   // 上传累计
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

