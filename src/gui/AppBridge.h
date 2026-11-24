#pragma once
#include <QObject>
#include <QString>
#include <QPointer>
#include <atomic>
#include <mutex>
#include <vector>
#include "../client/ClientApp.h"
#include "../service/service_client.h"

class QThread;

class AppBridge  : public QObject
{
	Q_OBJECT

public:
	explicit AppBridge(QObject* parent = nullptr);
	~AppBridge() override;
	uint64_t rx_bytes() const { return m_app->rx_bytes(); }
	uint64_t tx_bytes() const { return m_app->tx_bytes(); }

	bool routing_split() const { return m_app->routing_split(); }
	void set_routing_split(bool split) { m_app->set_routing_split(split); }
	QString routing_mode() const { return QString::fromStdString(cfg_to_utf8(m_app->routing_mode())); }
	void set_routing_mode(const QString& mode) { m_app->set_routing_mode(cfg_from_utf8(mode.toStdString())); }

	void set_update_blocked(bool blocked) { m_app->set_update_blocked(blocked); }
	void set_service_blocked(bool blocked) { m_app->set_service_blocked(blocked); }

public slots:
	void start();
	void stop();
	void connect_to_server(const ServerEntry& entry);
	void check_update();
	void download_and_install(const QString& url, const QString& sha256,
	                          quint64 size, const QString& version);

	void set_service_mode(bool managed);
	void check_service();
	void register_service();
	void apply_server_list();
	std::vector<service::ManagedServer> take_managed_servers();

signals:
	void stateChanged(ConnState  s);
	void connected(const QString& ip);
	void logappend(int level, const QString &line);
	void tokenRejected();
	void updateChecked(int status, int action, const QString& latest,
	                   const QString& notes, const QString& error,
	                   const QString& url, const QString& sha256, quint64 size);
	void downloadProgress(int percent);
	void downloadFinished(bool ok, const QString& error);

	void serviceChecked(int blocked, const QString& reason, const QString& fp,
	                    const QString& clientId, const QString& status,
	                    qulonglong expireAt, qulonglong quotaBytes,
	                    qulonglong usedBytes, const QString& error);
	void serviceRegistered(int ok, const QString& fp, const QString& clientId,
	                       const QString& token, const QString& status,
	                       qulonglong expireAt, qulonglong quotaBytes,
	                       const QString& error);
	void serviceServers(int count, const QString& error);
	void serviceModeChanged(int managed);
private:
	ClientApp* m_app;
	bool m_inited = false;

	std::atomic<bool> m_checkBusy{ false };
	std::atomic<bool> m_downloadBusy{ false };
	std::atomic<bool> m_svcCheckBusy{ false };
	QTimer* m_svcTimer = nullptr;
	std::atomic<bool> m_svcListBusy{ false };
	std::atomic<bool> m_dlCancel{ false };
	QPointer<QThread> m_dlThread;
	std::mutex m_svcMutex;
	std::vector<service::ManagedServer> m_pendingServers;
};
