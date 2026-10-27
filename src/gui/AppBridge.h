#pragma once
#include <QObject>
#include <QString>
#include <QPointer>
#include <atomic>
#include "../client/ClientApp.h"

class QThread;

class AppBridge  : public QObject
{
	Q_OBJECT

public:
	explicit AppBridge(QObject* parent = nullptr);
	~AppBridge() override;
	// 流量统计（采样用，原子量跨线程读取安全）
	uint64_t rx_bytes() const { return m_app->rx_bytes(); }   // 下载累计
	uint64_t tx_bytes() const { return m_app->tx_bytes(); }   // 上传累计

	// 分流模式：读运行时状态 / 更新运行时状态（落盘由 GUI 写 config.ini）
	bool routing_split() const { return m_app->routing_split(); }
	void set_routing_split(bool split) { m_app->set_routing_split(split); }

	// 强制更新时禁止连接（界面禁用之外的第二道闸门）
	void set_update_blocked(bool blocked) { m_app->set_update_blocked(blocked); }

public slots:
	void start();
	void stop();
	// 多服务器：连接指定服务器（自动 init + 设置服务器/身份 + start）
	void connect_to_server(const ServerEntry& entry);
	// 异步检查更新：结果通过 updateChecked 回来（在 GUI 线程）。
	// 内部防重入：检查进行中时再次调用会被直接忽略。
	void check_update();
	// 下载并启动安装器（前会先断开隧道：不能依赖自己要替换的那条隧道）。
	// 同样防重入：下载中重复调用被忽略（并发会写同一个文件）。
	void download_and_install(const QString& url, const QString& sha256,
	                          quint64 size, const QString& version);
signals:
	void stateChanged(ConnState  s);
	void connected(const QString& ip);
	void logappend(const QString &line);
	void tokenRejected();
	// status/action 用 int 传，避免头文件把 update:: 枚举暴露给 moc
	// status: 0=Ok 1=SignatureInvalid 2=NetworkFailed 3=PolicyInvalid
	// action: 0=None 1=Optional 2=Forced
	// url/sha256/size 一并带出：界面点「立即更新」时直接用，不必再查一次
	void updateChecked(int status, int action, const QString& latest,
	                   const QString& notes, const QString& error,
	                   const QString& url, const QString& sha256, quint64 size);
	// 下载进度：0~100，-1 表示总量未知
	void downloadProgress(int percent);
	void downloadFinished(bool ok, const QString& error);
private:
	ClientApp* m_app;
	bool m_inited = false;   // 是否已 init（首次连接时自动初始化）

	// ---- 并发边界（防重入 / 退出清理）----
	// check/update 各自防重入：否则连点按钮会叠起 N 个线程，
	// 结果互相覆盖 UI 状态，下载并发还会写同一个文件。
	std::atomic<bool> m_checkBusy{ false };
	std::atomic<bool> m_downloadBusy{ false };
	std::atomic<bool> m_dlCancel{ false };
	QPointer<QThread> m_dlThread;   // 线程结束后 deleteLater 会把它置空
};
