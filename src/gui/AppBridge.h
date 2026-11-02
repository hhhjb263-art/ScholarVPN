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
	// 流量统计（采样用，原子量跨线程读取安全）
	uint64_t rx_bytes() const { return m_app->rx_bytes(); }   // 下载累计
	uint64_t tx_bytes() const { return m_app->tx_bytes(); }   // 上传累计

	// 分流模式：读运行时状态 / 更新运行时状态（落盘由 GUI 写 config.ini）
	bool routing_split() const { return m_app->routing_split(); }
	void set_routing_split(bool split) { m_app->set_routing_split(split); }

	// 强制更新 / 受管服务状态不允许使用时禁止连接（界面禁用之外的第二道闸门）
	void set_update_blocked(bool blocked) { m_app->set_update_blocked(blocked); }
	void set_service_blocked(bool blocked) { m_app->set_service_blocked(blocked); }

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

	// ---- 受管服务（busy 与 check_update 同款防重入）----
	// 模式选择（设置页「自建 / 使用服务方」单选）：写盘 + 广播 + 立即联动。
	// managed：同步状态并拉列表填卡；off：解除服务闸门（自建不受约束）。
	void set_service_mode(bool managed);
	// 状态同步：启动时 / 设置页手动刷新。结果经 serviceChecked 回 GUI 线程。
	void check_service();
	// 申请/换发试用（用户显式点击）。结果经 serviceRegistered。
	void register_service();
	// 拉取受管服务器列表（注册成功后由 GUI 触发）。结果经 serviceServers。
	void apply_server_list();
	// GUI 在收到 serviceServers 后取回列表（线程写入 / GUI 线程取走，互斥保护）
	std::vector<service::ManagedServer> take_managed_servers();

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

	// ---- 受管服务 ----
	// blocked: 1=禁止连接（试用到期/超量/被拒）；reason 为界面文案。
	// error 非空 = 本次同步失败（网络/验签），blocked 恒为 0（查不到→放行）。
	void serviceChecked(int blocked, const QString& reason, const QString& fp,
	                    const QString& clientId, const QString& status,
	                    qulonglong expireAt, qulonglong quotaBytes,
	                    qulonglong usedBytes, const QString& error);
	// ok=1 时 token 有效（注册响应才有）；expireAt/quotaBytes 一并带出供落盘
	void serviceRegistered(int ok, const QString& fp, const QString& clientId,
	                       const QString& token, const QString& status,
	                       qulonglong expireAt, qulonglong quotaBytes,
	                       const QString& error);
	// count = 已取回的受管服务器数（take_managed_servers 取走）
	void serviceServers(int count, const QString& error);
	// 模式切换广播：1=managed（卡片由 serviceServers 异步填回）0=off（主窗口撤受管卡片）
	void serviceModeChanged(int managed);
private:
	ClientApp* m_app;
	bool m_inited = false;   // 是否已 init（首次连接时自动初始化）

	// ---- 并发边界（防重入 / 退出清理）----
	// check/update 各自防重入：否则连点按钮会叠起 N 个线程，
	// 结果互相覆盖 UI 状态，下载并发还会写同一个文件。
	std::atomic<bool> m_checkBusy{ false };
	std::atomic<bool> m_downloadBusy{ false };
	// 凭据类操作（状态同步/申请试用）与列表拉取分开防重入：
	// 模式切换到 managed 会连调 check + list，共用一个标志会把第二个吞掉
	std::atomic<bool> m_svcCheckBusy{ false };
	QTimer* m_svcTimer = nullptr;   // 受管状态心跳（需求 3：启动即同步+5min 轮询）
	std::atomic<bool> m_svcListBusy{ false };
	std::atomic<bool> m_dlCancel{ false };
	QPointer<QThread> m_dlThread;   // 线程结束后 deleteLater 会把它置空
	// 受管服务器列表暂存：apply_server_list 线程写入，GUI 线程 take 走
	std::mutex m_svcMutex;
	std::vector<service::ManagedServer> m_pendingServers;
};
