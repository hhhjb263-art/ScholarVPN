#include "AppBridge.h"
#include "util/utf.h" 
#include "update/update_checker.h"
#include "update/update_fetcher.h"   // update::download_file
#include "update/update_install.h"
#include "version.h"

#include <QPointer>
#include <QDebug>
#include <QStandardPaths>
#include <QSettings>
#include <QThread>

#if defined(_DEBUG)
#include <crtdbg.h>
#include <QMessageBox>
// 分步堆自检：断在哪一步，损坏就发生在上一步与其之间。
// 失败时弹窗（_CrtDbgReport 只写调试输出，用户经常看不到），
// 弹窗文字就是定位信息——把它发给开发者。
#define CHECK_HEAP_STEP(what) do { \
    if (!_CrtCheckMemory()) { \
        QMessageBox __hb(QMessageBox::Critical, QStringLiteral("HEAP CORRUPTED"), \
            QStringLiteral("堆损坏点: %1（把这条信息完整发我）").arg(QStringLiteral(what)), \
            QMessageBox::Ok); \
        __hb.exec(); \
        __debugbreak(); \
    } \
} while (0)
#else
#define CHECK_HEAP_STEP(what) do {} while (0)
#endif
AppBridge::AppBridge(QObject* parent)
	: QObject(parent), m_app(new ClientApp)
{
	// ClientApp 回调在内部 worker 线程触发 → 这里 emit 信号；
	// 信号连接的槽默认 AutoConnection：跨线程自动 Queued，UI 槽天然安全。
	m_app->set_state_callback([this](ConnState s) {
		emit stateChanged(s);
	});
	m_app->set_connected_callback([this](const std::string& ip) {
		emit connected(QString::fromStdString(ip));
	});
	m_app->set_log_callback([this](const std::string& line) {
		emit logappend(QString::fromStdString(line));
	});
	m_app->set_register_token_rejected_callback([this]() {
		emit tokenRejected();
	});
}

AppBridge::~AppBridge()
{
	// 退出清理：先取消下载线程再 stop。
	// wait(3s)：正常网络下取消标志会在下一个数据块间隔内生效；
	// 超时只能靠进程退出由 OS 回收——不用 QThread::terminate，
	// 被 terminate 的线程持有的 OpenSSL 会话状态不可控。
	if (m_dlThread && m_dlThread->isRunning())
	{
		m_dlCancel.store(true);
		m_dlThread->wait(3000);
	}
	m_app->stop();
	delete m_app;
}

void AppBridge::start()
{
	// 首次连接先 init（读 config / 身份密钥 / 建 Wintun 网卡 / 路由），
	// 否则 m_app->start() 会因为缺少初始化而连接失败
	if (!m_inited) {
		if (!m_app->init()) {
			emit logappend(QStringLiteral("初始化失败：请检查 config.ini、密钥与管理员权限"));
			return;                 // 失败后可再次点击重试
		}
		m_inited = true;
	}
	m_app->start();
}

void AppBridge::stop()
{
	m_app->stop();
}

void AppBridge::connect_to_server(const ServerEntry& entry)
{
	// 首次连接先 init（config / 身份密钥 / 网卡 / 路由）
	if (!m_inited) {
		if (!m_app->init()) {
			emit logappend(QStringLiteral("初始化失败：请检查 config.ini、密钥与管理员权限"));
			return;
		}
		m_inited = true;
	}
	// 切换目标服务器及其各自的 ClientID/RegisterToken，然后连接
	m_app->set_server(entry);
	m_app->start();
}

// 异步检查更新。
// 用 QThread::create + QPointer：线程可能比窗口活得久（用户关窗时还在拉取），
// QPointer 为空就直接放弃 emit，避免访问已销毁对象。
void AppBridge::check_update()
{
	// 防重入：检查进行中再触发直接忽略（连点按钮会叠起 N 个线程）。
	// 早退路径必须把 busy 复位，否则之后永远查不了。
	if (m_checkBusy.exchange(true))
	{
		return;
	}
	const QString iniPath = QString::fromStdString(
		narrow(cfg_path_join(cfg_app_dir(), CS("config.ini"))));
	QSettings st(iniPath, QSettings::IniFormat);
	const QString policy = st.value(QStringLiteral("Update/PolicyURL")).toString().trimmed();
	const QString sigUrl = st.value(QStringLiteral("Update/SigURL")).toString().trimmed();
	QString pubkey = st.value(QStringLiteral("Update/PublicKey")).toString();
	// INI 值只能是单行，公钥按「SPKI DER 的 base64」存储；
	// 含 -----BEGIN 的是完整 PEM（也接受）。统一转成 OpenSSL 能吃的 PEM。
	if (!pubkey.isEmpty() && !pubkey.contains(QStringLiteral("BEGIN")))
	{
		const QByteArray der = QByteArray::fromBase64(pubkey.toUtf8());
		const QString b64 = QString::fromUtf8(der.toBase64());   // 重新按 64 列折行
		QString pem = QStringLiteral("-----BEGIN PUBLIC KEY-----\n");
		for (int i = 0; i < b64.size(); i += 64)
		{
			pem += b64.mid(i, 64) + QLatin1Char('\n');
		}
		pem += QStringLiteral("-----END PUBLIC KEY-----\n");
		pubkey = pem;
	}

	// 未配置 = 功能未启用，**不算失败**。
	// 这一条很关键：默认配置必须放行，否则一升级就把所有用户锁死。
	if (policy.isEmpty() || pubkey.isEmpty())
	{
		emit updateChecked(static_cast<int>(update::CheckStatus::NetworkFailed),
		                   static_cast<int>(update::Action::None),
		                   QString(), QString(),
		                   QStringLiteral("更新检查未启用"),
		                   QString(), QString(), 0);
		return;
	}
	m_checkBusy.store(false);

#if defined(_WIN32)
	const QString osTag = QStringLiteral("win-x64");
#else
	const QString osTag = QStringLiteral("linux-x64");
#endif
	const QString current = QStringLiteral(SCHOLARVPN_VER_STRING);
	const QString sigFinal = sigUrl.isEmpty() ? (policy + QStringLiteral(".sig")) : sigUrl;

	QPointer<AppBridge> self(this);
	QThread* th = QThread::create([self, policy, sigFinal, pubkey, osTag, current]() {
		const auto r = update::check(policy.toStdString(), sigFinal.toStdString(),
		                             pubkey.toStdString(), osTag.toStdString(),
		                             current.toStdString(), 5000);
		qDebug().noquote() << "[Update][check] status =" << status_name(r.status)
		                   << "action =" << action_name(r.decision.action)
		                   << "latest =" << r.decision.policy.latest
		                   << "err =" << r.error;
#if defined(_DEBUG)
		// 线程内堆自检（此时无并发）：通过而 GUI 侧 _CrtCheckMemory 报坏，
		// 则 GUI 侧是竞态误报——check 线程退出时的清理（TLS/Qt 事件数据）
		// 也在碰堆，与 GUI 线程的 _CrtCheckMemory 并发会互相干扰。
		if (!_CrtCheckMemory())
		{
			_CrtDbgReport(_CRT_ERROR, __FILE__, __LINE__, nullptr,
			              "heap corrupted INSIDE check thread (after update::check)");
			__debugbreak();
		}
#endif
		if (self.isNull())
		{
			return;
		}
		// 跨线程 emit：Qt 自动走队列连接，槽在 GUI 线程执行
		emit self->updateChecked(static_cast<int>(r.status),
		                         static_cast<int>(r.decision.action),
		                         QString::fromStdString(r.decision.policy.latest),
		                         QString::fromStdString(r.decision.policy.notes),
		                         QString::fromStdString(r.error),
		                         QString::fromStdString(r.decision.policy.url),
		                         QString::fromStdString(r.decision.policy.sha256),
		                         static_cast<quint64>(r.decision.policy.size));
	});
	connect(th, &QThread::finished, th, &QThread::deleteLater);
	// busy 复位挂在 finished 上（receiver=this：对象销毁后不会再回调）
	connect(th, &QThread::finished, this, [this]() { m_checkBusy.store(false); });
	th->start();
}

namespace {

struct ProgressCtx {
	QPointer<AppBridge> self;
	int lastPct = -1;
};

// 进度回调跑在下载线程里，必须节流：每个数据块都 emit 会把事件队列淹掉，
// 界面反而卡顿。只在百分比变化时发一次。
void on_download_progress(std::uint64_t received, std::uint64_t total, void* user)
{
	auto* ctx = static_cast<ProgressCtx*>(user);
	if (ctx == nullptr || ctx->self.isNull()) return;
	const int pct = (total > 0) ? static_cast<int>(received * 100 / total) : -1;
	if (pct == ctx->lastPct) return;
	ctx->lastPct = pct;
	emit ctx->self->downloadProgress(pct);
}

} // namespace

// 下载 + 启动安装器。
// 先 stop()：安装包要走物理网卡，且安装器要替换本程序的文件，
// 不能依赖"自己要替换的那条隧道"。
void AppBridge::download_and_install(const QString& url, const QString& sha256,
                                     quint64 size, const QString& version)
{
	// 防重入：并发下载会写同一个文件，且结果互相覆盖 UI
	if (m_downloadBusy.exchange(true))
	{
		return;
	}
	m_dlCancel.store(false);
	CHECK_HEAP_STEP("enter download_and_install");
	m_app->stop();
	CHECK_HEAP_STEP("after m_app->stop()");

	// dest 用系统临时目录（Qt TempLocation：Windows=%TEMP%，Linux=/tmp）：
	// 安装包是"下载->校验->安装->删除"的临时文件，而 exe 目录
	// （/opt/scholarvpn 或 Program Files）运行时对普通用户不可写——
	// 用户实测"无法写入目标文件"。全程 QString（Qt 堆）。
	QString fileName = url;
	{
		const int slash = fileName.lastIndexOf(QLatin1Char('/'));
		fileName = (slash >= 0) ? fileName.mid(slash + 1) : fileName;
	}
	CHECK_HEAP_STEP("after fileName");

	const QString dest = QStandardPaths::writableLocation(QStandardPaths::TempLocation)
	    + QStringLiteral("/ScholarVPN-") + version + QStringLiteral("-") + fileName;
	const std::string destStd = dest.toStdString();
	CHECK_HEAP_STEP("after dest");

	QPointer<AppBridge> self(this);
	QThread* th = QThread::create([self, url, sha256, size, destStd]() {
		ProgressCtx ctx{ self, -1 };
		const auto r = update::download_file(url.toStdString(), destStd,
		                                     sha256.toStdString(), size,
		                                     &on_download_progress, &ctx);
		if (self.isNull())
		{
			return;
		}
		if (!r.ok)
		{
			emit self->downloadFinished(false, QString::fromStdString(r.error));
			return;
		}
		QString err;
		// 统一安装入口：Windows=Inno 静默派发；Linux=解包 tar.gz + pkexec 安装
		// （阻塞在下载线程等 polkit 认证，GUI 只显示状态）
		if (!update::install_package(QString::fromStdString(r.path), err))
		{
			emit self->downloadFinished(false, err);
			return;
		}
		// Windows：安装器会 CloseApplications 关掉本程序；Linux：/opt 已被新版取代
		emit self->downloadFinished(true, QString());
	});
	connect(th, &QThread::finished, th, &QThread::deleteLater);
	connect(th, &QThread::finished, this, [this]() { m_downloadBusy.store(false); });
	m_dlThread = th;   // 析构时据此取消并等待
	th->start();
}
