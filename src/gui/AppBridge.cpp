#include "AppBridge.h"
#include "../service/service_bootstrap.h"   // 发行版内置接入点
#include "util/utf.h"
#include "QtCfg.h"   // toQString（cfgstr 与 QString 互转）
#include "../Config.h"  // scholini::Ini*（config.ini 的 INI 原语）

using namespace scholini;
#include "update/update_checker.h"
#include "update/update_fetcher.h"   // update::download_file
#include "update/update_install.h"
#include "version.h"

#include <QPointer>
#include <QDebug>
#include <QStandardPaths>
#include <QSettings>
#include <QThread>
#include <QTimer>

#include <ctime>

// 历史说明：此处曾有 Debug 专用的分步堆自检诊断宏（全堆遍历）。
// 多线程下后台线程持续分配，GUI 线程遍历整个堆与之并发，产生竞态误报——
// Debug 构建频繁弹堆断言即此（2026-10-31 移除）。真实堆越界（update_fetcher
// 响应头缓冲）已另行修复；若再疑堆损坏，用 Application Verifier + 页堆定位，
// 不要恢复全堆遍历式自检。
AppBridge::AppBridge(QObject* parent)
	: QObject(parent), m_app(new ClientApp)
{
	// 受管状态心跳（2026-11-02 需求 3）：启动 30 秒后首次同步，之后每 5 分钟
	// 轮询一次授权服务器（低频小请求，不需要长连接）。运行中若被判超限，
	// 服务端会切断会话；这里把闸门置位，防止托盘/命令行绕过界面重连。
	m_svcTimer = new QTimer(this);
	QObject::connect(m_svcTimer, &QTimer::timeout, this, [this]() {
		if (!m_svcCheckBusy.load())
		{
			check_service();
		}
	});
	m_svcTimer->start(5 * 60 * 1000);
	QTimer::singleShot(30 * 1000, this, [this]() {
		if (!m_svcCheckBusy.load())
		{
			check_service();
		}
	});
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
	const cfgstr iniPath = cfg_path_join(cfg_app_dir(), CS("config.ini"));
	const QString policy = toQString(IniGetStr(iniPath, CS("Update"), CS("PolicyURL"), CS("")));
	const QString sigUrl = toQString(IniGetStr(iniPath, CS("Update"), CS("SigURL"), CS("")));
	QString pubkey = toQString(IniGetStr(iniPath, CS("Update"), CS("PublicKey"), CS("")));
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
		m_checkBusy.store(false);   // 早退也要复位，见函数入口的防重入注释
		return;
	}
	// busy 保持到检查线程 finished，由下方回调复位；若在这里提前复位，
	// 网络检查期间再点按钮就会叠起第二个线程（防重入失效）。

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
	m_app->stop();

	// dest 用系统临时目录（Qt TempLocation：Windows=%TEMP%，Linux=/tmp）：
	// 安装包是"下载->校验->安装->删除"的临时文件，而 exe 目录
	// （/opt/scholarvpn 或 Program Files）运行时对普通用户不可写——
	// 用户实测"无法写入目标文件"。全程 QString（Qt 堆）。
	QString fileName = url;
	{
		const int slash = fileName.lastIndexOf(QLatin1Char('/'));
		fileName = (slash >= 0) ? fileName.mid(slash + 1) : fileName;
	}

	const QString dest = QStandardPaths::writableLocation(QStandardPaths::TempLocation)
	    + QStringLiteral("/ScholarVPN-") + version + QStringLiteral("-") + fileName;
	const std::string destStd = dest.toStdString();

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

// ===========================================================================
// 受管服务（受管试用 / 状态同步 / 服务器列表下发）
// ===========================================================================

namespace {

// config.ini [Service] 配置（GUI 线程读取后按值传进工作线程）
struct ServiceCfg {
	bool enabled = false;
	QString baseUrl;    // broker 基地址（无尾斜杠约定：客户端拼接带 / 的路径）
	QString pubKey;     // service 签名公钥（SPKI DER base64 单行）
	QString fpOld;      // 上次记录的指纹（比对用）
};

ServiceCfg read_service_cfg()
{
	const cfgstr iniPath = cfg_path_join(cfg_app_dir(), CS("config.ini"));
	ServiceCfg sc;
	// 发行版内置接入点（service_bootstrap.h）：config 留空 = 用内置；
	// config 覆盖仅用于测试与换址迁移。是否启用由 [Service] Mode 决定，
	// 这里只保证「选了使用服务方就一定有接入点」。
	sc.baseUrl = toQString(IniGetStr(iniPath, CS("Service"), CS("ServiceURL"), CS("")));
	if (sc.baseUrl.isEmpty())
	{
		sc.baseUrl = QString::fromLatin1(service::kServiceBaseUrl);
	}
	while (sc.baseUrl.endsWith(QLatin1Char('/')))
	{
		sc.baseUrl.chop(1);
	}
	sc.pubKey = toQString(IniGetStr(iniPath, CS("Service"), CS("PublicKey"), CS("")));
	if (sc.pubKey.isEmpty())
	{
		sc.pubKey = QString::fromLatin1(service::kServicePubKeyB64);
	}
	sc.fpOld = toQString(IniGetStr(iniPath, CS("Service"), CS("Fp"), CS("")));
	sc.enabled = !sc.baseUrl.isEmpty() && !sc.pubKey.isEmpty();
	return sc;
}

// 三个服务线程共同的结果发射：汇总凭据 + 闸门判定
void emit_service_result(AppBridge* self, const service::Credentials& c,
                         const QString& fp, bool withToken)
{
	const service::Verdict v = service::evaluate(
		c, static_cast<std::uint64_t>(std::time(nullptr)));
	// 闸门联动：blocked 时置位 ClientApp 的服务闸门（start() 直接拒绝连接），
	// 解除时同步清除——心跳周期性刷新，保证运行中状态与服务端一致。
	if (self)
	{
		self->set_service_blocked(v.blocked);
	}
	if (withToken)
	{
		emit self->serviceRegistered(
			c.valid ? 1 : 0, fp, QString::fromStdString(c.client_id),
			QString::fromStdString(c.token), QString::fromStdString(c.status),
			static_cast<qulonglong>(c.expire_at),
			static_cast<qulonglong>(c.quota_bytes),
			QString::fromStdString(c.error));
	}
	else
	{
		emit self->serviceChecked(
			v.blocked ? 1 : 0, QString::fromStdString(v.reason), fp,
			QString::fromStdString(c.client_id), QString::fromStdString(c.status),
			static_cast<qulonglong>(c.expire_at),
			static_cast<qulonglong>(c.quota_bytes),
			static_cast<qulonglong>(c.used_bytes),
			QString::fromStdString(c.error));
	}
}

} // namespace

// 模式选择（设置页「自建 / 使用服务方」单选触发，GUI 线程调用）。
// 写盘 + 广播；managed 立即同步状态并拉列表（两个独立 busy，互不吞并），
// off 解除服务闸门——自建模式不受服务方约束，也不应再被锁在阻塞弹窗里。
void AppBridge::set_service_mode(bool managed)
{
	const cfgstr iniPath = cfg_path_join(cfg_app_dir(), CS("config.ini"));
	IniSetStr(iniPath, CS("Service"), CS("Mode"),
	          managed ? CS("managed") : CS("off"));
	emit serviceModeChanged(managed ? 1 : 0);
	if (managed)
	{
		check_service();
		apply_server_list();
	}
	else
	{
		set_service_blocked(false);
	}
}

// 状态同步：启动时 / 设置页「刷新状态」。
// busy 语义与 check_update 修复后一致：保持到线程 finished 由回调复位。
void AppBridge::check_service()
{
	if (m_svcCheckBusy.exchange(true))
	{
		return;
	}
	const ServiceCfg sc = read_service_cfg();
	QPointer<AppBridge> self(this);
	QThread* th = QThread::create([self, sc]() {
		if (!sc.enabled)
		{
			if (!self.isNull())
			{
				emit self->serviceChecked(0, QStringLiteral("受管服务未启用"),
				                          QString(), QString(), QString(),
				                          0, 0, 0, QString());
			}
			return;
		}
		const service::MachineInfo info = service::collect_machine_info();
		const QString fp = QString::fromStdString(info.fp);
		const QString url = sc.baseUrl + QStringLiteral("/trial/status?fp=") + fp;
		const service::Credentials c = service::fetch_status(
			url.toStdString(), sc.pubKey.toStdString());
		if (self.isNull())
		{
			return;
		}
		emit_service_result(self, c, fp, false);
	});
	connect(th, &QThread::finished, th, &QThread::deleteLater);
	connect(th, &QThread::finished, this, [this]() { m_svcCheckBusy.store(false); });
	th->start();
}

// 申请/换发试用（用户显式点击）。响应携带明文令牌，GUI 落盘并触发列表下发。
void AppBridge::register_service()
{
	if (m_svcCheckBusy.exchange(true))
	{
		return;
	}
	const ServiceCfg sc = read_service_cfg();
	QPointer<AppBridge> self(this);
	QThread* th = QThread::create([self, sc]() {
		if (!sc.enabled)
		{
			if (!self.isNull())
			{
				emit self->serviceRegistered(0, QString(), QString(), QString(),
				                             QString(), 0, 0,
				                             QStringLiteral("受管服务未配置"));
			}
			return;
		}
		const service::MachineInfo info = service::collect_machine_info();
		const QString fp = QString::fromStdString(info.fp);
		const service::Credentials c = service::register_trial(
			(sc.baseUrl + QStringLiteral("/trial/register")).toStdString(),
			sc.pubKey.toStdString(), info);
		if (self.isNull())
		{
			return;
		}
		emit_service_result(self, c, fp, true);
	});
	connect(th, &QThread::finished, th, &QThread::deleteLater);
	connect(th, &QThread::finished, this, [this]() { m_svcCheckBusy.store(false); });
	th->start();
}

// 拉取受管服务器列表（注册成功后由 GUI 触发），暂存等 GUI take 走。
void AppBridge::apply_server_list()
{
	if (m_svcListBusy.exchange(true))
	{
		return;
	}
	const ServiceCfg sc = read_service_cfg();
	QPointer<AppBridge> self(this);
	QThread* th = QThread::create([self, sc]() {
		if (!sc.enabled)
		{
			if (!self.isNull())
			{
				emit self->serviceServers(0, QStringLiteral("受管服务未配置"));
			}
			return;
		}
		// 服务器列表受控下发：必须携带已登记的设备指纹（未申请试用 → 403）
		const QString listUrl = sc.baseUrl + QStringLiteral("/svc/server-list.ini?fp=") + sc.fpOld;
		std::string err;
		std::vector<service::ManagedServer> list = service::fetch_server_list(
			listUrl.toStdString(),
			(sc.baseUrl + QStringLiteral("/svc/server-list.ini.sig?fp=") + sc.fpOld).toStdString(),
			sc.pubKey.toStdString(), err);
		if (self.isNull())
		{
			return;
		}
		int count = 0;
		{
			std::lock_guard<std::mutex> lk(self->m_svcMutex);
			self->m_pendingServers = std::move(list);
			count = static_cast<int>(self->m_pendingServers.size());
		}
		emit self->serviceServers(count, QString::fromStdString(err));
	});
	connect(th, &QThread::finished, th, &QThread::deleteLater);
	connect(th, &QThread::finished, this, [this]() { m_svcListBusy.store(false); });
	th->start();
}

std::vector<service::ManagedServer> AppBridge::take_managed_servers()
{
	std::lock_guard<std::mutex> lk(m_svcMutex);
	return std::move(m_pendingServers);   // 取走后 m_pendingServers 留空
}
