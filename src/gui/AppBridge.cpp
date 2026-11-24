#include "AppBridge.h"
#include "../service/service_bootstrap.h"
#include "util/utf.h"
#include "QtCfg.h"
#include "../Config.h"

using namespace scholini;
#include "update/update_checker.h"
#include "update/update_fetcher.h"
#include "update/update_install.h"
#include "version.h"

#include <QPointer>
#include <QDebug>
#include <QStandardPaths>
#include <QSettings>
#include <QThread>
#include <QTimer>

#include <ctime>

AppBridge::AppBridge(QObject* parent)
	: QObject(parent), m_app(new ClientApp)
{
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
	m_app->set_state_callback([this](ConnState s) {
		emit stateChanged(s);
	});
	m_app->set_connected_callback([this](const std::string& ip) {
		emit connected(QString::fromStdString(ip));
	});
	m_app->set_log_callback([this](int level, const std::string& line) {
		emit logappend(level, QString::fromStdString(line));
	});
	m_app->set_register_token_rejected_callback([this]() {
		emit tokenRejected();
	});
}

AppBridge::~AppBridge()
{
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
	if (!m_inited) {
		if (!m_app->init()) {
			emit logappend(2, QStringLiteral("初始化失败：请检查 config.ini、密钥与管理员权限"));
			return;
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
	if (!m_inited) {
		if (!m_app->init()) {
			emit logappend(2, QStringLiteral("初始化失败：请检查 config.ini、密钥与管理员权限"));
			return;
		}
		m_inited = true;
	}
	m_app->set_server(entry);
	m_app->start();
}

void AppBridge::check_update()
{
	if (m_checkBusy.exchange(true))
	{
		return;
	}
	const cfgstr iniPath = cfg_path_join(cfg_app_dir(), CS("config.ini"));
	QString policy = toQString(IniGetStr(iniPath, CS("Update"), CS("PolicyURL"), CS("")));
	QString sigUrl = toQString(IniGetStr(iniPath, CS("Update"), CS("SigURL"), CS("")));
	QString pubkey = toQString(IniGetStr(iniPath, CS("Update"), CS("PublicKey"), CS("")));

	// 受管模式：更新策略由后台托管，不再依赖本地写死的 PolicyURL/SigURL
	const cfgstr svcMode = IniGetStr(iniPath, CS("Service"), CS("Mode"), CS(""));
	cfgstr svcBase = IniGetStr(iniPath, CS("Service"), CS("ServiceURL"), CS(""));
	if (svcBase.empty() && svcMode == CS("managed"))
	{
		// 与 read_service_cfg 一致：配置没填 ServiceURL 时用内置地址
		svcBase = cfg_from_utf8(service::kServiceBaseUrl);
	}
	if (svcMode == CS("managed") && !svcBase.empty())
	{
		QString base = toQString(svcBase);
		while (base.endsWith(QLatin1Char('/')))
		{
			base.chop(1);
		}
		policy = base + QStringLiteral("/svc/update-policy.ini");
		sigUrl = policy + QStringLiteral(".sig");
		qDebug().noquote() << "[Update][check] 使用后台托管策略:" << policy;
	}
	if (!pubkey.isEmpty() && !pubkey.contains(QStringLiteral("BEGIN")))
	{
		const QByteArray der = QByteArray::fromBase64(pubkey.toUtf8());
		const QString b64 = QString::fromUtf8(der.toBase64());
		QString pem = QStringLiteral("-----BEGIN PUBLIC KEY-----\n");
		for (int i = 0; i < b64.size(); i += 64)
		{
			pem += b64.mid(i, 64) + QLatin1Char('\n');
		}
		pem += QStringLiteral("-----END PUBLIC KEY-----\n");
		pubkey = pem;
	}

	if (policy.isEmpty() || pubkey.isEmpty())
	{
		emit updateChecked(static_cast<int>(update::CheckStatus::NetworkFailed),
		                   static_cast<int>(update::Action::None),
		                   QString(), QString(),
		                   QStringLiteral("更新检查未启用"),
		                   QString(), QString(), 0);
		m_checkBusy.store(false);
		return;
	}

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
	connect(th, &QThread::finished, this, [this]() { m_checkBusy.store(false); });
	th->start();
}

namespace {

struct ProgressCtx {
	QPointer<AppBridge> self;
	int lastPct = -1;
};

void on_download_progress(std::uint64_t received, std::uint64_t total, void* user)
{
	auto* ctx = static_cast<ProgressCtx*>(user);
	if (ctx == nullptr || ctx->self.isNull()) return;
	const int pct = (total > 0) ? static_cast<int>(received * 100 / total) : -1;
	if (pct == ctx->lastPct) return;
	ctx->lastPct = pct;
	emit ctx->self->downloadProgress(pct);
}

}

void AppBridge::download_and_install(const QString& url, const QString& sha256,
                                     quint64 size, const QString& version)
{
	if (m_downloadBusy.exchange(true))
	{
		return;
	}
	m_dlCancel.store(false);
	m_app->stop();

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
		if (!update::install_package(QString::fromStdString(r.path), err))
		{
			emit self->downloadFinished(false, err);
			return;
		}
		emit self->downloadFinished(true, QString());
	});
	connect(th, &QThread::finished, th, &QThread::deleteLater);
	connect(th, &QThread::finished, this, [this]() { m_downloadBusy.store(false); });
	m_dlThread = th;
	th->start();
}

namespace {

struct ServiceCfg {
	bool enabled = false;
	QString baseUrl;
	QString pubKey;
	QString fpOld;
};

ServiceCfg read_service_cfg()
{
	const cfgstr iniPath = cfg_path_join(cfg_app_dir(), CS("config.ini"));
	ServiceCfg sc;
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

void emit_service_result(AppBridge* self, const service::Credentials& c,
                         const QString& fp, bool withToken)
{
	const service::Verdict v = service::evaluate(
		c, static_cast<std::uint64_t>(std::time(nullptr)));
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

}

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
	return std::move(m_pendingServers);
}
