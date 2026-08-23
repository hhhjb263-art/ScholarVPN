#include "AppBridge.h"
#include "util/utf.h" 
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
