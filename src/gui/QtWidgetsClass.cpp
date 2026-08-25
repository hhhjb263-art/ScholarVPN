#include "QtWidgetsClass.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QScrollArea>
#include <QPushButton>
#include <QSettings>
#include <QFont>
#include <QDialog>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QRegularExpression>

QtWidgetsClass::QtWidgetsClass(QWidget* parent)
	: QWidget(parent)
{
	ui.setupUi(this);
	this->resize(430, 750);
	this->setWindowTitle("ScholarVPN");

	QFont win11Font("Segoe UI", 9);
	this->setFont(win11Font);

	auto* topBar = new QHBoxLayout;
	topBar->setContentsMargins(12, 12, 12, 4);

	QPushButton* btn_add = new QPushButton("+ 添加服务器", this);
	btn_add->setFixedSize(120, 32);
	btn_add->setStyleSheet(R"(
	QPushButton{
		background-color:#f1f1f1;
		border:1px solid #dcdcdc;
		border-radius:8px;
		color:#111111;
	}
	QPushButton:hover{background-color:#e5e5e5;}
	QPushButton:pressed{background-color:#d8d8d8;}
	)");
	topBar->addStretch();
	topBar->addWidget(btn_add);

	m_scroll = new QScrollArea(this);
	m_scroll->setWidgetResizable(true);
	m_scroll->setFrameShape(QFrame::NoFrame);
	m_scroll->setStyleSheet(R"(
	QScrollArea{background-color:#f7f7f7; border:none;}
	QScrollBar:vertical{
		width:8px;
		background:#f7f7f7;
		margin:2px;
	}
	QScrollBar::handle:vertical{
		background:#c4c4c4;
		min-height:24px;
		border-radius:4px;
	}
	QScrollBar::handle:vertical:hover{background:#a8a8a8;}
	QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical{height:0px;}
	)");

	m_cardContainer = new QWidget;
	m_cardContainer->setStyleSheet("background-color:#f7f7f7;");
	m_cardLayout = new QVBoxLayout(m_cardContainer);
	m_cardLayout->setSpacing(14);
	m_cardLayout->setContentsMargins(12, 12, 12, 12);
	m_cardLayout->addStretch();            // 卡片靠顶部排布

	m_scroll->setWidget(m_cardContainer);

	auto* main = new QVBoxLayout(this);
	main->setContentsMargins(0, 0, 0, 0);
	main->addLayout(topBar);
	main->addWidget(m_scroll, 1);

	m_bridge = new AppBridge;
	m_thread_start = new QThread(this);
	m_bridge->moveToThread(m_thread_start);
	m_thread_start->start();

	connect(m_bridge, &AppBridge::connected, this, [this](const QString& ip) {
		if (m_activeCard >= 0 && m_activeCard < m_cardVips.size())
			m_cardVips[m_activeCard]->setText("内网IP: " + ip);
	});

	connect(m_bridge, &AppBridge::stateChanged, this, [this](ConnState s) {
		m_state = s;
		if (m_activeCard < 0 || m_activeCard >= static_cast<int>(m_cardVips.size()))
			return;
		QLabel* v = m_cardVips[m_activeCard];
		if (s == ConnState::Stopped || s == ConnState::Reconnecting)
			v->setText("内网IP: --");
		QPushButton* b = m_cardBtns[m_activeCard];
		b->setText(s == ConnState::Stopped ? "连接" : (s == ConnState::Connecting ? "连接中..." : "断开"));
		b->setStyleSheet(s == ConnState::Stopped ? R"(
			QPushButton{
				background-color:#0078d4; color:white; border:none; border-radius:8px;
			}
			QPushButton:hover{background-color:#0086ec;}
			QPushButton:pressed{background-color:#0069bc;}
			)" : R"(
			QPushButton{
				background-color:#d83b01; color:white; border:none; border-radius:8px;
			}
			QPushButton:hover{background-color:#e54910;}
			QPushButton:pressed{background-color:#c03400;}
			)");
	});

	connect(btn_add, &QPushButton::clicked, this, &QtWidgetsClass::write_edit);

	Read_iniFile();   // 读 config，为每台服务器建卡
}

QtWidgetsClass::~QtWidgetsClass()
{
	if (m_thread_start) {
		m_thread_start->quit();
		m_thread_start->wait();
	}
	delete m_bridge;
	delete m_cfg;
}

void QtWidgetsClass::clear_cards()
{
	for (QFrame* f : m_cards) {
		m_cardLayout->removeWidget(f);
		f->deleteLater();
	}
	m_cards.clear();
	m_cardNames.clear();
	m_cardIps.clear();
	m_cardVips.clear();
	m_cardBtns.clear();
}

// 读取 config.ini，为每台已配置的服务器建一张卡片（无配置则空界面，由手动添加）
void QtWidgetsClass::Read_iniFile()
{
	delete m_cfg;
	m_cfg = new Config(Config::GetAppDataRoaming() + L"\\ScholarVPN\\config.ini",
		Config::GetAppDataRoaming() + L"\\ScholarVPN");
	ClientConfig cc;
	clear_cards();   // 先清旧卡

	if (m_cfg->LoadClientConfig(cc)) {
		// 主服务器 IP（Debug 优先 DebugServerIP，用于兼容旧字段）
#ifdef _DEBUG
		m_serverIp = QString::fromStdWString(cc.DebugServerIP.empty() ? cc.ServerIP : cc.DebugServerIP);
#else
		m_serverIp = QString::fromStdWString(cc.ServerIP);
#endif
		for (const auto& s : cc.servers)
			create_card(s);
	} else {
		m_serverIp = QStringLiteral("--");
	}
}

void QtWidgetsClass::write_edit()
{
	QDialog dia(this);
	dia.resize(380, 420);          
	dia.setWindowTitle("添加服务器");
	QVBoxLayout* lay = new QVBoxLayout(&dia);
	lay->setContentsMargins(24, 24, 24, 24);
	lay->setSpacing(14);

	QLabel* ip = new QLabel("IP: ");
	QLineEdit* input_ip = new QLineEdit;
	input_ip->setPlaceholderText("例:127.0.0.1");

	QLabel* client_id = new QLabel("ClientID: ");
	QLineEdit* input_id = new QLineEdit;
	input_id->setPlaceholderText("Unique ClientID");

	QLabel* token = new QLabel("RegisterToken: ");
	QLineEdit* input_token = new QLineEdit;
	input_token->setPlaceholderText("注册令牌");

	// 服务器身份公钥（多服务器各自独立验签；可选，留空则使用内置公钥）
	QLabel* pubkey_label = new QLabel("服务器公钥(可选,留空则使用内置公钥): ");
	QPlainTextEdit* input_pubkey = new QPlainTextEdit;
	input_pubkey->setPlaceholderText("粘贴该服务器 server_sig.pub 完整内容（含 BEGIN/END 行）");
	input_pubkey->setFixedHeight(130); 

	QString edit_Style = R"(
QLineEdit{
	border:1px solid #dcdcdc;
	border-radius:8px;
	padding:6px 10px;
	background:#ffffff;
}
QLineEdit:focus{border:1px solid #0078d4;}
	)";
	input_ip->setStyleSheet(edit_Style);
	input_id->setStyleSheet(edit_Style);
	input_token->setStyleSheet(edit_Style);

	// Win11风格 QPlainTextEdit
	input_pubkey->setStyleSheet(R"(
QPlainTextEdit{
	border:1px solid #dcdcdc;
	border-radius:8px;
	padding:8px 10px;
	background:#ffffff;
	font-family:Consolas, monospace;
	font-size:10pt;
}
QPlainTextEdit:focus{
	border:1px solid #0078d4;
}
QScrollBar:vertical{
	width:8px;
	background:#f7f7f7;
	border-radius:4px;
}
QScrollBar::handle:vertical{
	background:#cccccc;
	border-radius:4px;
}
	)");

	QPushButton* btn_OK = new QPushButton("确认");
	QPushButton* btn_NO = new QPushButton("取消");
	QHBoxLayout* btnLayout = new QHBoxLayout();
	btnLayout->addStretch();
	btnLayout->addWidget(btn_OK);
	btnLayout->addWidget(btn_NO);

	btn_OK->setFixedHeight(32);
	btn_NO->setFixedHeight(32);

	QString btnOkStyle = R"(
QPushButton{
	background-color:#0078d4;
	color:white;
	border:none;
	border-radius:8px;
}
QPushButton:hover{background-color:#0086ec;}
QPushButton:pressed{background-color:#0069bc;}
	)";
	QString btnNoStyle = R"(
QPushButton{
	background-color:#f1f1f1;
	color:#111111;
	border:1px solid #dcdcdc;
	border-radius:8px;
}
QPushButton:hover{background-color:#e5e5e5;}
QPushButton:pressed{background-color:#d8d8d8;}
	)";

	btn_OK->setStyleSheet(btnOkStyle);
	btn_NO->setStyleSheet(btnNoStyle);

	lay->addWidget(ip);
	lay->addWidget(input_ip);
	lay->addWidget(client_id);
	lay->addWidget(input_id);
	lay->addWidget(token);
	lay->addWidget(input_token);
	lay->addWidget(pubkey_label);
	lay->addWidget(input_pubkey);
	lay->addStretch();
	lay->addLayout(btnLayout);

	connect(btn_OK, &QPushButton::clicked, &dia, &QDialog::accept);
	connect(btn_NO, &QPushButton::clicked, &dia, &QDialog::reject);

	if (dia.exec() != QDialog::Accepted)
		return;

	const QString newIp = input_ip->text().trimmed();
	const QString newId = input_id->text().trimmed();
	const QString newTok = input_token->text().trimmed();
	if (newIp.isEmpty()) {
		QMessageBox::warning(this, "提示", "服务器 IP 不能为空");
		return;
	}
	if (newId.isEmpty()) {
		QMessageBox::warning(this, "提示", "ClientID 不能为空");
		return;
	}

	QString pubkeyB64 = input_pubkey->toPlainText();
	pubkeyB64.remove(QRegularExpression("-----BEGIN[^-]*-----"));
	pubkeyB64.remove(QRegularExpression("-----END[^-]*-----"));
	pubkeyB64.remove(QRegularExpression("\\s"));
	if (pubkeyB64.length() > 44)
		pubkeyB64.clear();

	// 追加到 [ServerN] 节（真正多服务器，含各自身份）
	const QString inipath = QString::fromStdWString(
		Config::GetAppDataRoaming() + L"\\ScholarVPN\\config.ini");
	QSettings settings(inipath, QSettings::IniFormat);

	const int count = settings.value("Server/Count", 0).toInt();
	const int idx = count + 1;
	settings.setValue(QString("Server%1/Name").arg(idx), QString("computer%1").arg(idx));
	settings.setValue(QString("Server%1/ServerIP").arg(idx), newIp);
	settings.setValue(QString("Server%1/ServerPort").arg(idx), 51820);
	settings.setValue(QString("Server%1/ClientID").arg(idx), newId);
	settings.setValue(QString("Server%1/RegisterToken").arg(idx), newTok);
	settings.setValue(QString("Server%1/ServerPubKey").arg(idx), pubkeyB64);
	settings.setValue("Server/Count", idx);
	settings.sync();   // 防止  QSettings  默认延迟到析构才保存

	Read_iniFile();
}

void QtWidgetsClass::create_card(const ServerEntry& entry)
{
	int idx = 0;
	const QString name = entry.Name.empty() ? QStringLiteral("computer%1").arg(idx++) : QString::fromStdWString(entry.Name);
	const QString ip   = QString::fromStdWString(entry.ServerIP);

	QFrame* m_Frame = new QFrame;
	m_Frame->setFixedHeight(150);
	m_Frame->setObjectName("serverCard");
	m_Frame->setStyleSheet(R"(
	QFrame#serverCard{
		background-color:#ffffff;
		border-radius:12px;
		border:none;
	}
	)");

	QLabel* m_label_name = new QLabel(m_Frame);
	m_label_name->setText(name);
	m_label_name->setGeometry(16, 14, 200, 24);
	m_label_name->setStyleSheet("font-size:11pt; color:#1a1a1a;");

	QLabel* m_label_ip = new QLabel(m_Frame);
	m_label_ip->setGeometry(16, 46, 200, 24);
	m_label_ip->setText("IP: " + ip);          // 每张卡显示自己的服务器 IP
	m_label_ip->setStyleSheet("color:#444444;");

	QLabel* m_label_vip = new QLabel(m_Frame);
	m_label_vip->setGeometry(220, 46, 260, 24);
	m_label_vip->setText("内网IP: --");
	m_label_vip->setStyleSheet("color:#444444;");

	QPushButton* m_pushBtn = new QPushButton(m_Frame);
	m_pushBtn->setText("连接");
	m_pushBtn->setGeometry(30, 85, 325, 55);
	m_pushBtn->setStyleSheet(R"(
	QPushButton{
		background-color:#0078d4;
		color:white;
		border:none;
		border-radius:8px;
	}
	QPushButton:hover{background-color:#0086ec;}
	QPushButton:pressed{background-color:#0069bc;}
	)");

	// toggle：未连接 → 连这台服务器；已连接 → 断开（不会重连）
	const int cardIndex = static_cast<int>(m_cards.size());   // 本卡片索引
	connect(m_pushBtn, &QPushButton::clicked, this, [this, entry, cardIndex]() {
		if (m_state == ConnState::Stopped) {
			m_activeCard = cardIndex;          // 标记本卡片为当前活动卡片
			// 必须投递到 bridge 所在线程（moveToThread 只作用于信号槽连接，直接调用
			// 会在 GUI 线程同步执行 init()/建网卡/restore() 等重型操作 → 界面卡死无响应）
			QMetaObject::invokeMethod(m_bridge, [this, entry]() {
				m_bridge->connect_to_server(entry);
			}, Qt::QueuedConnection);
		} else {
			// 断开同样投递到 bridge 线程，避免 stop() 同步执行卡 GUI
			QMetaObject::invokeMethod(m_bridge, [this]() {
				m_bridge->stop();
			}, Qt::QueuedConnection);
		}
	});

	m_cardLayout->insertWidget(m_cardLayout->count() - 1, m_Frame);

	m_cards.append(m_Frame);
	m_cardNames.append(m_label_name);
	m_cardIps.append(m_label_ip);
	m_cardVips.append(m_label_vip);
	m_cardBtns.append(m_pushBtn);
	m_cardServers.append(entry);
}

void QtWidgetsClass::edit_card()
{
	
}
