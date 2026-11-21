#include "QtWidgetsClass.h"
#include "QtCfg.h"
#include "util/utf.h"
#include "CenteredComboBox.h"
#include "version.h"
#include "platform/cidr.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QScrollArea>
#include <QPushButton>
#include <QSettings>
#include <QFont>
#include <QDialog>
#include <QCheckBox>
#include <QMessageBox>
#include <QInputDialog>
#include <QLineEdit>
#include <QTimer>
#include <QDir>
#include <QListWidget>
#include <QStackedWidget>
#include <QPlainTextEdit>
#include <QRadioButton>
#include <QRegularExpression>
#include <QStyle>
#include <QDateTime>

using namespace scholini;

namespace {
std::string svc_fmt_bytes(unsigned long long n)
{
    char buf[32] = { 0 };
    if (n >= 1024ull * 1024 * 1024)
        std::snprintf(buf, sizeof(buf), "%.1f GB", n / 1073741824.0);
    else if (n >= 1024ull * 1024)
        std::snprintf(buf, sizeof(buf), "%.0f MB", n / 1048576.0);
    else
        std::snprintf(buf, sizeof(buf), "%llu B", n);
    return buf;
}
}
#include<QComboBox>
#include <QApplication>
#include <QAction>
#include <QCoreApplication>
#include <QIcon>

QtWidgetsClass::QtWidgetsClass(QWidget* parent)
	: QWidget(parent)
{
	ui.setupUi(this);

	this->setFixedSize(430, 750);
	this->setWindowTitle("ScholarVPN");

	QFont win11Font("Segoe UI", 9);
	this->setFont(win11Font);

	this->setObjectName("root");
	this->setAttribute(Qt::WA_StyledBackground, true);
	this->setStyleSheet("#root{"
		"background:qlineargradient(x1:0,y1:0,x2:0,y2:1,"
		"stop:0 #eef2fa, stop:0.5 #f3f5fa, stop:1 #f8f9fc);}");

	auto* topBar = new QHBoxLayout;
	topBar->setContentsMargins(16, 16, 16, 6);
	topBar->setSpacing(10);

	QLabel* brandDot = new QLabel(this);
	brandDot->setFixedSize(12, 12);
	brandDot->setStyleSheet("background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #3b82f6,stop:1 #06b6d4); border-radius:6px;");

	QLabel* brandTitle = new QLabel("ScholarVPN", this);
	brandTitle->setStyleSheet("font-size:15pt; font-weight:bold; color:#1b2340; background:transparent;");

	QLabel* brandSub = new QLabel("SECURE  UDP  TUNNEL", this);
	brandSub->setStyleSheet("font-size:7pt; color:#9aa3b8; background:transparent; letter-spacing:2px;");

	auto* brandText = new QVBoxLayout;
	brandText->setSpacing(0);
	brandText->addWidget(brandTitle);
	brandText->addWidget(brandSub);

	auto* brand = new QHBoxLayout;
	brand->setSpacing(8);
	brand->addWidget(brandDot, 0, Qt::AlignVCenter);
	brand->addLayout(brandText);

	QPushButton* btn_add = new QPushButton("+", this);
	btn_add->setFixedSize(34, 34);
	btn_add->setCursor(Qt::PointingHandCursor);
	btn_add->setToolTip(QStringLiteral("添加服务器"));
	btn_add->setStyleSheet(R"(
	QPushButton{
		background-color:qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #3b82f6,stop:1 #2563eb);
		border:none;
		border-radius:17px;
		color:white;
		font-size:15pt;
		font-weight:bold;
		text-align:center;
		padding:0 0 3px 0;   /* 字形沿基线偏低，底部留白把它顶回视觉中心 */
	}
	QPushButton:hover{
		background-color:qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #4f8ef7,stop:1 #2f6fe8);
	}
	QPushButton:pressed{
		background-color:qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #2b6fd4,stop:1 #1e56b8);
	}
	)");

	QPushButton* btn_setting = new QPushButton(QStringLiteral("⚙"), this);
	btn_setting->setFixedSize(34, 34);
	btn_setting->setCursor(Qt::PointingHandCursor);
	btn_setting->setToolTip(QStringLiteral("设置"));
	btn_setting->setStyleSheet(R"(
	QPushButton{
		background-color:qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #3b82f6,stop:1 #2563eb);
		border:none;
		border-radius:17px;
		color:white;
		font-size:13pt;
		text-align:center;
		padding:0 0 2px 0;
	}
	QPushButton:hover{
		background-color:qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #4f8ef7,stop:1 #2f6fe8);
	}
	QPushButton:pressed{
		background-color:qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #2b6fd4,stop:1 #1e56b8);
	}
	)");
	connect(btn_setting, &QPushButton::clicked, this, [this]() {
		Setting dlg(this, m_bridge);
		m_setting = &dlg;
		dlg.exec();
		m_setting = nullptr;
	});

	topBar->addWidget(btn_setting);
	topBar->addStretch(1);
	topBar->addLayout(brand);
	topBar->addStretch(1);
	topBar->addWidget(btn_add);

	m_scroll = new QScrollArea(this);
	m_scroll->setWidgetResizable(true);
	m_scroll->setFrameShape(QFrame::NoFrame);
	m_scroll->setStyleSheet(R"(
	QScrollArea{background-color:transparent; border:none;}
	QScrollBar:vertical{
		width:8px;
		background:transparent;
		margin:2px;
	}
	QScrollBar:handle:vertical{
		background:#c9cedb;
		min-height:24px;
		border-radius:4px;
	}
	QScrollBar:handle:vertical:hover{background:#aab1c2;}
	QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical{height:0px;}
	)");

	m_cardContainer = new QWidget;
	m_cardContainer->setStyleSheet("background-color:transparent;");
	m_cardLayout = new QVBoxLayout(m_cardContainer);
	m_cardLayout->setSpacing(12);
	m_cardLayout->setContentsMargins(4, 4, 4, 4);
	m_cardLayout->addStretch();

	m_scroll->setWidget(m_cardContainer);

	m_diaCard = new QWidget(this);
	m_diaCard->setGeometry(this->rect());
	m_diaCard->hide();

	auto* overlayLay = new QVBoxLayout(m_diaCard);
	overlayLay->setContentsMargins(0, 0, 0, 0);
	overlayLay->setSpacing(0);

	m_glassTop = new QWidget;
	m_glassTop->setFixedHeight(200);
	m_glassTop->setStyleSheet("background-color: rgba(15, 23, 42, 135);");
	m_glassTop->installEventFilter(this);
	m_glassTop->setCursor(Qt::PointingHandCursor);

	m_glassCard = new QFrame(m_glassTop);
	m_glassCard->setObjectName("glassCard");
	m_glassCard->setStyleSheet(R"(
	QFrame#glassCard{
		background-color: rgba(255, 255, 255, 238);
		border:1px solid rgba(255, 255, 255, 190);
		border-radius:14px;
	}
	)");
	auto* glassLay = new QVBoxLayout(m_glassCard);
	glassLay->setContentsMargins(18, 12, 18, 12);
	glassLay->setSpacing(5);

	QLabel* glassCaption = new QLabel("当前服务器", m_glassCard);
	glassCaption->setStyleSheet("background:transparent; color:#9aa3b8; font-size:8pt; letter-spacing:2px;");

	m_glassName = new QLabel(m_glassCard);
	m_glassName->setStyleSheet("background:transparent; color:#1f2937; font-size:13pt; font-weight:bold;");

	m_glassIp = new QLabel(m_glassCard);
	m_glassIp->setStyleSheet("background:transparent; color:#4b5563; font-family:Consolas,'Courier New',monospace; font-size:10pt;");

	m_glassVip = new QLabel(m_glassCard);
	m_glassVip->setStyleSheet("background:transparent; color:#4b5563; font-family:Consolas,'Courier New',monospace; font-size:10pt;");

	m_glassState = new QLabel(m_glassCard);
	m_glassState->setStyleSheet("background:transparent; color:#0078d4; font-size:10pt;");

	glassLay->addWidget(glassCaption);
	glassLay->addWidget(m_glassName);
	glassLay->addWidget(m_glassIp);
	glassLay->addWidget(m_glassVip);
	glassLay->addWidget(m_glassState);

	auto* glassTopLay = new QVBoxLayout(m_glassTop);
	glassTopLay->setContentsMargins(16, 48, 16, 16);
	glassTopLay->addWidget(m_glassCard);
	glassTopLay->addStretch();

	QWidget* panel = new QWidget;
	panel->setStyleSheet(R"(
	QWidget#switchPanel{
		background-color:#f7f8fc;
		border-top-left-radius:20px;
		border-top-right-radius:20px;
		border-top:1px solid #e5e9f2;
	}
	)");
	panel->setObjectName("switchPanel");

	auto* panelLay = new QVBoxLayout(panel);
	panelLay->setContentsMargins(16, 14, 16, 14);
	panelLay->setSpacing(6);

	QPushButton* btn_close = new QPushButton("×", panel);
	btn_close->setFixedSize(34, 34);
	btn_close->setCursor(Qt::PointingHandCursor);
	btn_close->setStyleSheet(R"(
	QPushButton{
		background-color:#eef0f6;
		border:none;
		border-radius:17px;
		color:#5b6472;
		font-size:14pt;
	}
	QPushButton:hover{background-color:#e2e5ee;color:#1f2937;}
	QPushButton::text{top:-2px};
	)");
	connect(btn_close, &QPushButton::clicked, this, [this] { m_diaCard->hide(); });

	QLabel* dia_title = new QLabel("切换服务器", panel);
	dia_title->setStyleSheet("font-size:13pt; font-weight:bold; color:#1f2937; background:transparent;");

	QLabel* dia_subtitle = new QLabel("点击卡片选择要连接的服务器", panel);
	dia_subtitle->setStyleSheet("font-size:9pt; color:#9aa3b8; background:transparent;");

	auto* diaTitleCol = new QVBoxLayout;
	diaTitleCol->setSpacing(2);
	diaTitleCol->addWidget(dia_title);
	diaTitleCol->addWidget(dia_subtitle);

	auto* diaTop = new QHBoxLayout;
	diaTop->setSpacing(12);
	diaTop->addLayout(diaTitleCol);
	diaTop->addStretch();
	diaTop->addWidget(btn_close, 0, Qt::AlignTop);

	panelLay->addLayout(diaTop);
	panelLay->addWidget(m_scroll, 1);

	overlayLay->addWidget(m_glassTop);
	overlayLay->addWidget(panel, 1);

	m_homeCard = new QFrame(this);
	m_homeCard->setFixedHeight(176);
	m_homeCard->setObjectName("serverCard");
	m_homeCard->setStyleSheet(R"(
	QFrame#serverCard{
		background-color:#ffffff;
		border:1px solid #e8ecf3;
		border-radius:16px;
	}
	QFrame#serverCard:hover{ border:1px solid #d4dcea; }
	)");
	m_homeCard->hide();

	m_homeAccent = new QFrame(m_homeCard);
	m_homeAccent->setGeometry(0, 24, 4, 128);
	m_homeAccent->setStyleSheet("background-color:#3b82f6; border-top-left-radius:16px;"
	                            "border-bottom-left-radius:16px;");

	m_homeAvatar = new QLabel(m_homeCard);
	m_homeAvatar->setGeometry(20, 20, 48, 48);
	m_homeAvatar->setAlignment(Qt::AlignCenter);
	m_homeAvatar->setText("S");
	m_homeAvatar->setStyleSheet(R"(
	QLabel{
		background-color:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #3b82f6,stop:1 #06b6d4);
		border-radius:24px;
		color:white;
		font-size:16pt;
		font-weight:bold;
	}
	)");

	m_homeName = new QLabel(m_homeCard);
	m_homeName->setGeometry(82, 20, 240, 26);
	m_homeName->setStyleSheet("background:transparent; font-size:13pt; font-weight:bold; color:#1f2937;");

	m_homeTag = new QLabel(m_homeCard);
	m_homeTag->setGeometry(82, 52, 64, 20);
	m_homeTag->setAlignment(Qt::AlignCenter);
	m_homeTag->setText("受管服务");
	m_homeTag->setStyleSheet(R"(
	QLabel{
		background-color:#e8f4f8; color:#0891b2;
		border:1px solid #a5d8e6; border-radius:10px; font-size:8pt;
	}
	)");
	m_homeTag->hide();

	m_homeIp = new QLabel(m_homeCard);
	m_homeIp->setGeometry(82, 52, 180, 22);
	m_homeIp->setStyleSheet("background:transparent; font-family:Consolas,'Courier New',monospace; font-size:10pt; color:#6b7280;");

	m_homeVip = new QLabel(m_homeCard);
	m_homeVip->setGeometry(268, 52, 140, 22);
	m_homeVip->setText("内网IP: --");
	m_homeVip->setStyleSheet("background:transparent; font-family:Consolas,'Courier New',monospace; font-size:10pt; color:#6b7280;");

	m_homeUsageBar = new QProgressBar(m_homeCard);
	m_homeUsageBar->setGeometry(24, 76, 358, 6);
	m_homeUsageBar->setTextVisible(false);
	m_homeUsageBar->setRange(0, 100);
	m_homeUsageBar->setValue(0);
	m_homeUsageBar->setStyleSheet(R"(
	QProgressBar{ background-color:#e8ecf3; border:none; border-radius:3px; }
	QProgressBar::chunk{ background-color:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #3b82f6,stop:1 #06b6d4);
	                     border-radius:3px; }
	)");
	m_homeUsageBar->hide();

	m_homeUsageText = new QLabel(m_homeCard);
	m_homeUsageText->setGeometry(24, 82, 358, 18);
	m_homeUsageText->setAlignment(Qt::AlignRight);
	m_homeUsageText->setStyleSheet("background:transparent; font-size:8pt; color:#8b94a6;");
	m_homeUsageText->hide();

	m_homeBtn = new QPushButton("连接", m_homeCard);
	m_homeBtn->setGeometry(24, 104, 358, 56);
	m_homeBtn->setCursor(Qt::PointingHandCursor);
	m_homeEditBtn = new QPushButton("管理", m_homeCard);
	m_homeEditBtn->setGeometry(322, 18, 64, 26);
	m_homeEditBtn->setCursor(Qt::PointingHandCursor);
	m_homeEditBtn->setStyleSheet(R"(
	QPushButton{
		background:transparent;
		border:1px solid #e2e6ee;
		border-radius:13px;
		color:#5b6472;
		font-size:9pt;
	}
	QPushButton:hover{ border:1px solid #3b82f6; color:#2563eb; }
	)");

	connect(m_homeBtn, &QPushButton::clicked, this, [this]() {
		if (m_selectedCard < 0 || m_selectedCard >= (int)m_cardServers.size())
			return;
		const ServerEntry entry = m_cardServers[m_selectedCard];
		if (m_state == ConnState::Stopped) {
			if (!ClientApp::is_elevated()) {
				QMessageBox::information(this, QStringLiteral("需要管理员权限"),
					QStringLiteral("建立 VPN 需要创建虚拟网卡、修改路由与 DNS，这些操作需要管理员权限。\n\n"
						"请关闭本程序，右键 ScholarVPN.exe →「以管理员身份运行」后再点击连接。"));
				return;
			}
			m_activeCard = m_selectedCard;
			QMetaObject::invokeMethod(m_bridge, [this, entry]() {
				m_bridge->connect_to_server(entry);
			}, Qt::QueuedConnection);
		} else {
			QMetaObject::invokeMethod(m_bridge, [this]() {
				m_bridge->stop();
			}, Qt::QueuedConnection);
		}
	});
	connect(m_homeEditBtn, &QPushButton::clicked, this, [this]() {
		if (m_selectedCard < 0 || m_selectedCard >= (int)m_cardServers.size())
			return;
		m_activeCard = m_selectedCard;
		edit_card();
	});

	m_homeHint = new QLabel("当前无服务器\n\n点击右上角「 + 添加服务器 」创建你的第一个配置", this);
	m_homeHint->setAlignment(Qt::AlignCenter);
	m_homeHint->setStyleSheet("color:#a0a8ba; font-size:10pt; background:transparent;");

	auto* homeArea = new QVBoxLayout;
	homeArea->setContentsMargins(14, 10, 14, 12);
	homeArea->setSpacing(10);
	homeArea->addWidget(m_homeCard, 0, Qt::AlignTop);

	m_speedChart = new SpeedChart(this);
	homeArea->addWidget(m_speedChart, 0, Qt::AlignTop);

	auto* main = new QVBoxLayout(this);
	main->setContentsMargins(0, 0, 0, 0);
	main->setSpacing(0);
	main->addLayout(topBar);
	main->addLayout(homeArea, 1);
	main->addWidget(m_homeHint, 1);

	m_bridge = new AppBridge;
	m_thread_start = new QThread(this);
	m_bridge->moveToThread(m_thread_start);
	m_thread_start->start();

	connect(m_bridge, &AppBridge::connected, this, [this](const QString& ip) {
		m_homeVip->setText("内网IP: " + ip);
		update_glass_card();
	});

	connect(m_bridge, &AppBridge::stateChanged, this, [this](ConnState s) {
		m_state = s;
		if (s == ConnState::Stopped || s == ConnState::Reconnecting)
			m_homeVip->setText("内网IP: --");
		m_btnSwitch->setEnabled(s == ConnState::Stopped);
		const bool stopped = (s == ConnState::Stopped);
		refresh_mode_buttons();
		update_home_btn();
		update_glass_card();

		if (s == ConnState::Error) {
			QMessageBox::warning(this, QStringLiteral("连接失败"),
				QStringLiteral("连接服务器 [%1] 失败：已连续 5 次尝试未成功，已停止自动重连。\n\n"
					"请检查：\n"
					"  1. 服务器 IP / 端口是否正确，服务端是否在运行\n"
					"  2. 网络/运营商是否拦截（可尝试更换端口）\n"
					"  3. 首次使用需先注册：在编辑窗口填入有效 RegisterToken")
					.arg(m_homeName->text()));
		}
	});

	connect(m_bridge, &AppBridge::tokenRejected, this, [this]() {
		if (m_selectedCard < 0 || m_selectedCard >= (int)m_cardServers.size())
			return;
		m_cardServers[m_selectedCard].RegisterToken.clear();
		const cfgstr iniPath = cfg_path_join(cfg_app_dir(), CS("config.ini"));
		IniSetStr(iniPath, CS("Server") + cfg_num(m_selectedCard + 1),
		          CS("RegisterToken"), CS(""));
	});

	m_btnSwitch = new QPushButton(this);
	m_btnSwitch->setCursor(Qt::PointingHandCursor);
	m_btnSwitch->setGeometry(105, 615, 220, 52);
	m_btnSwitch->setText("⇄  Switch Server");
	m_btnSwitch->setStyleSheet(R"(
	QPushButton{
		background-color:qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #4f8ef7,stop:1 #2563eb);
		border:none;
		border-radius:26px;
		color:white;
		font-size:11pt;
		font-weight:bold;
	}
	QPushButton:hover{
		background-color:qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #639df8,stop:1 #2f6fe8);
	}
	QPushButton:pressed{
		background-color:qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #2b6fd4,stop:1 #1e56b8);
	}
	)");

	connect(m_btnSwitch, &QPushButton::clicked, this, [=] {
		qDebug() << "show switch";
		show_switch_dialog();
	});

	QFrame* seg = new QFrame(this);
	seg->setGeometry(105, 680, 220, 34);
	seg->setStyleSheet(QStringLiteral(
	    "QFrame{background-color:#eef1f6;border:1px solid #e4e8f0;border-radius:10px;}"));
	auto* segLay = new QHBoxLayout(seg);
	segLay->setContentsMargins(3, 3, 3, 3);
	segLay->setSpacing(0);

	const QString segBtnStyle = QStringLiteral(
	    "QPushButton{background:transparent;border:none;border-radius:8px;"
	    "color:#5b6472;font-size:10pt;}"
	    "QPushButton:checked{background-color:#ffffff;color:#2563eb;font-weight:bold;}"
	    "QPushButton:disabled{color:#c3c8d2;background:transparent;}");

	m_btnGlobal = new QPushButton(QStringLiteral("全局"), seg);
	m_btnGlobal->setCursor(Qt::PointingHandCursor);
	m_btnGlobal->setCheckable(true);
	m_btnGlobal->setAutoExclusive(true);
	m_btnGlobal->setStyleSheet(segBtnStyle);
	m_btnGlobal->setToolTip(QStringLiteral("所有流量都走隧道（包括国内网站）"));

	m_btnSplit = new QPushButton(QStringLiteral("智能分流"), seg);
	m_btnSplit->setCursor(Qt::PointingHandCursor);
	m_btnSplit->setCheckable(true);
	m_btnSplit->setAutoExclusive(true);
	m_btnSplit->setStyleSheet(segBtnStyle);
	m_btnSplit->setToolTip(QStringLiteral("国内 IP 直连，其余走隧道"));

	m_btnIntranet = new QPushButton(QStringLiteral("内网访问"), seg);
	m_btnIntranet->setCursor(Qt::PointingHandCursor);
	m_btnIntranet->setCheckable(true);
	m_btnIntranet->setAutoExclusive(true);
	m_btnIntranet->setStyleSheet(segBtnStyle);
	m_btnIntranet->setToolTip(QStringLiteral("只让指定内网网段走隧道，其余流量走本地网络"));

	segLay->addWidget(m_btnGlobal);
	segLay->addWidget(m_btnSplit);
	segLay->addWidget(m_btnIntranet);

	{
		const cfgstr modeIni = cfg_path_join(cfg_app_dir(), CS("config.ini"));
		const cfgstr mode = IniGetStr(modeIni, CS("Routing"), CS("Mode"), CS("full"));
		const bool split = (mode == CS("split"));
		const bool intra = (mode == CS("intranet"));
		m_btnSplit->setChecked(split);
		m_btnIntranet->setChecked(intra);
		m_btnGlobal->setChecked(!split && !intra);
		m_bridge->set_routing_mode(QString::fromStdString(cfg_to_utf8(mode)));
	}

	auto sync_mode_buttons = [this]() {
		const cfgstr modeIni = cfg_path_join(cfg_app_dir(), CS("config.ini"));
		const cfgstr mode = IniGetStr(modeIni, CS("Routing"), CS("Mode"), CS("full"));
		m_btnGlobal->setChecked(mode == CS("full"));
		m_btnSplit->setChecked(mode == CS("split"));
		m_btnIntranet->setChecked(mode == CS("intranet"));
	};

	auto apply_mode = [this](const QString& mode) {
		const cfgstr modeIni = cfg_path_join(cfg_app_dir(), CS("config.ini"));
		IniSetStr(modeIni, CS("Routing"), CS("Mode"), cfg_from_utf8(mode.toStdString()));
		m_bridge->set_routing_mode(mode);
		qDebug() << "routing mode ->" << mode;
	};
	connect(m_btnGlobal, &QPushButton::clicked, this,
		[apply_mode]() { apply_mode(QStringLiteral("full")); });
	connect(m_btnSplit, &QPushButton::clicked, this,
		[apply_mode]() { apply_mode(QStringLiteral("split")); });
	connect(m_btnIntranet, &QPushButton::clicked, this,
		[this, apply_mode, sync_mode_buttons]() {
			const cfgstr modeIni = cfg_path_join(cfg_app_dir(), CS("config.ini"));
			const cfgstr cur = IniGetStr(modeIni, CS("Routing"), CS("IntranetSubnets"), CS(""));
			bool ok = false;
			const QString text = QInputDialog::getText(this, QStringLiteral("内网访问"),
				QStringLiteral("经隧道访问的内网网段（逗号分隔）：\n"
				               "例如 192.168.10.0/24,10.20.0.0/16\n"
				               "留空 = 不注入任何路由，所有流量仍走本地网络。"),
				QLineEdit::Normal, QString::fromStdString(cfg_to_utf8(cur)), &ok);
			if (!ok) {
				sync_mode_buttons();
				return;
			}
			const QString trimmed = text.trimmed();
			for (const QString& part : trimmed.split(QRegularExpression("[,;\\s]+"),
			                                         Qt::SkipEmptyParts)) {
				cidr::Cidr probe{};
				if (!cidr::parse(part.toStdString(), probe) || probe.prefix == 0) {
					QMessageBox::warning(this, QStringLiteral("内网访问"),
						QStringLiteral("网段格式不正确：%1\n\n"
							"请填写 a.b.c.d/前缀 形式，例如 192.168.10.0/24。\n"
							"为保证安全，不接受 0.0.0.0/0（那等于全局代理）。").arg(part));
					sync_mode_buttons();
					return;
				}
			}
			IniSetStr(modeIni, CS("Routing"), CS("IntranetSubnets"),
			          cfg_from_utf8(trimmed.toStdString()));
			apply_mode(QStringLiteral("intranet"));
		});

	m_svcInfo = new QLabel(this);
	m_svcInfo->setGeometry(16, 716, 398, 24);
	m_svcInfo->setAlignment(Qt::AlignCenter);
	m_svcInfo->setStyleSheet("color:#8b94a6; font-size:9pt; background:transparent;");
	m_svcInfo->hide();

	QTimer::singleShot(0, this, [this]() { m_bridge->check_update(); });

	connect(m_bridge, &AppBridge::updateChecked, this,
		[this](int status, int action, const QString& latest, const QString& notes, const QString& err,
		       const QString& url, const QString& sha256, quint64 size) {
			m_updateUrl = url;
			m_updateSha256 = sha256;
			m_updateLatest = latest;
			m_updateSize = size;
			const cfgstr iniPathU = cfg_path_join(cfg_app_dir(), CS("config.ini"));
			const QString installedSha = toQString(
				IniGetStr(iniPathU, CS("Update"), CS("InstalledSha"), CS("")));
			if (!installedSha.isEmpty() && installedSha == sha256 && action == 1)
			{
				action = 0;
			}
			if (m_setting)
			{
				m_setting->applyUpdateInfo(status, action, latest, notes, err, url, sha256, size);
			}
			const bool sigBad = (status == 1);
			const bool forced = (status == 0 && action == 2);
			if (!sigBad && !forced)
			{
				return;
			}

			m_bridge->set_update_blocked(true);
			m_homeBtn->setEnabled(false);

			const QString title = sigBad ? QStringLiteral("更新信息校验失败")
			                             : QStringLiteral("需要更新");
			const QString body = sigBad
				? QStringLiteral("无法验证更新信息的来源，为避免安全风险，程序已停止使用。\n\n%1").arg(err)
				: QStringLiteral("当前版本 v%1 已不被支持，必须更新后才能继续使用。\n\n新版本：v%2\n%3")
				      .arg(QStringLiteral(SCHOLARVPN_VER_STRING), latest, notes);

			QMessageBox box(QMessageBox::Warning, title, body, QMessageBox::NoButton, this);
			box.setWindowFlags(box.windowFlags() & ~Qt::WindowCloseButtonHint);
			box.setEscapeButton(nullptr);
			QPushButton* primary = box.addButton(
				sigBad ? QStringLiteral("重试") : QStringLiteral("立即更新"),
				QMessageBox::AcceptRole);
			QPushButton* quitBtn = box.addButton(QStringLiteral("退出"), QMessageBox::RejectRole);
			m_updateBox = &box;
			m_boxBtn = primary;

			for (;;)
			{
				box.exec();
				if (box.clickedButton() == quitBtn)
				{
					qApp->quit();
					return;
				}
				if (m_lastDownloadOk)
				{
					qApp->quit();
					return;
				}
				if (box.clickedButton() == primary && !sigBad &&
				    !m_updateUrl.isEmpty() && !m_updateSha256.isEmpty())
				{
					primary->setEnabled(false);
					m_bridge->download_and_install(m_updateUrl, m_updateSha256,
					                               m_updateSize, m_updateLatest);
				}
			}
		});

	connect(m_bridge, &AppBridge::downloadProgress, this, [this](int pct) {
		const QString t = pct >= 0 ? QStringLiteral("下载中 %1%").arg(pct)
		                           : QStringLiteral("下载中...");
		if (m_boxBtn)
		{
			m_boxBtn->setText(t);
			return;
		}
		if (m_setting)
		{
			m_setting->applyDownloadProgress(pct);
		}
	});

	connect(m_bridge, &AppBridge::downloadFinished, this, [this](bool ok, const QString& err) {
		m_lastDownloadOk = ok;
		if (ok)
		{
			{
				const cfgstr iniPathS = cfg_path_join(cfg_app_dir(), CS("config.ini"));
				IniSetStr(iniPathS, CS("Update"), CS("InstalledSha"),
				          cfg_from_utf8(m_updateSha256.toStdString()));
			}
#if defined(_WIN32)
			qApp->quit();
#else
			if (m_boxBtn)
			{
				m_boxBtn->setText(QStringLiteral("安装完成，请重新启动 ScholarVPN"));
				m_boxBtn->setEnabled(true);
			}
			if (m_setting)
			{
				m_setting->applyDownloadFinished(true, QString());
			}
#endif
			return;
		}
		if (m_boxBtn)
		{
			m_boxBtn->setText(QStringLiteral("下载失败，点此重试"));
			m_boxBtn->setEnabled(true);
		}
		if (m_setting)
		{
			m_setting->applyDownloadFinished(false, err);
		}
	});

	QTimer::singleShot(0, this, [this]() {
		const cfgstr iniPath = cfg_path_join(cfg_app_dir(), CS("config.ini"));
		if (IniGetStr(iniPath, CS("Service"), CS("Mode"), CS("")) == CS("managed"))
		{
			m_bridge->check_service();
			m_bridge->apply_server_list();
		}
	});
	{
		auto* svcTimer = new QTimer(this);
		svcTimer->setInterval(5 * 60 * 1000);
		connect(svcTimer, &QTimer::timeout, this, [this]() {
			const cfgstr iniPath = cfg_path_join(cfg_app_dir(), CS("config.ini"));
			if (IniGetStr(iniPath, CS("Service"), CS("Mode"), CS("")) == CS("managed"))
			{
				m_bridge->check_service();
			}
		});
		svcTimer->start();
	}

	connect(m_bridge, &AppBridge::serviceChecked, this,
		[this](int blocked, const QString& reason, const QString& fp,
		       const QString& clientId, const QString& status,
		       qulonglong expireAt, qulonglong quotaBytes, qulonglong usedBytes,
		       const QString& err) {
			m_svcCheckPending = false;
			if (err.isEmpty() && !fp.isEmpty())
			{
				const cfgstr iniPath = cfg_path_join(cfg_app_dir(), CS("config.ini"));
				IniSetStr(iniPath, CS("Service"), CS("Fp"), fromQString(fp));
				IniSetStr(iniPath, CS("Service"), CS("ClientID"), fromQString(clientId));
				IniSetStr(iniPath, CS("Service"), CS("Status"), fromQString(status));
				IniSetStr(iniPath, CS("Service"), CS("ExpireAt"),
				          cfg_from_utf8(std::to_string(expireAt)));
				IniSetStr(iniPath, CS("Service"), CS("QuotaBytes"),
				          cfg_from_utf8(std::to_string(quotaBytes)));
				IniSetStr(iniPath, CS("Service"), CS("UsedBytes"),
				          cfg_from_utf8(std::to_string(usedBytes)));
			}
			m_bridge->set_service_blocked(blocked == 1);

			{
				const cfgstr iniPath = cfg_path_join(cfg_app_dir(), CS("config.ini"));
				const bool managed = IniGetStr(iniPath, CS("Service"), CS("Mode"), CS(""))
				                     == CS("managed");
				QString text;
				if (managed && !err.isEmpty())
				{
					text = QStringLiteral("服务状态同步失败");
				}
				else if (managed && !status.isEmpty())
				{
					if (status == QStringLiteral("approved"))
					{
						text = QStringLiteral("已授权 · 已用 %1")
						           .arg(QString::fromStdString(
						               svc_fmt_bytes(static_cast<qulonglong>(usedBytes))));
					}
					else if (status == QStringLiteral("trial"))
					{
						QString seg;
						if (expireAt > 0)
						{
							const qint64 remain = qint64(expireAt)
							                      - qint64(QDateTime::currentSecsSinceEpoch());
							seg = remain > 0
							          ? QStringLiteral("剩余 %1 小时").arg(remain / 3600)
							          : QStringLiteral("已到期");
						}
						QString used;
						if (quotaBytes > 0)
						{
							used = QStringLiteral(" · 已用 %1 / %2")
							           .arg(QString::fromStdString(svc_fmt_bytes(usedBytes)),
							                QString::fromStdString(svc_fmt_bytes(quotaBytes)));
						}
						text = QStringLiteral("试用中") + (seg.isEmpty() ? QString() : QStringLiteral(" · ") + seg) + used;
					}
					else if (status == QStringLiteral("rejected"))
					{
						text = QStringLiteral("服务申请已被拒绝");
					}
					else if (status == QStringLiteral("revoked"))
					{
						text = QStringLiteral("授权已被服务方取消");
					}
					else if (status.isEmpty())
					{
						text = QStringLiteral("受管服务 · 尚未申请试用");
					}
					if (m_homeUsageBar)
						update_home_usage();
				}
				if (text.isEmpty())
				{
					m_svcInfo->hide();
				}
				else
				{
					m_svcInfo->setText(text);
					m_svcInfo->show();
				}
			}

			if (m_setting)
			{
				m_setting->applyServiceInfo(blocked, reason, fp, clientId, status,
				                            expireAt, quotaBytes, usedBytes, err);
			}

			if (m_svcBox)
			{
				if (blocked != 1)
				{
					m_svcBox->accept();
					m_svcBox = nullptr;
				}
				else
				{
					m_svcBox->setText(reason);
				}
				return;
			}
			if (blocked == 1)
			{
				show_service_blocked_box(reason);
			}
		});

	connect(m_bridge, &AppBridge::serviceRegistered, this,
		[this](int ok, const QString& fp, const QString& clientId,
		       const QString& token, const QString& status,
		       qulonglong expireAt, qulonglong quotaBytes, const QString& err) {
			if (!ok)
			{
				if (m_setting)
				{
					m_setting->applyServiceInfo(0, QString(), fp, clientId, QString(),
					                            0, 0, 0,
					                            err.isEmpty()
					                                ? QStringLiteral("申请失败")
					                                : err);
				}
				return;
			}
			const cfgstr iniPath = cfg_path_join(cfg_app_dir(), CS("config.ini"));
			IniSetStr(iniPath, CS("Service"), CS("Fp"), fromQString(fp));
			IniSetStr(iniPath, CS("Service"), CS("ClientID"), fromQString(clientId));
			IniSetStr(iniPath, CS("Service"), CS("Token"), fromQString(token));
			IniSetStr(iniPath, CS("Service"), CS("Status"), fromQString(status));
			IniSetStr(iniPath, CS("Service"), CS("ExpireAt"),
			          cfg_from_utf8(std::to_string(expireAt)));
			IniSetStr(iniPath, CS("Service"), CS("QuotaBytes"),
			          cfg_from_utf8(std::to_string(quotaBytes)));
			m_bridge->apply_server_list();
		});

	connect(m_bridge, &AppBridge::serviceServers, this,
		[this](int count, const QString& err) {
			if (!err.isEmpty() && count == 0)
			{
				if (m_setting)
				{
					m_setting->applyServiceServers(err);
				}
				return;
			}
			apply_managed_servers(count);
		});

	connect(m_bridge, &AppBridge::serviceModeChanged, this, [this](int managed) {
		if (managed == 0)
		{
			remove_managed_cards();
		}
	});

	connect(btn_add, &QPushButton::clicked, this, [this]() {
		const cfgstr iniPath = cfg_path_join(cfg_app_dir(), CS("config.ini"));
		if (IniGetStr(iniPath, CS("Service"), CS("Mode"), CS("")) != CS("managed")) {
			write_edit();
			return;
		}
		QMessageBox box(QMessageBox::Information, QStringLiteral("受管模式"),
		    QStringLiteral("当前使用服务方服务器（受管模式）：服务器列表由服务方统一下发，"
		                   "手动新增的服务器配置不会生效。\n\n如需添加自建服务器，"
		                   "请先在「设置 → 服务」中切换为「自建服务器」。"),
		    QMessageBox::NoButton, this);
		QPushButton* go = box.addButton(QStringLiteral("打开设置"), QMessageBox::ActionRole);
		box.addButton(QStringLiteral("知道了"), QMessageBox::AcceptRole);
		box.exec();
		if (box.clickedButton() == go) {
			Setting dlg(this, m_bridge, 1);
			m_setting = &dlg;
			dlg.exec();
			m_setting = nullptr;
		}
	});

	auto* speedTimer = new QTimer(this);
	connect(speedTimer, &QTimer::timeout, this, &QtWidgetsClass::update_speed);
	speedTimer->start(1000);

	Read_iniFile();
	createtray();

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
	m_cardDots.clear();
	m_cardServers.clear();
}

void QtWidgetsClass::Read_iniFile()
{
	delete m_cfg;
	m_cfg = new Config(cfg_path_join(cfg_app_dir(), CS("config.ini")),
		cfg_app_dir());
	ClientConfig cc;
	clear_cards();

	if (m_cfg->LoadClientConfig(cc)) {
#ifdef _DEBUG
		m_serverIp = toQString(cc.DebugServerIP.empty() ? cc.ServerIP : cc.DebugServerIP);
#else
		m_serverIp = toQString(cc.ServerIP);
#endif
		for (const auto& s : cc.servers)
			create_card(s);
	} else {
		m_serverIp = QStringLiteral("--");
	}

	if (m_selectedCard < 0 || m_selectedCard >= (int)m_cardServers.size())
		m_selectedCard = m_cardServers.isEmpty() ? -1 : (int)m_cardServers.size() - 1;
	show_home_card(m_selectedCard);
	update_dia_highlight();
	refresh_mode_buttons();
}

void QtWidgetsClass::write_edit()
{
	QDialog dia(this);
	dia.resize(380, 515);
	dia.setWindowTitle("添加服务器");
	QVBoxLayout* lay = new QVBoxLayout(&dia);
	lay->setContentsMargins(24, 24, 24, 24);
	lay->setSpacing(14);

	QLabel* name_lab = new QLabel("名称(可选,留空用默认 computer+N): ");
	QLineEdit* input_name = new QLineEdit;
	input_name->setPlaceholderText("例:公司服务器");

	QLabel* ip = new QLabel("IP: ");
	QLineEdit* input_ip = new QLineEdit;
	input_ip->setPlaceholderText("例:127.0.0.1");

	QLabel* port_lab = new QLabel("端口(默认 51820): ");
	QLineEdit* input_port = new QLineEdit;
	input_port->setPlaceholderText("例:51820");
	input_port->setText("51820");

	QLabel* client_id = new QLabel("ClientID: ");
	QLineEdit* input_id = new QLineEdit;
	input_id->setPlaceholderText("Unique ClientID");

	QLabel* token = new QLabel("RegisterToken: ");
	QLineEdit* input_token = new QLineEdit;
	input_token->setPlaceholderText("首次需注册令牌");

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
	input_name->setStyleSheet(edit_Style);
	input_ip->setStyleSheet(edit_Style);
	input_port->setStyleSheet(edit_Style);
	input_id->setStyleSheet(edit_Style);
	input_token->setStyleSheet(edit_Style);

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

	lay->addWidget(name_lab);
	lay->addWidget(input_name);
	lay->addWidget(ip);
	lay->addWidget(input_ip);
	lay->addWidget(port_lab);
	lay->addWidget(input_port);
	lay->addWidget(client_id);
	lay->addWidget(input_id);
	lay->addWidget(token);
	lay->addWidget(input_token);
	lay->addWidget(pubkey_label);
	lay->addWidget(input_pubkey);
	lay->addStretch();
	lay->addLayout(btnLayout);

	connect(btn_OK, &QPushButton::clicked, &dia, [&]() {
		bool portOk = false;
		const int port = input_port->text().trimmed().toInt(&portOk);
		if (!portOk || port < 1 || port > 65535) {
			QMessageBox::warning(&dia, "提示", "端口无效：应为 1-65535 的数字");
			return;
		}

		QString pk = input_pubkey->toPlainText();
		pk.remove(QRegularExpression("\\s"));
		pk.remove(QRegularExpression("-+BEGIN[^-]*?-+"));
		pk.remove(QRegularExpression("-*END[^-]*?-+"));
		pk.remove(QRegularExpression("-+"));
		if (!pk.isEmpty() && pk.size() != 60) {
			QMessageBox::warning(&dia, "提示",
				QString("服务器公钥格式无效：应为 60 位 base64（server_sig.pub 的正文行），当前为 %1 位。\n"
					"注意：不要复制 registered_clients.txt 里的 hex 或客户端日志整段；\n"
					"留空 = 使用内置公钥。").arg(pk.size()));
			return;
		}
		dia.accept();
	});
	connect(btn_NO, &QPushButton::clicked, &dia, &QDialog::reject);

	if (dia.exec() != QDialog::Accepted)
		return;

	const QString newIp = input_ip->text().trimmed();
	const QString newId = input_id->text().trimmed();
	const QString newTok = input_token->text().trimmed();
	const QString newName = input_name->text().trimmed();
	if (newIp.isEmpty()) {
		QMessageBox::warning(this, "提示", "服务器 IP 不能为空");
		return;
	}
	if (newId.isEmpty()) {
		QMessageBox::warning(this, "提示", "ClientID 不能为空");
		return;
	}

	bool portOk = false;
	const int newPort = input_port->text().trimmed().toInt(&portOk);
	if (!portOk || newPort < 1 || newPort > 65535) {
		QMessageBox::warning(this, "提示", "端口无效：应为 1-65535 的数字");
		return;
	}

	QString pubkeyB64 = input_pubkey->toPlainText();
	pubkeyB64.remove(QRegularExpression("\\s"));
	pubkeyB64.remove(QRegularExpression("-+BEGIN[^-]*?-+"));
	pubkeyB64.remove(QRegularExpression("-*END[^-]*?-+"));
	pubkeyB64.remove(QRegularExpression("-+"));
	if (pubkeyB64.length() != 60)
		pubkeyB64.clear();

	const cfgstr inipath = cfg_path_join(cfg_app_dir(), CS("config.ini"));
	const int count = IniGetInt(inipath, CS("Server"), CS("Count"), 0);
	const int idx = count + 1;
	const cfgstr sec = CS("Server") + cfg_num(idx);
	IniSetStr(inipath, sec, CS("Name"),
	          fromQString(newName.isEmpty() ? QString("computer%1").arg(idx) : newName));
	IniSetStr(inipath, sec, CS("ServerIP"), fromQString(newIp));
	IniSetInt(inipath, sec, CS("ServerPort"), newPort);
	IniSetStr(inipath, sec, CS("ClientID"), fromQString(newId));
	IniSetStr(inipath, sec, CS("RegisterToken"), fromQString(newTok));
	IniSetStr(inipath, sec, CS("ServerPubKey"), fromQString(pubkeyB64));
	IniSetInt(inipath, CS("Server"), CS("Count"), idx);

	Read_iniFile();

}

void QtWidgetsClass::create_card(const ServerEntry& entry)
{
	const QString name = entry.Name.empty()
		? QStringLiteral("computer%1").arg(m_cards.size() + 1)
		: toQString(entry.Name);
	const QString ip   = toQString(entry.ServerIP);

	QFrame* card = new QFrame;
	card->setFixedHeight(96);
	card->setObjectName("selectCard");
	card->setCursor(Qt::PointingHandCursor);
	card->setStyleSheet(R"(
	QFrame#selectCard{
		background-color:#ffffff;
		border:2px solid transparent;
		border-radius:14px;
	}
	QFrame#selectCard:hover{
		background-color:#f5f9ff;
		border:2px solid #bfd9ff;
	}
	QFrame#selectCard[selected="true"]{
		background-color:#eef5ff;
		border:2px solid #3b82f6;
	}
	)");

	QLabel* avatar = new QLabel(card);
	avatar->setGeometry(16, 24, 48, 48);
	avatar->setAlignment(Qt::AlignCenter);
	avatar->setText(name.left(1).toUpper());
	avatar->setStyleSheet(R"(
	QLabel{
		background-color:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #3b82f6,stop:1 #06b6d4);
		border-radius:24px;
		color:white;
		font-size:16pt;
		font-weight:bold;
	}
	)");

	QLabel* lab_name = new QLabel(card);
	lab_name->setGeometry(78, 22, 210, 26);
	lab_name->setText(name);
	lab_name->setStyleSheet("background:transparent; font-size:11pt; font-weight:bold; color:#1f2937;");

	QLabel* lab_ip = new QLabel(card);
	lab_ip->setGeometry(78, 54, 210, 22);
	lab_ip->setText(entry.managed ? QStringLiteral("官方服务 · 服务方下发") : ("IP: " + ip));
	lab_ip->setStyleSheet(entry.managed
	    ? "background:transparent; font-size:9pt; color:#0891b2;"
	    : "background:transparent; font-family:Consolas,'Courier New',monospace; font-size:9pt; color:#6b7280;");

	QLabel* dot = new QLabel(card);
	dot->setGeometry(286, 26, 8, 8);
	dot->setStyleSheet("background-color:#3fb950; border-radius:4px;");
	dot->hide();
	m_cardDots.append(dot);

	QComboBox* box_sock = new CenteredComboBox(card);
	box_sock->setGeometry(entry.managed ? 296 : 278, 20, 92, 24);
	box_sock->setCursor(Qt::PointingHandCursor);
	box_sock->addItem(QStringLiteral("UDP"), 0);
	box_sock->addItem(QStringLiteral("TCP"), 1);

	for (int i = 0; i < box_sock->count(); ++i)
	{
		box_sock->setItemData(i, static_cast<int>(Qt::AlignCenter), Qt::TextAlignmentRole);
	}

	box_sock->setCurrentIndex(entry.transport ? 1 : 0);
	box_sock->setStyleSheet(R"(
	QComboBox{
		background-color:#f1f3f7;
		border:1px solid #e2e6ee;
		border-radius:6px;
		padding:2px 6px;
		color:#1f2937;
		font-size:9pt;
	}
	QComboBox::drop-down{ border:none; width:16px; }
	QComboBox QAbstractItemView{
		background-color:#ffffff;
		border:1px solid #e2e6ee;
		selection-background-color:#eef5ff;
		selection-color:#1f2937;
	}
	QComboBox QAbstractItemView::item{
		min-height:22px;
		text-align:center;
	}
	)");
	const int sockIdx = static_cast<int>(m_cards.size());
	connect(box_sock, &QComboBox::currentIndexChanged, this, [this, sockIdx, box_sock](int index) {
		if (sockIdx < 0 || sockIdx >= (int)m_cardServers.size())
			return;
		m_cardServers[sockIdx].transport = box_sock->itemData(index).toInt() ? 1 : 0;
		const cfgstr inipath = cfg_path_join(cfg_app_dir(), CS("config.ini"));
		IniSetInt(inipath, CS("Server") + cfg_num(sockIdx + 1),
		          CS("Transport"), m_cardServers[sockIdx].transport);
	});
	card->installEventFilter(this);

	m_cardLayout->insertWidget(m_cardLayout->count() - 1, card);

	m_cards.append(card);
	m_cardServers.append(entry);
}

void QtWidgetsClass::select_card(int index)
{
	if (index < 0 || index >= (int)m_cardServers.size())
		return;
	m_selectedCard = index;
	refresh_mode_buttons();
	update_dia_highlight();
	show_home_card(index);
	if (m_diaCard)
		m_diaCard->hide();
}

// 受管服务器（服务方下发）不开放内网访问：卡片切换与连接状态变化时刷新
void QtWidgetsClass::refresh_mode_buttons()
{
	if (!m_btnGlobal || !m_btnSplit || !m_btnIntranet) {
		return;
	}
	const bool stopped = (m_state == ConnState::Stopped);
	const bool hasSel = (m_selectedCard >= 0 &&
	                     m_selectedCard < static_cast<int>(m_cardServers.size()));
	const bool managed = hasSel && m_cardServers.at(m_selectedCard).managed;

	m_btnGlobal->setEnabled(stopped);
	m_btnSplit->setEnabled(stopped);
	m_btnIntranet->setEnabled(stopped && !managed);
	m_btnIntranet->setToolTip(managed
		? QStringLiteral("受管服务器（由服务方下发）不支持内网访问")
		: QStringLiteral("只让指定内网网段走隧道，其余流量走本地网络"));

	if (managed && m_btnIntranet->isChecked()) {
		// 选中的是受管卡片：内网模式退回全局，避免下次连接一条路由都没有
		m_btnGlobal->setChecked(true);
		const cfgstr modeIni = cfg_path_join(cfg_app_dir(), CS("config.ini"));
		IniSetStr(modeIni, CS("Routing"), CS("Mode"), CS("full"));
		m_bridge->set_routing_mode(QStringLiteral("full"));
	}
}

void QtWidgetsClass::update_dia_highlight()
{
	const bool online = (m_state == ConnState::Connected);
	for (int i = 0; i < m_cards.size(); ++i) {
		m_cards[i]->setProperty("selected", i == m_selectedCard);
		m_cards[i]->style()->unpolish(m_cards[i]);
		m_cards[i]->style()->polish(m_cards[i]);
	}
	for (int i = 0; i < m_cardDots.size() && i < m_cards.size(); ++i) {
		m_cardDots[i]->setVisible(online && i == m_activeCard);
	}
}

void QtWidgetsClass::update_glass_card()
{
	if (m_selectedCard < 0 || m_selectedCard >= (int)m_cardServers.size()) {
		m_glassCard->hide();
		return;
	}
	const ServerEntry& e = m_cardServers[m_selectedCard];
	const QString name = e.Name.empty()
		? QStringLiteral("computer%1").arg(m_selectedCard + 1)
		: toQString(e.Name);
	m_glassName->setText(name);
	m_glassIp->setText(e.managed ? QStringLiteral("受管服务")
	                             : ("IP: " + toQString(e.ServerIP)));

	const QString vip = m_homeVip->text();
	m_glassVip->setText(vip == "内网IP: --" ? "内网IP: --" : vip);

	QString stateText;
	QString stateColor;
	switch (m_state) {
	case ConnState::Connected:    stateText = "● 已连接";   stateColor = "#059669"; break;
	case ConnState::Connecting:   stateText = "● 连接中..."; stateColor = "#d97706"; break;
	case ConnState::Reconnecting: stateText = "● 重连中..."; stateColor = "#d97706"; break;
	case ConnState::Error:        stateText = "● 连接错误";  stateColor = "#dc2626"; break;
	default:                      stateText = "○ 未连接";   stateColor = "#94a3b8"; break;
	}
	m_glassState->setText(stateText);
	m_glassState->setStyleSheet(QString("background:transparent; color:%1; font-size:10pt;").arg(stateColor));

	m_glassCard->show();
}

void QtWidgetsClass::show_home_card(int index)
{
	if (index < 0 || index >= (int)m_cardServers.size()) {
		m_homeCard->hide();
		m_homeHint->show();
		return;
	}
	const ServerEntry& e = m_cardServers[index];
	const QString name = e.Name.empty()
		? QStringLiteral("computer%1").arg(index + 1)
		: toQString(e.Name);
	m_homeName->setText(name);
	m_homeAvatar->setText(name.left(1).toUpper());
	m_homeVip->setText("内网IP: --");
	m_homeEditBtn->setVisible(!e.managed);
	m_homeTag->setVisible(e.managed);
	m_homeUsageBar->setVisible(e.managed);
	m_homeUsageText->setVisible(e.managed);
	m_homeIp->setVisible(!e.managed);
	m_homeVip->setVisible(!e.managed);
	if (!e.managed)
		m_homeIp->setText("IP: " + toQString(e.ServerIP));
	else
		update_home_usage();
	update_home_btn();
	m_homeCard->show();
	m_homeHint->hide();
	update_glass_card();
}

void QtWidgetsClass::update_home_usage()
{
	const cfgstr iniPath = cfg_path_join(cfg_app_dir(), CS("config.ini"));
	const std::string status = narrow(IniGetStr(iniPath, CS("Service"), CS("Status"), CS("")));
	if (status != "trial") {
		if (status == "approved") {
			const unsigned long long used = std::strtoull(narrow(
				IniGetStr(iniPath, CS("Service"), CS("UsedBytes"), CS("0"))).c_str(), nullptr, 10);
			m_homeUsageBar->hide();
			m_homeUsageText->show();
			m_homeUsageText->setText(QStringLiteral("已授权 · 已用 %1")
			                             .arg(QString::fromStdString(svc_fmt_bytes(used))));
		}
		return;
	}
	const unsigned long long expire = std::strtoull(narrow(
		IniGetStr(iniPath, CS("Service"), CS("ExpireAt"), CS("0"))).c_str(), nullptr, 10);
	const unsigned long long quota = std::strtoull(narrow(
		IniGetStr(iniPath, CS("Service"), CS("QuotaBytes"), CS("0"))).c_str(), nullptr, 10);
	const unsigned long long used = std::strtoull(narrow(
		IniGetStr(iniPath, CS("Service"), CS("UsedBytes"), CS("0"))).c_str(), nullptr, 10);

	QString remain;
	if (expire != 0) {
		const qint64 left = qint64(expire) - qint64(QDateTime::currentSecsSinceEpoch());
		remain = left > 0 ? QStringLiteral("剩余 %1 小时").arg(left / 3600)
		                  : QStringLiteral("已到期");
	}
	if (quota == 0) {
		m_homeUsageBar->hide();
		m_homeUsageText->setText(remain);
		return;
	}
	const int pct = static_cast<int>(std::min<unsigned long long>(100, used * 100 / quota));
	m_homeUsageBar->setValue(pct);
	m_homeUsageText->setText(QStringLiteral("%1 · 已用 %2 / %3")
	                             .arg(remain,
	                                  QString::fromStdString(svc_fmt_bytes(used)),
	                                  QString::fromStdString(svc_fmt_bytes(quota))));
}

void QtWidgetsClass::update_home_btn()
{
	QString text;
	QString grad;
	if (m_state == ConnState::Stopped) {
		text = "连  接";
		grad = "stop:0 #3b82f6,stop:1 #2563eb";
	} else if (m_state == ConnState::Connecting || m_state == ConnState::Reconnecting) {
		text = (m_state == ConnState::Connecting) ? "连接中..." : "重连中...";
		grad = "stop:0 #f5a623,stop:1 #e8940a";
	} else {
		text = "断  开";
		grad = "stop:0 #f05252,stop:1 #dc2626";
	}
	QString accent = "#3b82f6";
	if (m_state == ConnState::Connected)        accent = "#10b981";
	else if (m_state == ConnState::Connecting)  accent = "#f5a623";
	else if (m_state == ConnState::Reconnecting) accent = "#f5a623";
	else if (m_state == ConnState::Error)       accent = "#ef4444";
	m_homeAccent->setStyleSheet(QString("background-color:%1;"
	    "border-top-left-radius:16px; border-bottom-left-radius:16px;").arg(accent));
	m_homeBtn->setText(text);
	m_homeBtn->setStyleSheet(QString(R"(
	QPushButton{
		background-color:qlineargradient(x1:0,y1:0,x2:0,y2:1,%1);
		border:none;
		border-radius:14px;
		color:white;
		font-size:12pt;
		font-weight:bold;
		letter-spacing:2px;
	}
	QPushButton:hover{
		background-color:qlineargradient(x1:0,y1:0,x2:0,y2:1,%1);
		opacity:0.9;
	}
	)").arg(grad));
}

bool QtWidgetsClass::eventFilter(QObject* obj, QEvent* ev)
{
	if (ev->type() == QEvent::MouseButtonRelease) {
		if (obj == m_glassTop) {
			m_diaCard->hide();
			return true;
		}
		const int idx = m_cards.indexOf(static_cast<QFrame*>(obj));
		if (idx >= 0)
			select_card(idx);
	}
	return QWidget::eventFilter(obj, ev);
}

void QtWidgetsClass::show_switch_dialog()
{
	if (!m_diaCard)
		return;
	Read_iniFile();
	if (m_diaCard->isHidden()) {
		m_diaCard->setGeometry(this->rect());
		m_diaCard->show();
		m_diaCard->raise();
	} else {
		m_diaCard->hide();
	}
}

void QtWidgetsClass::resizeEvent(QResizeEvent* ev)
{
	QWidget::resizeEvent(ev);
	if (m_diaCard && !m_diaCard->isHidden())
		m_diaCard->setGeometry(this->rect());
}

void QtWidgetsClass::createtray()
{
	if (!QSystemTrayIcon::isSystemTrayAvailable()) {
		qDebug() << "系统托盘不可用，跳过托盘初始化";
		return;
	}

	m_trayicon = new QSystemTrayIcon(this);

	QIcon trayIcon(":/source/icon.ico");
	if (trayIcon.isNull()) {
		const QString dir = QCoreApplication::applicationDirPath();
		const QString candidates[] = {
			dir + "/icon.ico",
			dir + "/source/icon.ico",
			QStringLiteral("source/icon.ico")
		};
		for (const QString& p : candidates) {
			QIcon candidate(p);
			if (!candidate.isNull()) { trayIcon = candidate; break; }
		}
	}
	if (trayIcon.isNull()) {
		qDebug() << "托盘图标加载失败（无 .qrc 且未找到 icon.ico），使用系统默认图标";
		trayIcon = style()->standardIcon(QStyle::SP_ComputerIcon);
	}
	m_trayicon->setIcon(trayIcon);
	m_trayicon->setToolTip("ScholarVPN");

	m_menu = new QMenu(this);
	m_menu->setStyleSheet(QString(R"(
		Qmenu{
			border-radius:12px;
		}
		)"));
	m_actionShow = new QAction(QStringLiteral("显示"), this);
	m_actionQuit = new QAction(QStringLiteral("退出"), this);
	m_menu->addAction(m_actionShow);
	m_menu->addSeparator();
	m_menu->addAction(m_actionQuit);

	m_trayicon->setContextMenu(m_menu);

	connect(m_actionShow, &QAction::triggered, this, [this] {
		this->showNormal();
		this->raise();
		this->activateWindow();
	});
	connect(m_actionQuit, &QAction::triggered, qApp, &QApplication::quit);
	connect(m_trayicon, &QSystemTrayIcon::activated, this,
		[this](QSystemTrayIcon::ActivationReason reason) {
			if (reason == QSystemTrayIcon::DoubleClick)
			{
				this->showNormal();
				this->raise();
				this->activateWindow();
			}
		});
	m_trayicon->show();
}

void QtWidgetsClass::closeEvent(QCloseEvent* event)
{
	if (m_trayicon && m_trayicon->isVisible())
	{
		hide();
		m_trayicon->showMessage("提示", "程序最小化到托盘，右键托盘图标操作");
		event->ignore();
	}
	else
	{
		event->accept();
	}
}

void QtWidgetsClass::edit_card()
{
	const int idx = m_activeCard;
	if (idx < 0 || idx >= (int)m_cardServers.size() || m_cardServers.empty())
		return;

	const ServerEntry& entry = m_cardServers[idx];
	QDialog dia(this);
	dia.resize(380, 545);
	dia.setWindowTitle("编辑服务器");
	QVBoxLayout* lay = new QVBoxLayout(&dia);
	lay->setContentsMargins(24, 24, 24, 24);
	lay->setSpacing(14);

	QLabel* lab_name = new QLabel("名称(可选,留空用默认 computer+N): ", &dia);
	QLineEdit* edit_name = new QLineEdit(&dia);
	edit_name->setPlaceholderText("例:公司服务器");

	QLabel* lab_ip = new QLabel("IP:", &dia);
	QLineEdit* edit_ip = new QLineEdit(&dia);
	edit_ip->setPlaceholderText("例:127.0.0.1");

	QLabel* lab_port = new QLabel("端口:", &dia);
	QLineEdit* edit_port = new QLineEdit(&dia);
	edit_port->setPlaceholderText("默认:51820");

	QLabel* Cilent_id = new QLabel("ClientID: ", &dia);
	QLineEdit* edit_ID = new QLineEdit(&dia);
	edit_ID->setPlaceholderText("Unique ClientID");

	QLabel* lab_token = new QLabel("RegisterToken: ", &dia);
	QLineEdit* edit_token = new QLineEdit(&dia);
	edit_token->setPlaceholderText("首次需注册令牌");

	QLabel* pubkey_label = new QLabel("服务器公钥(可选,留空则使用内置公钥): ", &dia);
	QPlainTextEdit* input_pubkey = new QPlainTextEdit(&dia);
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

	edit_name->setText(entry.Name.empty()
		? QStringLiteral("computer%1").arg(idx + 1)
		: toQString(entry.Name));
	edit_ip->setText(toQString(entry.ServerIP));
	edit_port->setText(QString::number(entry.ServerPort));
	edit_ID->setText(toQString(entry.ClientID));
	edit_token->setText(toQString(entry.RegisterToken));

	if (!entry.ServerPubKey.empty()) {
		QString b64 = toQString(entry.ServerPubKey);
		b64.remove(QRegularExpression("\\s"));
		QString body;
		for (int i = 0; i < b64.size(); i += 64)
			body += b64.mid(i, 64) + "\n";
		input_pubkey->setPlainText("-----BEGIN PUBLIC KEY-----\n" + body + "-----END PUBLIC KEY-----\n");
	}

	edit_name->setStyleSheet(edit_Style);
	edit_ip->setStyleSheet(edit_Style);
	edit_port->setStyleSheet(edit_Style);
	edit_ID->setStyleSheet(edit_Style);
	edit_token->setStyleSheet(edit_Style);
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

	QPushButton* btn_OK = new QPushButton("确认", &dia);
	QPushButton* btn_NO = new QPushButton("取消", &dia);
	QPushButton* btn_Del = new QPushButton("删除", &dia);
	QHBoxLayout* btnLayout = new QHBoxLayout();
	btnLayout->addStretch();
	btnLayout->addWidget(btn_OK);
	btnLayout->addWidget(btn_NO);
	btnLayout->addWidget(btn_Del);
	btn_OK->setFixedHeight(32);
	btn_NO->setFixedHeight(32);
	btn_Del->setFixedHeight(32);

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
	QString btnDelStyle = R"(
QPushButton{
	background-color:#FF6666;
	color:#111111;
	border:none;
	border-radius:8px;
}
QPushButton:hover{background-color:#FF0000;}
	)";
	btn_OK->setStyleSheet(btnOkStyle);
	btn_OK->setCursor(Qt::PointingHandCursor);
	btn_NO->setStyleSheet(btnNoStyle);
	btn_NO->setCursor(Qt::PointingHandCursor);
	btn_Del->setStyleSheet(btnDelStyle);
	btn_Del->setCursor(Qt::PointingHandCursor);

	lay->addWidget(lab_name);
	lay->addWidget(edit_name);
	lay->addWidget(lab_ip);
	lay->addWidget(edit_ip);
	lay->addWidget(lab_port);
	lay->addWidget(edit_port);
	lay->addWidget(Cilent_id);
	lay->addWidget(edit_ID);
	lay->addWidget(lab_token);
	lay->addWidget(edit_token);
	lay->addWidget(pubkey_label);
	lay->addWidget(input_pubkey);
	lay->addStretch();
	lay->addLayout(btnLayout);

	connect(btn_OK, &QPushButton::clicked, &dia, [&]() {
		bool portOk = false;
		const int port = edit_port->text().trimmed().toInt(&portOk);
		if (!portOk || port < 1 || port > 65535) {
			QMessageBox::warning(&dia, "提示", "端口无效：应为 1-65535 的数字");
			return;
		}

		QString pk = input_pubkey->toPlainText();
		pk.remove(QRegularExpression("\\s"));
		pk.remove(QRegularExpression("-+BEGIN[^-]*?-+"));
		pk.remove(QRegularExpression("-*END[^-]*?-+"));
		pk.remove(QRegularExpression("-+"));
		if (!pk.isEmpty() && pk.size() != 60) {
			QMessageBox::warning(&dia, "提示",
				QString("服务器公钥格式无效：应为 60 位 base64（server_sig.pub 的正文行），当前为 %1 位。\n"
					"注意：不要复制 registered_clients.txt 里的 hex 或客户端日志整段；\n"
					"留空 = 使用内置公钥。").arg(pk.size()));
			return;
		}
		dia.accept();
	});
	connect(btn_NO, &QPushButton::clicked, &dia, &QDialog::reject);
	connect(btn_Del, &QPushButton::clicked, &dia, [&] {
		int msg = QMessageBox::question(this,
			"确认", "确认此操作?",
			QMessageBox::Yes | QMessageBox::No,
			QMessageBox::No
			);
		if (msg == QMessageBox::Yes) {
			const cfgstr inipath = cfg_path_join(cfg_app_dir(), CS("config.ini"));
			IniDelSection(inipath, CS("Server") + cfg_num(m_selectedCard + 1));
			const int cnt = IniGetInt(inipath, CS("Server"), CS("Count"), 0);
			IniSetInt(inipath, CS("Server"), CS("Count"), qMax(0, cnt - 1));
			m_selectedCard = -1;
			Read_iniFile();
			dia.reject();
		}
	});
	if (dia.exec() != QDialog::Accepted)
		return;

	const QString newIP = edit_ip->text().trimmed();
	const QString newID = edit_ID->text().trimmed();
	const QString newToken = edit_token->text().trimmed();
	const QString newName = edit_name->text().trimmed();

	if (newIP.isEmpty()) {
		QMessageBox::warning(this, "提示", "服务器 IP 不能为空");
		return;
	}
	if (newID.isEmpty()) {
		QMessageBox::warning(this, "提示", "ClientID 不能为空");
		return;
	}

	bool portOk = false;
	const int newPort = edit_port->text().trimmed().toInt(&portOk);
	if (!portOk || newPort < 1 || newPort > 65535) {
		QMessageBox::warning(this, "提示", "端口无效：应为 1-65535 的数字");
		return;
	}

	QString pubkeyB64 = input_pubkey->toPlainText();
	pubkeyB64.remove(QRegularExpression("\\s"));
	pubkeyB64.remove(QRegularExpression("-+BEGIN[^-]*?-+"));
	pubkeyB64.remove(QRegularExpression("-*END[^-]*?-+"));
	pubkeyB64.remove(QRegularExpression("-+"));

	if (pubkeyB64.size() != 60)
	{
		pubkeyB64.clear();
	}

	const cfgstr inipath = cfg_path_join(cfg_app_dir(), CS("config.ini"));
	const cfgstr sec = CS("Server") + cfg_num(idx + 1);
	IniSetStr(inipath, sec, CS("Name"),
	          fromQString(newName.isEmpty() ? QString("computer%1").arg(idx + 1) : newName));
	IniSetStr(inipath, sec, CS("ServerIP"), fromQString(newIP));
	IniSetInt(inipath, sec, CS("ServerPort"), newPort);
	IniSetStr(inipath, sec, CS("ClientID"), fromQString(newID));
	IniSetStr(inipath, sec, CS("RegisterToken"), fromQString(newToken));
	IniSetStr(inipath, sec, CS("ServerPubKey"), fromQString(pubkeyB64));

	Read_iniFile();
}

void QtWidgetsClass::update_speed()
{
	if (!m_bridge)
		return;
	const uint64_t rx = m_bridge->rx_bytes();
	const uint64_t tx = m_bridge->tx_bytes();
	if (m_speedFirst) {
		m_speedFirst = false;
	}
	else if (m_speedChart) {
		m_speedChart->push_sample(double(rx - m_rxLast), double(tx - m_txLast));
	}
	m_rxLast = rx;
	m_txLast = tx;
}

namespace {

const QString kRunKey =
	QStringLiteral("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
const QString kRunValue = QStringLiteral("ScholarVPN");

QString autostart_command()
{
	return QLatin1Char('"')
		+ QDir::toNativeSeparators(QCoreApplication::applicationFilePath())
		+ QLatin1Char('"');
}

bool autostart_is_enabled()
{
	QSettings reg(kRunKey, QSettings::NativeFormat);
	const QString value = reg.value(kRunValue).toString();
	if (value.isEmpty())
		return false;
	return value.contains(QDir::toNativeSeparators(QCoreApplication::applicationFilePath()),
		Qt::CaseInsensitive);
}

bool autostart_set(bool enable)
{
	QSettings reg(kRunKey, QSettings::NativeFormat);
	if (enable)
		reg.setValue(kRunValue, autostart_command());
	else
		reg.remove(kRunValue);
	reg.sync();
	return reg.status() == QSettings::NoError;
}

}

void QtWidgetsClass::show_service_blocked_box(const QString& reason)
{
	QMessageBox* box = new QMessageBox(QMessageBox::Warning,
		QStringLiteral("服务不可用"), reason, QMessageBox::NoButton, this);
	box->setWindowFlags(box->windowFlags() & ~Qt::WindowCloseButtonHint);
	box->setEscapeButton(nullptr);
	QPushButton* refresh = box->addButton(QStringLiteral("刷新状态"),
	                                      QMessageBox::ActionRole);
	QPushButton* quitBtn = box->addButton(QStringLiteral("退出"),
	                                      QMessageBox::ActionRole);
	m_svcBox = box;
	connect(refresh, &QPushButton::clicked, this, [this]() {
		if (!m_svcCheckPending)
		{
			m_svcCheckPending = true;
			m_bridge->check_service();
		}
	});
	connect(quitBtn, &QPushButton::clicked, this, []() { qApp->quit(); });
	box->exec();
	m_svcBox = nullptr;
	delete box;
}

std::vector<ServerEntry> QtWidgetsClass::read_server_entries(const cfgstr& ini_path, int* countOut)
{
	const int count = IniGetInt(ini_path, CS("Server"), CS("Count"), 0);
	if (countOut != nullptr)
	{
		*countOut = count;
	}
	std::vector<ServerEntry> list;
	for (int i = 1; i <= count; ++i)
	{
		const cfgstr sec = CS("Server") + cfg_num(i);
		ServerEntry e;
		e.Name = IniGetStr(ini_path, sec, CS("Name"), CS(""));
		e.ServerIP = IniGetStr(ini_path, sec, CS("ServerIP"), CS(""));
		e.ServerPort = IniGetInt(ini_path, sec, CS("ServerPort"), 51820);
		e.transport = IniGetInt(ini_path, sec, CS("Transport"), 0) ? 1 : 0;
		e.ClientID = IniGetStr(ini_path, sec, CS("ClientID"), CS(""));
		e.RegisterToken = IniGetStr(ini_path, sec, CS("RegisterToken"), CS(""));
		e.ServerPubKey = IniGetStr(ini_path, sec, CS("ServerPubKey"), CS(""));
		e.managed = IniGetInt(ini_path, sec, CS("Managed"), 0) != 0;
		list.push_back(e);
	}
	return list;
}

void QtWidgetsClass::write_server_entries(const cfgstr& ini_path, int oldCount,
                                          const std::vector<ServerEntry>& list)
{
	for (int i = 1; i <= oldCount; ++i)
	{
		IniDelSection(ini_path, CS("Server") + cfg_num(i));
	}
	for (std::size_t i = 0; i < list.size(); ++i)
	{
		const cfgstr sec = CS("Server") + cfg_num(static_cast<long long>(i) + 1);
		IniSetStr(ini_path, sec, CS("Name"), list[i].Name);
		IniSetStr(ini_path, sec, CS("ServerIP"), list[i].ServerIP);
		IniSetInt(ini_path, sec, CS("ServerPort"), list[i].ServerPort);
		IniSetInt(ini_path, sec, CS("Transport"), list[i].transport);
		IniSetStr(ini_path, sec, CS("ClientID"), list[i].ClientID);
		IniSetStr(ini_path, sec, CS("RegisterToken"), list[i].RegisterToken);
		IniSetStr(ini_path, sec, CS("ServerPubKey"), list[i].ServerPubKey);
		IniSetInt(ini_path, sec, CS("Managed"), list[i].managed ? 1 : 0);
	}
	IniSetInt(ini_path, CS("Server"), CS("Count"), static_cast<int>(list.size()));
}

void QtWidgetsClass::apply_managed_servers(int count)
{
	Q_UNUSED(count);
	std::vector<service::ManagedServer> list = m_bridge->take_managed_servers();
	const cfgstr iniPath = cfg_path_join(cfg_app_dir(), CS("config.ini"));

	if (list.empty())
	{
		if (m_setting)
		{
			m_setting->applyServiceServers(QStringLiteral("服务器列表为空"));
		}
		return;
	}

	int oldCount = 0;
	const std::vector<ServerEntry> existing = read_server_entries(iniPath, &oldCount);
	const QStringList oldManaged = toQString(
	    IniGetStr(iniPath, CS("Service"), CS("ManagedServers"), CS("")))
	    .split(QLatin1Char(','), Qt::SkipEmptyParts);

	std::vector<ServerEntry> keep;
	for (const auto& e : existing)
	{
		const QString addr = toQString(e.ServerIP) + QLatin1Char(':')
		                   + QString::number(e.ServerPort);
		if (!oldManaged.contains(addr))
		{
			keep.push_back(e);
		}
	}

	const QString svcId = toQString(IniGetStr(iniPath, CS("Service"), CS("ClientID"), CS("")));
	const QString svcToken = toQString(IniGetStr(iniPath, CS("Service"), CS("Token"), CS("")));
	QString managedList;
	for (const auto& s : list)
	{
		std::string ip;
		int port = 0;
		if (!service::split_addr(s.addr, ip, port))
		{
			continue;
		}
		ServerEntry e;
		e.Name = to_cfgstr(s.remark.empty() ? s.addr : s.remark);
		e.ServerIP = fromQString(QString::fromStdString(ip));
		e.ServerPort = port;
		e.ClientID = fromQString(svcId);
		e.RegisterToken = fromQString(svcToken);
		e.ServerPubKey = fromQString(QString::fromStdString(s.pubkey_b64));
		e.managed = true;
		e.transport = 1;
		{
			const QString addr = QString::fromStdString(s.addr);
			for (const auto& old : existing)
			{
				if (toQString(old.ServerIP) + QLatin1Char(':') +
				        QString::number(old.ServerPort) == addr)
				{
					e.transport = old.transport;
					break;
				}
			}
		}
		keep.push_back(e);
		managedList += QString::fromStdString(s.addr) + QLatin1Char(',');
	}
	if (!managedList.isEmpty())
	{
		managedList.chop(1);
	}

	write_server_entries(iniPath, oldCount, keep);
	IniSetStr(iniPath, CS("Service"), CS("ManagedServers"), fromQString(managedList));

	m_selectedCard = -1;
	Read_iniFile();
	if (m_setting)
	{
		m_setting->applyServiceServers(
		    QStringLiteral("已下发 %1 台受管服务器（共 %2 张卡片）")
		        .arg(static_cast<int>(list.size()))
		        .arg(static_cast<int>(keep.size())));
	}
}

void QtWidgetsClass::remove_managed_cards()
{
	const cfgstr iniPath = cfg_path_join(cfg_app_dir(), CS("config.ini"));
	const QStringList managed = toQString(
	    IniGetStr(iniPath, CS("Service"), CS("ManagedServers"), CS("")))
	    .split(QLatin1Char(','), Qt::SkipEmptyParts);
	if (managed.isEmpty())
	{
		return;
	}
	int oldCount = 0;
	const std::vector<ServerEntry> existing = read_server_entries(iniPath, &oldCount);
	std::vector<ServerEntry> keep;
	for (const auto& e : existing)
	{
		const QString addr = toQString(e.ServerIP) + QLatin1Char(':')
		                   + QString::number(e.ServerPort);
		if (!managed.contains(addr))
		{
			keep.push_back(e);
		}
	}
	if (keep.size() == existing.size())
	{
		return;
	}
	write_server_entries(iniPath, oldCount, keep);
	m_selectedCard = -1;
	Read_iniFile();
}

Setting::Setting(QWidget* parent, AppBridge* bridge, int initialPage)
	: QDialog(parent), m_bridge(bridge), m_initialPage(initialPage)
{
	create_setting();
}

Setting::~Setting() = default;

void Setting::create_setting()
{
	setWindowTitle(QStringLiteral("设置"));

	constexpr int SETTING_DLG_MIN_WIDTH = 430;
	constexpr int SETTING_DLG_MAX_WIDTH = 520;
	constexpr int SETTING_DLG_HEIGHT = 460;
	constexpr int NAV_WIDTH = 112;

	int dlgWidth = SETTING_DLG_MIN_WIDTH;
	if (parentWidget())
	{
		dlgWidth = qMin(parentWidget()->width(), SETTING_DLG_MAX_WIDTH);
	}
	setFixedSize(dlgWidth, SETTING_DLG_HEIGHT);

	if (parentWidget())
	{
		this->move(parentWidget()->window()->frameGeometry().center() - this->frameGeometry().center());
	}

	setStyleSheet("QDialog{ background-color:#f7f8fc; }");
	auto* root = new QVBoxLayout(this);
	root->setContentsMargins(18, 16, 18, 16);
	root->setSpacing(12);

	QLabel* title = new QLabel(QStringLiteral("设置"), this);
	title->setStyleSheet("font-size:15pt; font-weight:bold; color:#1f2937; background:transparent;");
	root->addWidget(title);

	auto* body = new QHBoxLayout;
	body->setSpacing(14);

	QListWidget* nav = new QListWidget(this);
	nav->setFixedWidth(NAV_WIDTH);
	nav->setFrameShape(QFrame::NoFrame);
	nav->setStyleSheet(R"(
    QListWidget{ background:transparent; border:none; outline:none; }
    QListWidget::item{ height:32px; border-radius:10px; padding-left:12px; color:#5b6472; font-size:9pt; }
    QListWidget::item:selected{ background-color:#e8f0fe; color:#2563eb; font-weight:bold; }
    QListWidget::item:hover{ background-color:#eef2fa; }
    )");
	nav->addItem(QStringLiteral("通用"));
	nav->addItem(QStringLiteral("服务"));
	nav->addItem(QStringLiteral("关于"));
	nav->setCurrentRow(m_initialPage);

	QStackedWidget* stack = new QStackedWidget(this);

	QWidget* generalPage = new QWidget;
	auto* genLay = new QVBoxLayout(generalPage);
	genLay->setContentsMargins(0, 0, 0, 0);
	genLay->setSpacing(8);

	QFrame* card = new QFrame(generalPage);
	card->setObjectName("setCard");
	card->setStyleSheet(R"(
    QFrame#setCard{ background-color:#ffffff; border:1px solid #e8ecf3; border-radius:12px; }
    )");
	auto* cardLay = new QVBoxLayout(card);
	cardLay->setContentsMargins(14, 12, 14, 12);
	cardLay->setSpacing(6);

	m_chkAutoStart = new QCheckBox(QStringLiteral("开机自启动"), card);
	m_chkAutoStart->setCursor(Qt::PointingHandCursor);
	m_chkAutoStart->setStyleSheet("font-size:10pt; color:#1f2937; background:transparent;");
	m_chkAutoStart->setChecked(autostart_is_enabled());
	cardLay->addWidget(m_chkAutoStart);

	QLabel* hint = new QLabel(
		QStringLiteral("开机后自动启动 ScholarVPN（当前用户，无需管理员权限）"), card);
	hint->setStyleSheet("font-size:8pt; color:#9aa3b8; background:transparent;");
	hint->setWordWrap(true);
	cardLay->addWidget(hint);

	genLay->addWidget(card);
	genLay->addStretch();
	stack->addWidget(generalPage);

	build_about_page(stack, nav);
	build_service_page(stack, nav);

	connect(nav, &QListWidget::currentRowChanged, stack, &QStackedWidget::setCurrentIndex);
	body->addWidget(nav);
	body->addWidget(stack, 1);
	root->addLayout(body, 1);

	auto* btnRow = new QHBoxLayout;
	btnRow->setSpacing(10);
	btnRow->addStretch();

	QPushButton* btnCancel = new QPushButton(QStringLiteral("取消"), this);
	btnCancel->setFixedSize(96, 36);
	btnCancel->setCursor(Qt::PointingHandCursor);
	btnCancel->setStyleSheet(R"(
    QPushButton{
        background-color:#ffffff;
        border:1px solid #e2e6ee;
        border-radius:18px;
        color:#5b6472;
        font-size:10pt;
    }
    QPushButton:hover{ border:1px solid #3b82f6; color:#2563eb; }
    QPushButton:pressed{ background-color:#eef2fa; }
    )");
	connect(btnCancel, &QPushButton::clicked, this, &QDialog::reject);

	QPushButton* btnOk = new QPushButton(QStringLiteral("确认"), this);
	btnOk->setFixedSize(96, 36);
	btnOk->setCursor(Qt::PointingHandCursor);
	btnOk->setDefault(true);
	btnOk->setStyleSheet(R"(
    QPushButton{
        background-color:#2563eb;
        border:none;
        border-radius:18px;
        color:white;
        font-size:10pt;
        font-weight:bold;
    }
    QPushButton:hover{ background-color:#2f6fe8; }
    QPushButton:pressed{ background-color:#1e56b8; }
    )");
	connect(btnOk, &QPushButton::clicked, this, [this]() {
		if (!autostart_set(m_chkAutoStart->isChecked()))
		{
			QMessageBox::warning(this, QStringLiteral("设置失败"),
				QStringLiteral("无法写入开机自启动项（注册表 HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run）。"));
			return;
		}
		accept();
		});

	btnRow->addWidget(btnCancel);
	btnRow->addWidget(btnOk);
	root->addLayout(btnRow);
}

void Setting::build_about_page(QStackedWidget* stack, QListWidget* nav)
{
	QWidget* page = new QWidget;
	auto* lay = new QVBoxLayout(page);
	lay->setContentsMargins(0, 0, 0, 0);
	lay->setSpacing(8);

	QFrame* card = new QFrame(page);
	card->setObjectName("setCard");
	card->setStyleSheet(
	    "QFrame#setCard{ background-color:#ffffff; border:1px solid #e8ecf3; border-radius:12px; }");
	auto* cl = new QVBoxLayout(card);
	cl->setContentsMargins(14, 12, 14, 12);
	cl->setSpacing(6);

	QLabel* name = new QLabel(QStringLiteral("ScholarVPN"), card);
	name->setStyleSheet(
	    "font-size:13pt; font-weight:bold; color:#1f2937; background:transparent;");
	cl->addWidget(name);

	m_aboutVer = new QLabel(QStringLiteral("版本 v") + QStringLiteral(SCHOLARVPN_VER_STRING), card);
	m_aboutVer->setStyleSheet("font-size:10pt; color:#5b6472; background:transparent;");
	cl->addWidget(m_aboutVer);

	m_btnCheck = new QPushButton(QStringLiteral("检查更新"), card);
	m_btnCheck->setCursor(Qt::PointingHandCursor);
	m_btnCheck->setFixedHeight(30);
	m_btnCheck->setStyleSheet(
	    "QPushButton{background-color:#e8f0fe;border:1px solid #b9d3f0;border-radius:8px;"
	    "color:#2563eb;font-size:10pt;}"
	    "QPushButton:disabled{color:#9aa3b8;background:#f1f3f7;}");
	connect(m_btnCheck, &QPushButton::clicked, this, [this]() {
		if (m_bridge == nullptr)
		{
			return;
		}
		m_aboutStatus->setText(QStringLiteral("检查中..."));
		m_bridge->check_update();
	});
	cl->addWidget(m_btnCheck);

	m_aboutStatus = new QLabel(
	    QStringLiteral("是否需要更新由服务端策略决定"), card);
	m_aboutStatus->setStyleSheet("font-size:9pt; color:#6b7280; background:transparent;");
	m_aboutStatus->setWordWrap(true);
	cl->addWidget(m_aboutStatus);

	m_btnUpdateNow = new QPushButton(QStringLiteral("立即更新"), card);
	m_btnUpdateNow->setCursor(Qt::PointingHandCursor);
	m_btnUpdateNow->setFixedHeight(30);
	m_btnUpdateNow->hide();
	m_btnUpdateNow->setStyleSheet(
	    "QPushButton{background-color:qlineargradient(x1:0,y1:0,x2:0,y2:1,"
	    "stop:0 #4f8ef7,stop:1 #2563eb);border:none;border-radius:8px;"
	    "color:white;font-size:10pt;font-weight:bold;}"
	    "QPushButton:disabled{background:#c9d4e5;}");
	connect(m_btnUpdateNow, &QPushButton::clicked, this, [this]() {
		if (m_bridge == nullptr || m_url.isEmpty() || m_sha256.isEmpty())
		{
			return;
		}
		m_btnCheck->setEnabled(false);
		m_btnUpdateNow->setEnabled(false);
		m_btnUpdateNow->setText(QStringLiteral("下载中..."));
		m_bridge->download_and_install(m_url, m_sha256, m_size, m_latest);
	});
	cl->addWidget(m_btnUpdateNow);

	lay->addWidget(card);
	lay->addStretch();
	stack->addWidget(page);
}

void Setting::applyUpdateInfo(int status, int action, const QString& latest,
                              const QString& notes, const QString& err,
                              const QString& url, const QString& sha256, quint64 size)
{
	m_url = url;
	m_sha256 = sha256;
	m_latest = latest;
	m_notes = notes;
	m_size = size;
	if (m_bridge != nullptr)
	{
		m_bridge->set_update_blocked(status == 1 || (status == 0 && action == 2));
	}

	if (status == 1)
	{
		m_aboutStatus->setText(QStringLiteral("更新信息校验失败：%1").arg(err));
		m_btnUpdateNow->hide();
		return;
	}
	if (status == 0 && action == 2)
	{
		m_aboutStatus->setText(
		    QStringLiteral("当前版本已不被支持，必须更新到 v%1。").arg(latest));
		m_btnUpdateNow->show();
		m_btnUpdateNow->setText(QStringLiteral("立即更新"));
		m_btnUpdateNow->setEnabled(true);
		m_btnCheck->setEnabled(true);
		return;
	}
	if (status == 0 && action == 1)
	{
		m_aboutStatus->setText(
		    notes.isEmpty() ? QStringLiteral("发现新版本 v%1").arg(latest)
		                    : QStringLiteral("发现新版本 v%1：").arg(latest) + notes);
		m_btnUpdateNow->show();
		m_btnUpdateNow->setText(QStringLiteral("立即更新"));
		m_btnUpdateNow->setEnabled(true);
		m_btnCheck->setEnabled(true);
		return;
	}
	if (status == 0)
	{
		m_aboutStatus->setText(QStringLiteral("已是最新版本"));
		m_btnUpdateNow->hide();
		return;
	}
	if (!err.contains(QStringLiteral("未启用")))
	{
		m_aboutStatus->setText(QStringLiteral("检查失败：%1").arg(err));
	}
}

void Setting::applyDownloadProgress(int pct)
{
	if (m_btnUpdateNow != nullptr)
	{
		m_btnUpdateNow->setText(pct >= 0 ? QStringLiteral("下载中 %1%").arg(pct)
		                                 : QStringLiteral("下载中..."));
	}
}

void Setting::applyDownloadFinished(bool ok, const QString& err)
{
	if (ok)
	{
		if (m_aboutStatus != nullptr)
		{
			m_aboutStatus->setText(QStringLiteral("安装器已启动，程序即将退出…"));
		}
		return;
	}
	if (m_btnCheck != nullptr)
	{
		m_btnCheck->setEnabled(true);
	}
	if (m_btnUpdateNow != nullptr)
	{
		m_btnUpdateNow->setEnabled(true);
		m_btnUpdateNow->setText(QStringLiteral("立即更新"));
	}
	if (m_aboutStatus != nullptr)
	{
		m_aboutStatus->setText(QStringLiteral("更新失败：%1").arg(err));
	}
}

void Setting::build_service_page(QStackedWidget* stack, QListWidget* nav)
{
	Q_UNUSED(nav);
	QWidget* page = new QWidget;
	auto* lay = new QVBoxLayout(page);
	lay->setContentsMargins(0, 0, 0, 0);
	lay->setSpacing(8);

	QFrame* card = new QFrame(page);
	card->setObjectName("setSvcCard");
	card->setStyleSheet(
	    "QFrame#setSvcCard{ background-color:#ffffff; border:1px solid #e8ecf3; border-radius:12px; }");
	auto* cl = new QVBoxLayout(card);
	cl->setContentsMargins(14, 12, 14, 12);
	cl->setSpacing(6);

	QLabel* title = new QLabel(QStringLiteral("服务器来源"), card);
	title->setStyleSheet(
	    "font-size:13pt; font-weight:bold; color:#1f2937; background:transparent;");
	cl->addWidget(title);

	const bool managedNow = st_cfg_managed();

	QRadioButton* rbSelf = new QRadioButton(
	    QStringLiteral("自建服务器（自己搭建的服务端）"), card);
	QRadioButton* rbManaged = new QRadioButton(
	    QStringLiteral("使用服务方（第三方，自动下发）"), card);
	rbSelf->setCursor(Qt::PointingHandCursor);
	rbManaged->setCursor(Qt::PointingHandCursor);
	rbSelf->setStyleSheet("font-size:10pt; color:#1f2937; background:transparent;");
	rbManaged->setStyleSheet("font-size:10pt; color:#1f2937; background:transparent;");
	(managedNow ? rbManaged : rbSelf)->setChecked(true);
	connect(rbSelf, &QRadioButton::toggled, this, [this](bool on) {
		if (on && m_bridge != nullptr)
		{
			m_bridge->set_service_mode(false);
		}
	});
	connect(rbManaged, &QRadioButton::toggled, this, [this](bool on) {
		if (on && m_bridge != nullptr)
		{
			m_bridge->set_service_mode(true);
		}
	});
	cl->addWidget(rbSelf);
	cl->addWidget(rbManaged);

	m_svcDetail = new QLabel(card);
	m_svcDetail->setStyleSheet("font-size:9pt; color:#6b7280; background:transparent;");
	m_svcDetail->setWordWrap(true);
	cl->addWidget(m_svcDetail);

	const bool svcActive = managedNow;
	if (svcActive)
	{
		m_svcDetail->setText(QStringLiteral("向服务方申请 3 天 / 2GB 试用，由服务方确认转正式。"));

		auto* btnRow = new QHBoxLayout;
		btnRow->setSpacing(8);
		const QString btnStyle =
		    "QPushButton{background-color:#e8f0fe;border:1px solid #b9d3f0;border-radius:8px;"
		    "color:#2563eb;font-size:10pt;}"
		    "QPushButton:disabled{color:#9aa3b8;background:#f1f3f7;}";
		m_btnSvcApply = new QPushButton(QStringLiteral("申请试用"), card);
		m_btnSvcApply->setCursor(Qt::PointingHandCursor);
		m_btnSvcApply->setFixedHeight(30);
		m_btnSvcApply->setStyleSheet(btnStyle);
		connect(m_btnSvcApply, &QPushButton::clicked, this, [this]() {
			if (m_bridge == nullptr) return;
			m_btnSvcApply->setEnabled(false);
			m_svcStatus->setText(QStringLiteral("申请中..."));
			m_bridge->register_service();
		});
		btnRow->addWidget(m_btnSvcApply);
		m_btnSvcRefresh = new QPushButton(QStringLiteral("刷新状态"), card);
		m_btnSvcRefresh->setCursor(Qt::PointingHandCursor);
		m_btnSvcRefresh->setFixedHeight(30);
		m_btnSvcRefresh->setStyleSheet(btnStyle);
		connect(m_btnSvcRefresh, &QPushButton::clicked, this, [this]() {
			if (m_bridge == nullptr) return;
			m_svcStatus->setText(QStringLiteral("检查中..."));
			m_bridge->check_service();
			m_bridge->apply_server_list();
		});
		btnRow->addWidget(m_btnSvcRefresh);
		cl->addLayout(btnRow);
	}
	else
	{
		m_svcDetail->setText(
		    QStringLiteral("自建模式：不连接服务方，服务方下发的服务器已从列表移除。"));
	}

	m_svcStatus = new QLabel(QStringLiteral("—"), card);
	m_svcStatus->setStyleSheet("font-size:9pt; color:#6b7280; background:transparent;");
	m_svcStatus->setWordWrap(true);
	cl->addWidget(m_svcStatus);

	lay->addWidget(card);
	lay->addStretch();
	stack->insertWidget(1, page);
}

bool Setting::st_cfg_managed() const
{
	const cfgstr iniPath = cfg_path_join(cfg_app_dir(), CS("config.ini"));
	return IniGetStr(iniPath, CS("Service"), CS("Mode"), CS("")) == CS("managed");
}

void Setting::applyServiceInfo(int blocked, const QString& reason, const QString& fp,
                               const QString& clientId, const QString& status,
                               qulonglong expire, qulonglong quota, qulonglong used,
                               const QString& err)
{
	Q_UNUSED(reason);
	if (m_svcStatus == nullptr)
	{
		return;
	}
	if (m_btnSvcApply != nullptr)
	{
		m_btnSvcApply->setEnabled(true);
	}
	if (!err.isEmpty())
	{
		m_svcStatus->setText(QStringLiteral("失败：%1").arg(err));
		return;
	}

	QString text;
	if (status.isEmpty())
	{
		text = QStringLiteral("尚未申请试用");
	}
	else if (status == QStringLiteral("approved"))
	{
		text = QStringLiteral("已授权（不限流量不限期）");
	}
	else if (status == QStringLiteral("rejected"))
	{
		text = QStringLiteral("申请已被拒绝，请联系服务方");
	}
	else if (status == QStringLiteral("revoked"))
	{
		text = QStringLiteral("授权已被服务方取消，请联系服务方");
	}
	else if (status == QStringLiteral("trial"))
	{
		QString detail;
		if (expire > 0)
		{
			const qint64 remain = qint64(expire)
			                      - qint64(QDateTime::currentSecsSinceEpoch());
			detail += (remain > 0) ? QStringLiteral("剩余 %1 小时").arg(remain / 3600)
			                       : QStringLiteral("已到期，等待服务方确认授权");
		}
		if (quota > 0)
		{
			detail += QStringLiteral("　已用 %1 MB / %2 MB")
			              .arg(used / (1024ull * 1024ull))
			              .arg(quota / (1024ull * 1024ull));
		}
		text = QStringLiteral("试用中：") + detail;
	}
	else
	{
		text = QStringLiteral("状态：") + status;
	}
	if (blocked == 1)
	{
		text = QStringLiteral("⛔ ") + text;
	}
	m_svcStatus->setText(text);

	if (!clientId.isEmpty() && m_svcDetail != nullptr)
	{
		m_svcDetail->setText(QStringLiteral("账号 %1　机器指纹 %2…")
		                         .arg(clientId, fp.left(12)));
		m_svcDetail->setToolTip(fp);
		m_svcDetail->setTextInteractionFlags(Qt::TextSelectableByMouse);
	}
}

void Setting::applyServiceServers(const QString& text)
{
	if (m_svcStatus != nullptr)
	{
		m_svcStatus->setText(text);
	}
}
