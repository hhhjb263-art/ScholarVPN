#include "QtWidgetsClass.h"
#include "QtCfg.h"   // toQString / fromQString（cfgstr <-> QString 的唯一桥）
#include "util/utf.h"   // to_cfgstr / narrow（受管服务卡片合并写回 cfgstr 用）
#include "CenteredComboBox.h"
#include "version.h"   // SCHOLARVPN_VER_STRING   // 只重写绘制、不改行为的居中下拉框
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QScrollArea>
#include <QPushButton>
#include <QSettings>
#include <QFont>
#include <QDialog>
#include <QCheckBox>
#include <QMessageBox>
#include <QTimer>
#include <QDir>
#include <QListWidget>
#include <QStackedWidget>
#include <QPlainTextEdit>
#include <QRadioButton>
#include <QRegularExpression>
#include <QStyle>
#include <QDateTime>

using namespace scholini;   // config.ini 的 INI 原语

namespace {
// 受管服务用量显示的字节格式化（主页用量条与设置页共用语义）
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
} // namespace
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


	// 设置按钮（齿轮）：打开设置子页面（含「通用」栏 / 开机自启动）。
	// 放品牌左侧，与右侧"添加服务器"按钮对称，样式保持一致。
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
	m_cardLayout->addStretch();            // 卡片靠顶部排布

	m_scroll->setWidget(m_cardContainer);

	
	m_diaCard = new QWidget(this);
	m_diaCard->setGeometry(this->rect());     // 铺满主窗口
	m_diaCard->hide();

	auto* overlayLay = new QVBoxLayout(m_diaCard);
	overlayLay->setContentsMargins(0, 0, 0, 0);
	overlayLay->setSpacing(0);

	// 顶部 200px 半透明区：透出底下的主页面；
	m_glassTop = new QWidget;
	m_glassTop->setFixedHeight(200);
	m_glassTop->setStyleSheet("background-color: rgba(15, 23, 42, 135);");
	m_glassTop->installEventFilter(this);     // 点击半透明区收起
	m_glassTop->setCursor(Qt::PointingHandCursor);

	// 半透明区里的摘要卡
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

	// 半透明
	auto* glassTopLay = new QVBoxLayout(m_glassTop);
	glassTopLay->setContentsMargins(16, 48, 16, 16);
	glassTopLay->addWidget(m_glassCard);
	glassTopLay->addStretch();

	// 下方
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

	// 显示当前选择的服务器
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

	// 连接状态色条（卡片左缘，随状态变色：蓝=空闲 绿=已连 橙=连接中 红=错误）
	m_homeAccent = new QFrame(m_homeCard);
	m_homeAccent->setGeometry(0, 24, 4, 128);
	m_homeAccent->setStyleSheet("background-color:#3b82f6; border-top-left-radius:16px;"
	                            "border-bottom-left-radius:16px;");

	// 服务器头像圈：名称首字母 + 蓝青渐变底（与 Switch 卡片同款）
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

	// 受管服务的「受管服务」小徽标（仅受管卡片显示）
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

	// 受管服务用量：细进度条 + 文字（仅受管卡片显示）
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

	// 当前显示的服务器
	connect(m_homeBtn, &QPushButton::clicked, this, [this]() {
		if (m_selectedCard < 0 || m_selectedCard >= (int)m_cardServers.size())
			return;
		const ServerEntry entry = m_cardServers[m_selectedCard];
		if (m_state == ConnState::Stopped) {
			// 免 UAC 启动：普通用户可运行本程序（界面/托盘可用），但建立连接需要
			// 管理员权限（建 Wintun 网卡 / 改路由 / 改 DNS）。这里先拦截并明确告知，
			// 否则初始化在后台失败、日志又没接到界面上，用户只看到"点了没反应"。
			if (!ClientApp::is_elevated()) {
				QMessageBox::information(this, QStringLiteral("需要管理员权限"),
					QStringLiteral("建立 VPN 需要创建虚拟网卡、修改路由与 DNS，这些操作需要管理员权限。\n\n"
						"请关闭本程序，右键 ScholarVPN.exe →「以管理员身份运行」后再点击连接。"));
				return;
			}
			m_activeCard = m_selectedCard;
			// 必须投递到 bridge 所在线程（moveToThread 只作用于信号槽连接，直接调用
			// 会在 GUI 线程同步执行 init()/建网卡/restore() 等重型操作 → 界面卡死无响应）
			// 注意：lambda 里不能碰任何 QWidget（setEnabled 等）——它跑在 bridge 工作线程！
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
	// 编辑
	connect(m_homeEditBtn, &QPushButton::clicked, this, [this]() {
		if (m_selectedCard < 0 || m_selectedCard >= (int)m_cardServers.size())
			return;
		m_activeCard = m_selectedCard;   // edit_card 按 m_activeCard 取配置
		edit_card();
	});

	// 添加服务器
	m_homeHint = new QLabel("当前无服务器\n\n点击右上角「 + 添加服务器 」创建你的第一个配置", this);
	m_homeHint->setAlignment(Qt::AlignCenter);
	m_homeHint->setStyleSheet("color:#a0a8ba; font-size:10pt; background:transparent;");

	auto* homeArea = new QVBoxLayout;
	homeArea->setContentsMargins(14, 10, 14, 12);
	homeArea->setSpacing(10);
	homeArea->addWidget(m_homeCard, 0, Qt::AlignTop);

	// 速度折线图（原生自绘）
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
		// 分流模式是"下次连接生效"的全局设置：连接中禁用，
		// 避免 GUI 线程与 worker 线程同时改路由表
		const bool stopped = (s == ConnState::Stopped);
		if (m_btnGlobal) m_btnGlobal->setEnabled(stopped);
		if (m_btnSplit) m_btnSplit->setEnabled(stopped);
		update_home_btn();
		update_glass_card();

		// 重连达到上限（Error）：弹窗告知，用户手动重连
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

	// 服务端拒绝注册令牌（无效/已使用）：清掉当前卡片的令牌，转登录模式。
	// 否则令牌留在 m_cardServers / config.ini 里，下次连接又被 set_server 灌回去 → deny 1 死循环。
	// （若公钥其实已注册成功，清掉令牌后下次连接即以登录模式通过）
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

	// ---- 分流模式切换：全局 / 智能 ----
	// 全局：所有流量走隧道（原有行为，默认）
	// 智能：国内 IP 段走物理网卡，其余走隧道（依赖 exe 目录下的 chnroute.txt）
	//
	// 持久化只写 [Routing] Mode 这一个键，不调 ClientApp::save_config()——
	// 那会把整份配置写回，可能覆盖用户在卡片上刚改的 Transport。
	// 两个选项合成一个分段控件（胶囊）：与 Switch Server 同宽居中，
	// 选中项白底蓝字，视觉上是一个整体而不是两个悬空小按钮
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

	segLay->addWidget(m_btnGlobal);
	segLay->addWidget(m_btnSplit);

	// 初始状态以 config.ini 为准：ClientApp 在首次连接时才加载配置，
	// 这里如果读内存会拿到默认值，导致重启后按钮显示与实际不符。
	{
		const cfgstr modeIni = cfg_path_join(cfg_app_dir(), CS("config.ini"));
		const bool split = (IniGetStr(modeIni, CS("Routing"), CS("Mode"), CS("full"))
		                    == CS("split"));
		m_btnSplit->setChecked(split);
		m_btnGlobal->setChecked(!split);
		m_bridge->set_routing_split(split);   // 同步给运行时，避免第一次连接用旧值
	}

	auto apply_mode = [this](bool split) {
		const cfgstr modeIni = cfg_path_join(cfg_app_dir(), CS("config.ini"));
		IniSetStr(modeIni, CS("Routing"), CS("Mode"),
		          split ? CS("split") : CS("full"));
		m_bridge->set_routing_split(split);   // 只改内存，下次连接生效
		qDebug() << "routing mode ->" << (split ? "split" : "full");
	};
	connect(m_btnGlobal, &QPushButton::clicked, this, [apply_mode]() { apply_mode(false); });
	connect(m_btnSplit, &QPushButton::clicked, this, [apply_mode]() { apply_mode(true); });

	// 受管服务用量条（自建模式隐藏）：剩余时长 + 已用/配额，随 serviceChecked 刷新
	m_svcInfo = new QLabel(this);
	m_svcInfo->setGeometry(16, 716, 398, 24);
	m_svcInfo->setAlignment(Qt::AlignCenter);
	m_svcInfo->setStyleSheet("color:#8b94a6; font-size:9pt; background:transparent;");
	m_svcInfo->hide();

	// 启动时后台查一次：由服务端策略决定强制 / 可选 / 无需更新。
	// 结果的界面表现在全部在设置【关于】页。
	QTimer::singleShot(0, this, [this]() { m_bridge->check_update(); });

	connect(m_bridge, &AppBridge::updateChecked, this,
		[this](int status, int action, const QString& latest, const QString& notes, const QString& err,
		       const QString& url, const QString& sha256, quint64 size) {
			m_updateUrl = url;
			m_updateSha256 = sha256;
			m_updateLatest = latest;
			m_updateSize = size;
			// 包哈希比较（2026-11-02 需求 5）：已装包与服务器包一致 = 已是最新，
			// 与版本号无关（同版本重发的修复包也能触发提示）。版本号（minimum）
			// 只用于强制更新判定（大更新必须升级），非强制的提示以包差异为准。
			const cfgstr iniPathU = cfg_path_join(cfg_app_dir(), CS("config.ini"));
			const QString installedSha = toQString(
				IniGetStr(iniPathU, CS("Update"), CS("InstalledSha"), CS("")));
			if (!installedSha.isEmpty() && installedSha == sha256 && action == 1)
			{
				action = 0;   // optional → none：包一致，视为已是最新
			}
			// 界面表现在全部在设置【关于】页（开着才同步）
			if (m_setting)
			{
				m_setting->applyUpdateInfo(status, action, latest, notes, err, url, sha256, size);
			}
			// 全局约束：验签失败 / 强制 → 禁连接 + 阻塞弹窗
			//（Setting 无 Q_OBJECT 不能自己弹阻塞框，且它可能根本没开）
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

			// 循环 exec：点「立即更新」后弹窗不关闭，进度直接显示在按钮上；
			// 下载失败回到弹窗（按钮变「下载失败，点此重试」），用户可反复重试；
			// 成功或点「退出」才离开。
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
				// 下载中再次 exec：进度经 downloadProgress 显示在 primary 上
			}
		});

	// 下载进度：强制弹窗开着时显示在弹窗按钮上，否则显示在设置【关于】页
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
			// 记录已装包哈希：下次检查按包差异判断（不再只看版本号）
			{
				const cfgstr iniPathS = cfg_path_join(cfg_app_dir(), CS("config.ini"));
				IniSetStr(iniPathS, CS("Update"), CS("InstalledSha"),
				          cfg_from_utf8(m_updateSha256.toStdString()));
			}
#if defined(_WIN32)
			// Windows：Inno 已派发，/CLOSEAPPLICATIONS 会关掉本进程——主动退出让出文件锁
			qApp->quit();
#else
			// Linux：pkexec 已把新版装到 /opt（文件替换不需要退出），
			// 提示用户手动重启即用上新版
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

	// ---- 受管服务（受管试用 / 状态同步 / 列表自动填卡）----
	// 启动时同步一次：仅 Mode=managed 时发起（off = 自建，与旧行为完全一致）
	QTimer::singleShot(0, this, [this]() {
		const cfgstr iniPath = cfg_path_join(cfg_app_dir(), CS("config.ini"));
		if (IniGetStr(iniPath, CS("Service"), CS("Mode"), CS("")) == CS("managed"))
		{
			m_bridge->check_service();      // 状态/凭据同步
			m_bridge->apply_server_list();  // 列表同步：服务方改钥/改址后启动即跟进
		}
	});
	// 受管模式：每 5 分钟同步一次用量（服务端每 30s 才落库一次，别更勤）
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
			// 状态落盘（fp/凭据由 broker 返回为准；查失败不动已有值）
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
			// 闸门：blocked 才禁连接（同步失败=查不到→放行，与更新系统同语义）
			m_bridge->set_service_blocked(blocked == 1);

			// 主页用量条：受管模式显示剩余时长/流量（自建模式隐藏）
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
						update_home_usage();   // 主页卡片用量条同步
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

			// 设置【服务】页开着就同步显示
			if (m_setting)
			{
				m_setting->applyServiceInfo(blocked, reason, fp, clientId, status,
				                            expireAt, quotaBytes, usedBytes, err);
			}

			// 阻塞弹窗已开着：刷新结果直接更新/关闭它，绝不再叠新弹窗
			if (m_svcBox)
			{
				if (blocked != 1)
				{
					m_svcBox->accept();   // 已放行：关闭弹窗
					m_svcBox = nullptr;
				}
				else
				{
					m_svcBox->setText(reason);   // 仍被锁：原地更新原因
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
			// 凭据落盘（token 为一次性注册令牌，与 RegisterToken 同级敏感）
			const cfgstr iniPath = cfg_path_join(cfg_app_dir(), CS("config.ini"));
			IniSetStr(iniPath, CS("Service"), CS("Fp"), fromQString(fp));
			IniSetStr(iniPath, CS("Service"), CS("ClientID"), fromQString(clientId));
			IniSetStr(iniPath, CS("Service"), CS("Token"), fromQString(token));
			IniSetStr(iniPath, CS("Service"), CS("Status"), fromQString(status));
			IniSetStr(iniPath, CS("Service"), CS("ExpireAt"),
			          cfg_from_utf8(std::to_string(expireAt)));
			IniSetStr(iniPath, CS("Service"), CS("QuotaBytes"),
			          cfg_from_utf8(std::to_string(quotaBytes)));
			// 注册成功 → 自动拉服务器列表（serviceServers 里填卡）
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

	// 模式切换：切回自建时撤掉受管卡片（切到受管的填卡由 apply_server_list 异步完成）
	connect(m_bridge, &AppBridge::serviceModeChanged, this, [this](int managed) {
		if (managed == 0)
		{
			remove_managed_cards();
		}
	});

	// 受管模式下「+」新增不生效（服务器由服务方统一下发）：按钮保留，
	// 点击弹窗说明原因并可直达设置页；自建模式行为不变
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
			Setting dlg(this, m_bridge, 1);   // 直达「服务」页
			m_setting = &dlg;
			dlg.exec();
			m_setting = nullptr;
		}
	});

	// 每秒采样一次流量 → update_speed() 计算速率推入折线图
	auto* speedTimer = new QTimer(this);
	connect(speedTimer, &QTimer::timeout, this, &QtWidgetsClass::update_speed);
	speedTimer->start(1000);

	Read_iniFile();   // 读 config，为每台服务器建卡
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

// 读取 config.ini，为每台已配置的服务器建一张卡片
void QtWidgetsClass::Read_iniFile()
{
	delete m_cfg;
	m_cfg = new Config(cfg_path_join(cfg_app_dir(), CS("config.ini")),
		cfg_app_dir());
	ClientConfig cc;
	clear_cards();   // 先清旧卡

	if (m_cfg->LoadClientConfig(cc)) {
		// 主服务器 IP（Debug 优先 DebugServerIP，用于兼容旧字段）
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

	// 主页面只显示一张卡：选择优先于最新（从未选择过 → 显示最新添加的一张）
	if (m_selectedCard < 0 || m_selectedCard >= (int)m_cardServers.size())
		m_selectedCard = m_cardServers.isEmpty() ? -1 : (int)m_cardServers.size() - 1;
	show_home_card(m_selectedCard);
	update_dia_highlight();
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
	input_name->setStyleSheet(edit_Style);
	input_ip->setStyleSheet(edit_Style);
	input_port->setStyleSheet(edit_Style);
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

	// 公钥校验前移到确认时（与编辑服务器一致）：非法留在对话框提示，不静默清空
	connect(btn_OK, &QPushButton::clicked, &dia, [&]() {
		// 端口校验：1-65535
		bool portOk = false;
		const int port = input_port->text().trimmed().toInt(&portOk);
		if (!portOk || port < 1 || port > 65535) {
			QMessageBox::warning(&dia, "提示", "端口无效：应为 1-65535 的数字");
			return;   // 留在对话框
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
	const QString newName = input_name->text().trimmed();   // 空 = 用默认 computer+N
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

	// 追加到 [ServerN] 节（真正多服务器，含各自身份）
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

// dia 中的可选卡片：头像 + 名称 + IP，点击整卡选中（无连接/编辑按钮，操作都在主页面卡片上）
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

	// 头像：服务器名首字母，圆形渐变底
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
	lab_name->setGeometry(78, 22, 210, 26);   // 右侧留出传输下拉框的位置
	lab_name->setText(name);
	lab_name->setStyleSheet("background:transparent; font-size:11pt; font-weight:bold; color:#1f2937;");

	QLabel* lab_ip = new QLabel(card);
	lab_ip->setGeometry(78, 54, 210, 22);
	// 受管卡片不显示 IP/端口（服务方地址不暴露给使用者），改显官方标识（青色）
	lab_ip->setText(entry.managed ? QStringLiteral("官方服务 · 服务方下发") : ("IP: " + ip));
	lab_ip->setStyleSheet(entry.managed
	    ? "background:transparent; font-size:9pt; color:#0891b2;"
	    : "background:transparent; font-family:Consolas,'Courier New',monospace; font-size:9pt; color:#6b7280;");

	// 在线状态圆点：该服务器正处于已连接状态时显示（update_dia_highlight 维护）
	QLabel* dot = new QLabel(card);
	dot->setGeometry(286, 26, 8, 8);
	dot->setStyleSheet("background-color:#3fb950; border-radius:4px;");
	dot->hide();
	m_cardDots.append(dot);

	// 传输方式下拉框：UDP / TCP（userData = ServerEntry.transport，0=UDP 1=TCP）
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
	// 选择即持久化：写入该服务器的 Transport 配置并同步内存（连接时生效）
	connect(box_sock, &QComboBox::currentIndexChanged, this, [this, sockIdx, box_sock](int index) {
		if (sockIdx < 0 || sockIdx >= (int)m_cardServers.size())
			return;
		m_cardServers[sockIdx].transport = box_sock->itemData(index).toInt() ? 1 : 0;
		const cfgstr inipath = cfg_path_join(cfg_app_dir(), CS("config.ini"));
		IniSetInt(inipath, CS("Server") + cfg_num(sockIdx + 1),
		          CS("Transport"), m_cardServers[sockIdx].transport);
	});
	card->installEventFilter(this);   // 整卡可点 → 选中

	m_cardLayout->insertWidget(m_cardLayout->count() - 1, card);

	m_cards.append(card);
	m_cardServers.append(entry);
}

// dia 中点击某张卡片：设为当前选择 → 主页面更新 → 高亮 → 收起弹窗
void QtWidgetsClass::select_card(int index)
{
	if (index < 0 || index >= (int)m_cardServers.size())
		return;
	m_selectedCard = index;
	update_dia_highlight();
	show_home_card(index);
	if (m_diaCard)
		m_diaCard->hide();
}

// 刷新 dia 列表的选中高亮（当前主页面显示的卡片描边标蓝）
void QtWidgetsClass::update_dia_highlight()
{
	const bool online = (m_state == ConnState::Connected);
	for (int i = 0; i < m_cards.size(); ++i) {
		m_cards[i]->setProperty("selected", i == m_selectedCard);
		m_cards[i]->style()->unpolish(m_cards[i]);
		m_cards[i]->style()->polish(m_cards[i]);
	}
	// 在线圆点：只标当前已连接的那台服务器
	for (int i = 0; i < m_cardDots.size() && i < m_cards.size(); ++i) {
		m_cardDots[i]->setVisible(online && i == m_activeCard);
	}
}

// 半透明区摘要卡
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

	// 内网 IP：与主页面卡片一致（已连接时显示服务端分配的虚拟 IP）
	const QString vip = m_homeVip->text();
	m_glassVip->setText(vip == "内网IP: --" ? "内网IP: --" : vip);

	// 连接状态文字与颜色
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

// 主页面显示指定服务器的卡片（连接 + 编辑）
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
	// 受管卡片不显示「管理」：服务器与身份均由服务方下发，编辑会破坏受管语义
	m_homeEditBtn->setVisible(!e.managed);
	// 受管卡片：不显示 IP 等服务方地址信息，显示受管徽标 + 用量进度；
	// 服务器更换走 Switch 按钮（Switch 卡片只显示地名）
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
	update_glass_card();     // 覆盖层摘要卡跟随显示同一台服务器
}

// 受管服务的用量行/进度条（读最近一次同步进 config 的 [Service] 数据；
// 数据源由 serviceChecked 每 5 分钟/手动刷新写入，这里只做展示）
void QtWidgetsClass::update_home_usage()
{
	const cfgstr iniPath = cfg_path_join(cfg_app_dir(), CS("config.ini"));
	const std::string status = narrow(IniGetStr(iniPath, CS("Service"), CS("Status"), CS("")));
	if (status != "trial") {
		// 正式用户显示"已授权"，无进度条；非受管数据则整体隐藏
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

// 按当前连接状态刷新主页面"连接/断开"按钮（三态：蓝=连接 橙=连接中 红=断开）
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
	// 左缘状态色条与按钮同色系（空闲蓝/连接中橙/已连绿/错误红）
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

// 整卡点击选中
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
	// 覆盖层是主窗口子控件：显示时同步尺寸并抬到最顶（盖过 Switch 按钮等绝对定位控件）
	if (m_diaCard->isHidden()) {
		m_diaCard->setGeometry(this->rect());
		m_diaCard->show();
		m_diaCard->raise();
	} else {
		m_diaCard->hide();
	}
}

// 主窗口尺寸变化：覆盖层跟随铺满
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

	// 托盘图标：优先 Qt 资源，其次相对路径查找（基准为 exe 所在目录），
	// 最后回退系统标准图标。
	// 注意：本工程没有 .qrc，":/source/icon.ico" 实际取不到
	QIcon trayIcon(":/source/icon.ico");
	if (trayIcon.isNull()) {
		const QString dir = QCoreApplication::applicationDirPath();
		const QString candidates[] = {
			dir + "/icon.ico",                    // 相对 exe 目录：PostBuild 拷贝来的 icon.ico
			dir + "/source/icon.ico",             // 相对 exe 目录：exe 旁若有 source 子目录
			QStringLiteral("source/icon.ico")     // 相对当前工作目录（VS 调试时 cwd = 工程根）
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
			if (reason == QSystemTrayIcon::DoubleClick) //左键单击
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
		event->ignore(); // 忽略关闭事件，不退出
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

	// 公钥校验前移到确认时：非法直接提示并留在对话框，而不是静默清空后写空串
	connect(btn_OK, &QPushButton::clicked, &dia, [&]() {
		// 端口校验：1-65535
		bool portOk = false;
		const int port = edit_port->text().trimmed().toInt(&portOk);
		if (!portOk || port < 1 || port > 65535) {
			QMessageBox::warning(&dia, "提示", "端口无效：应为 1-65535 的数字");
			return;   // 留在对话框
		}

		QString pk = input_pubkey->toPlainText();
		// 稳健归一化：先去空白，再按标记词剥离 PEM 头尾（容忍横线缺失/数量不定），
		// base64 字母表不含 '-'，最后清掉所有连字符即可
		pk.remove(QRegularExpression("\\s"));
		pk.remove(QRegularExpression("-+BEGIN[^-]*?-+"));
		pk.remove(QRegularExpression("-*END[^-]*?-+"));
		pk.remove(QRegularExpression("-+"));
		if (!pk.isEmpty() && pk.size() != 60) {
			QMessageBox::warning(&dia, "提示",
				QString("服务器公钥格式无效：应为 60 位 base64（server_sig.pub 的正文行），当前为 %1 位。\n"
					"注意：不要复制 registered_clients.txt 里的 hex 或客户端日志整段；\n"
					"留空 = 使用内置公钥。").arg(pk.size()));
			return;   // 不关闭，让用户修改
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
			// 显式维护 Count，不依赖 Read_iniFile 的重排兜底
			const int cnt = IniGetInt(inipath, CS("Server"), CS("Count"), 0);
			IniSetInt(inipath, CS("Server"), CS("Count"), qMax(0, cnt - 1));
			m_selectedCard = -1;
			Read_iniFile();
			dia.reject();   // 以“取消”语义关闭：避免 exec 返回 Accepted 后落入下方保存分支，把旧值写回别的节
		}
	});
	if (dia.exec() != QDialog::Accepted)
		return;

	const QString newIP = edit_ip->text().trimmed();
	const QString newID = edit_ID->text().trimmed();
	const QString newToken = edit_token->text().trimmed();
	const QString newName = edit_name->text().trimmed();   // 空 = 用默认 computer+N

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

// 每秒采样：累计字节差值 → 速率（字节/秒），推入折线图（rx=下载 tx=上传）
void QtWidgetsClass::update_speed()
{
	if (!m_bridge)
		return;
	const uint64_t rx = m_bridge->rx_bytes();
	const uint64_t tx = m_bridge->tx_bytes();
	if (m_speedFirst) {          // 首次采样没有增量基准，速率为 0
		m_speedFirst = false;
	}
	else if (m_speedChart) {
		m_speedChart->push_sample(double(rx - m_rxLast), double(tx - m_txLast));
	}
	m_rxLast = rx;
	m_txLast = tx;
}


namespace {


// 开机自启动：用 QSettings 写当前用户注册表 Run 键（HKCU，无需管理员权限）。
// 值 = "<exe 完整路径>"，用户登录时由系统拉起。
const QString kRunKey =
	QStringLiteral("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
const QString kRunValue = QStringLiteral("ScholarVPN");

// 带引号的 exe 路径（防路径含空格）
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
	// 用 exe 路径判定：程序挪过位置则视为未启用（重新勾选会写入新路径）
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

} // namespace

// ===========================================================================
// 受管服务（QtWidgetsClass 侧）
// ===========================================================================

// 服务不可用阻塞弹窗：无关闭按钮 + Esc 屏蔽，只有「刷新状态」与「退出」。
// 刷新是异步的（ActionRole 点击不关窗），结果经 serviceChecked 原地更新文本
// 或 accept 关闭——绝不在这个弹窗之上再叠第二个弹窗。
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

// 把拉到的受管服务器合并进 [ServerN]：撤掉上次下发的（按 [Service]
// ManagedServers 记录识别），追加新列表；用户自建卡片原样保留。
// 读 [ServerN] 全部条目（countOut 返回原 Count，供写回时清理脏节）
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

// 重写 [ServerN]：先删 [1..oldCount] 全部旧节（删中间台不残留脏节），再按序写回
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
		// 空列表不动作（保留现状）；失败场景已在 serviceServers 分支处理
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

	// 只保留非受管的（受管的这批整体被新列表替换）
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

	// 注意：受管条目共用同一 client_id/token（配额按 client_id 计，共享 2GB 池）。
	// 同机单服务器部署下 token 只被该服务器消费一次；将来多台托管服务器需要
	// broker 按台发号（方案 8.3 预留），P0 先如实按单台实现。
	const QString svcId = toQString(IniGetStr(iniPath, CS("Service"), CS("ClientID"), CS("")));
	const QString svcToken = toQString(IniGetStr(iniPath, CS("Service"), CS("Token"), CS("")));
	QString managedList;
	for (const auto& s : list)
	{
		std::string ip;
		int port = 0;
		if (!service::split_addr(s.addr, ip, port))
		{
			continue;   // 坏行跳过
		}
		ServerEntry e;
		e.Name = to_cfgstr(s.remark.empty() ? s.addr : s.remark);
		e.ServerIP = fromQString(QString::fromStdString(ip));
		e.ServerPort = port;
		e.ClientID = fromQString(svcId);
		e.RegisterToken = fromQString(svcToken);
		e.ServerPubKey = fromQString(QString::fromStdString(s.pubkey_b64));
		e.managed = true;
		// 受管默认 TCP：实测移动网络 UDP 国际方向被 QoS 丢弃（握手通、数据全死）。
		// 但用户若在卡片上手动切过传输方式，刷新列表时必须保留他的选择——
		// 否则"切了 TCP、重启又变回 UDP"，永远测不出真实结果（已踩过）。
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

	m_selectedCard = -1;   // 卡片集合变了，交由 Read_iniFile 收敛选中项
	Read_iniFile();
	if (m_setting)
	{
		m_setting->applyServiceServers(
		    QStringLiteral("已下发 %1 台受管服务器（共 %2 张卡片）")
		        .arg(static_cast<int>(list.size()))
		        .arg(static_cast<int>(keep.size())));
	}
}

// 切回「自建」：把受管卡片从 [ServerN] 撤掉——自建模式不应看到也不应连服务方下发的卡。
// ManagedServers 记录保留：切回受管后 apply_server_list 仍按它正确替换批次。
void QtWidgetsClass::remove_managed_cards()
{
	const cfgstr iniPath = cfg_path_join(cfg_app_dir(), CS("config.ini"));
	const QStringList managed = toQString(
	    IniGetStr(iniPath, CS("Service"), CS("ManagedServers"), CS("")))
	    .split(QLatin1Char(','), Qt::SkipEmptyParts);
	if (managed.isEmpty())
	{
		return;   // 从未下发过受管卡
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
		return;   // 列表里没有受管卡
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

	// 窗口居中到父窗口
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
	build_service_page(stack, nav);   // insertWidget(1)：排在通用后、关于前

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

// ---------------- 设置【关于】页 ----------------

void Setting::build_about_page(QStackedWidget* stack, QListWidget* nav)
{
	// 注意：导航项「关于」由 create_setting 统一添加（这里只建页面），
	// 在这里再加一次会导致左栏出现两个「关于」。
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
		m_bridge->check_update();   // 结果经主界面转发 applyUpdateInfo
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
	m_btnUpdateNow->hide();   // 有更新时才显示
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
	// 阻塞判定与主界面一致（双保险，主界面也会做同样的事）
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
	// 网络失败：不打扰（未启用时 err 会说明原因）
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
		// 退出由主界面统一执行（强制弹窗也在等这个信号）
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

// 设置【服务】页：受管模式状态展示 + 申请试用 / 刷新状态入口。
// 导航项「服务」由 create_setting 统一插入（row=1），页面 insertWidget(1) 对齐。
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

	// 接入点随发行版内置（service_bootstrap.h），「使用服务方」恒可用；
	// config.ini [Service] 仅作覆盖（测试/换址），不再是启用前提。
	const bool managedNow = st_cfg_managed();

	// —— 来源选择（先设初始态再连信号，避免构建页面时误触发切换）——
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

	// —— 受管状态区：仅「使用服务方」时显示操作按钮 ——
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
			m_bridge->register_service();   // 结果经主界面转发 applyServiceInfo
		});
		btnRow->addWidget(m_btnSvcApply);
		m_btnSvcRefresh = new QPushButton(QStringLiteral("刷新状态"), card);
		m_btnSvcRefresh->setCursor(Qt::PointingHandCursor);
		m_btnSvcRefresh->setFixedHeight(30);
		m_btnSvcRefresh->setStyleSheet(btnStyle);
		connect(m_btnSvcRefresh, &QPushButton::clicked, this, [this]() {
			if (m_bridge == nullptr) return;
			m_svcStatus->setText(QStringLiteral("检查中..."));
			m_bridge->check_service();      // 状态/凭据同步
			m_bridge->apply_server_list();  // 服务器列表一并刷新（服务方可更新公钥/地址）
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
	stack->insertWidget(1, page);   // 通用(0) → 服务(1) → 关于(2)
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
		return;   // 服务页未构建（未配置）时无需展示
	}
	// 申请结果到达：恢复按钮
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
		// 只展示账号与指纹前缀（核对用），不展示任何敏感信息；
		// 鼠标悬停显示完整指纹（老板要求：显示不全的悬停看全部）
		m_svcDetail->setText(QStringLiteral("账号 %1　机器指纹 %2…")
		                         .arg(clientId, fp.left(12)));
		m_svcDetail->setToolTip(fp);
		// 文字可鼠标选中 → Ctrl+C 复制完整指纹（显示不全时的兜底复制途径）
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
