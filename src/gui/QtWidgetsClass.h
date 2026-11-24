#pragma once
#include "AppBridge.h"
#include <QWidget>
#include <QString>
#include <QScrollArea>
#include <QVBoxLayout>
#include "ui_QtWidgetsClass.h"
#include <QFrame>
#include <QDialog>
#include <QCheckBox>
#include <QLabel>
#include <QPushButton>
#include <QThread>
#include<qlineedit.h>
#include <QPainter>
#include <QTimer>
#include <QProgressBar>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QCloseEvent>
#include <QHash>
#include <QVector>
#include <vector>
#include <mutex>
#include <QPlainTextEdit>
#include <QComboBox>

class Setting;
class QMessageBox;

class SpeedChart : public QWidget
{
public:
	explicit SpeedChart(QWidget* parent = nullptr) : QWidget(parent)
	{
		setFixedHeight(190);
		for (int i = 0; i < N; ++i) { m_rx[i] = 0.0; m_tx[i] = 0.0; }
	}

	void push_sample(double rxSpeed, double txSpeed)
	{
		for (int i = 0; i < N - 1; ++i) {
			m_rx[i] = m_rx[i + 1];
			m_tx[i] = m_tx[i + 1];
		}
		m_rx[N - 1] = rxSpeed;
		m_tx[N - 1] = txSpeed;
		update();
	}

protected:
	void paintEvent(QPaintEvent*) override
	{
		QPainter p(this);
		p.setRenderHint(QPainter::Antialiasing);

		p.setPen(Qt::NoPen);
		p.setBrush(QColor(0xff, 0xff, 0xff));
		p.drawRoundedRect(rect(), 14, 14);

		const QRectF area = rect().adjusted(46, 28, -12, -20);

		double peak = 0.0;
		for (int i = 0; i < N; ++i)
			peak = qMax(peak, qMax(m_rx[i], m_tx[i]));
		const double vmax = qMax(1024.0, peak) * 1.15;

		p.setFont(QFont("Segoe UI", 7));
		for (int g = 0; g <= 3; ++g) {
			const double y = area.bottom() - area.height() * g / 3.0;
			p.setPen(QColor(0xe8, 0xec, 0xf3));
			p.drawLine(QPointF(area.left(), y), QPointF(area.right(), y));
			p.setPen(QColor(0x9a, 0xa3, 0xb8));
			p.drawText(QRectF(0, y - 8, area.left() - 6, 16),
				Qt::AlignRight | Qt::AlignVCenter, format_speed(vmax * g / 3.0));
		}

		if (peak > 0) {
			const double py = area.bottom() - area.height() * (peak / vmax);
			QPen dashPen(QColor(0xd9, 0x77, 0x06), 1, Qt::DashLine);
			p.setPen(dashPen);
			p.drawLine(QPointF(area.left(), py), QPointF(area.right(), py));
		}

		draw_series(p, area, m_rx, QColor(0x25, 0x63, 0xeb), vmax);
		draw_series(p, area, m_tx, QColor(0x10, 0xb9, 0x81), vmax);

		p.setFont(QFont("Segoe UI", 8));
		p.setPen(QColor(0x25, 0x63, 0xeb));
		p.drawText(QPointF(area.left(), 16), QStringLiteral("■ 下载"));
		p.setPen(QColor(0x10, 0xb9, 0x81));
		p.drawText(QPointF(area.left() + 54, 16), QStringLiteral("■ 上传"));
		p.setPen(QColor(0xd9, 0x77, 0x06));
		p.drawText(QRectF(width() - 190, 6, 180, 16),
			Qt::AlignRight | Qt::AlignVCenter,
			QStringLiteral("峰值 %1/s").arg(format_speed(peak)));
	}

private:
	static constexpr int N = 60;
	double m_rx[N];
	double m_tx[N];

	static QString format_speed(double v)
	{
		if (v >= 1024.0 * 1024.0) return QString::number(v / 1024.0 / 1024.0, 'f', 1) + "M";
		if (v >= 1024.0)          return QString::number(v / 1024.0, 'f', 0) + "K";
		return QString::number(v, 'f', 0);
	}

	static void draw_series(QPainter& p, const QRectF& area,
		const double* s, const QColor& c, double vmax)
	{
		QPolygonF poly;
		for (int i = 0; i < N; ++i) {
			const double x = area.left() + area.width() * i / (N - 1);
			const double y = area.bottom() - area.height() * qBound(0.0, s[i] / vmax, 1.0);
			poly << QPointF(x, y);
		}
		QPen pen(c, 1.7);
		pen.setJoinStyle(Qt::RoundJoin);
		p.setPen(pen);
		p.drawPolyline(poly);
	}
};

// GUI 日志环形缓冲的一条记录（级别：0=信息 1=警告 2=错误）
struct UiLogEntry
{
	quint64 seq = 0;   // 全局递增序号，环形缓冲裁剪后仍能正确增量渲染
	int level = 0;
	QString time;
	QString text;
};

// 主连接圆盘：自绘外环 + 内圆 + 两行文案，替代原来的方块按钮
class DialButton : public QPushButton
{
public:
	explicit DialButton(QWidget* parent = nullptr);

	void set_sub_text(const QString& s);
	void set_accent(const QColor& c);
	// 0=未连接 1=进行中 2=已连接 3=错误
	void set_dial_state(int state);

protected:
	void paintEvent(QPaintEvent* e) override;

private:
	QString m_sub;
	QColor  m_accent{ 0x25, 0x63, 0xEB };
	int     m_state = 0;
};

// 迷你趋势线：固定窗口的采样环，只负责画，不管取数
class Sparkline : public QWidget
{
public:
	explicit Sparkline(QWidget* parent = nullptr);

	void set_color(const QColor& c);
	void push(double v);

protected:
	void paintEvent(QPaintEvent* e) override;

private:
	static constexpr int kN = 36;
	QColor m_color{ 0x25, 0x63, 0xEB };
	double m_v[kN]{};
	int    m_count = 0;
	double m_max = 1024.0;
};

// 速率块：上下行两张小卡（数字 + 趋势线）
class SpeedPanel : public QWidget
{
public:
	explicit SpeedPanel(QWidget* parent = nullptr);

	void push(double rxBytesPerSec, double txBytesPerSec);

private:
	Sparkline* m_rxLine = nullptr;
	Sparkline* m_txLine = nullptr;
	QLabel*    m_rxValue = nullptr;
	QLabel*    m_txValue = nullptr;
};

class QtWidgetsClass : public QWidget
{
	Q_OBJECT
public:
	QtWidgetsClass(QWidget* parent = nullptr);
	~QtWidgetsClass();

	void Read_iniFile();
	void write_edit();
	void edit_card();
	void update_speed();
private:
	void clear_cards();
	void create_card(const ServerEntry& entry);
	void show_switch_dialog();
	void select_card(int index);
	void show_home_card(int index);
	void update_glass_card();
	void update_home_btn();
	void update_dia_highlight();
	void show_service_blocked_box(const QString& reason);
	void apply_managed_servers(int count);
	void remove_managed_cards();
	static std::vector<ServerEntry> read_server_entries(const cfgstr& ini_path, int* countOut);
	static void write_server_entries(const cfgstr& ini_path, int oldCount,
	                                 const std::vector<ServerEntry>& list);
	bool eventFilter(QObject* obj, QEvent* ev) override;
	void resizeEvent(QResizeEvent* ev) override;
	void createtray();
protected:
	void closeEvent(QCloseEvent * event) override;
private:
	Config* m_cfg = nullptr;
	Ui::QtWidgetsClassClass ui;

	QWidget* m_diaCard = nullptr;
	QWidget* m_glassTop = nullptr;
	QScrollArea* m_scroll = nullptr;

	QFrame*      m_glassCard = nullptr;
	QLabel*      m_glassName = nullptr;
	QLabel*      m_glassIp = nullptr;
	QLabel*      m_glassVip = nullptr;
	QLabel*      m_glassState = nullptr;
	QWidget* m_cardContainer = nullptr;
	QVBoxLayout* m_cardLayout = nullptr;

	QList<QFrame*>      m_cards;
	QList<ServerEntry> m_cardServers;
	int m_selectedCard = -1;

	QFrame*      m_homeCard = nullptr;
	QLabel*      m_homeName = nullptr;
	QLabel*      m_homeIp = nullptr;
	QLabel*      m_homeVip = nullptr;
	QPushButton* m_homeBtn = nullptr;
	QPushButton* m_homeEditBtn = nullptr;
	QLabel* m_homeHint = nullptr;
	QFrame* m_homeAccent = nullptr;
	QLabel* m_homeAvatar = nullptr;
	QLabel* m_homeTag = nullptr;
	QProgressBar* m_homeUsageBar = nullptr;
	QLabel* m_homeUsageText = nullptr;
	QList<QLabel*> m_cardDots;
	void update_home_usage();

	QString     m_serverIp;
	ConnState   m_state{ ConnState::Stopped };
	int m_activeCard = -1;

	QVector<UiLogEntry> m_logs;
	quint64 m_logSeq = 0;
	void append_log_line(int level, const QString& text);

public:
	const QVector<UiLogEntry>& logs() const { return m_logs; }
	quint64 log_seq() const { return m_logSeq; }
	void clear_logs();

private:
	SpeedPanel* m_speedPanel = nullptr;
	QVBoxLayout* m_homeLay = nullptr;
	QString m_dialIp;
	QLabel*     m_statusPill = nullptr;
	void update_status_pill();
	uint64_t m_rxLast = 0;
	uint64_t m_txLast = 0;
	bool m_speedFirst = true;

	AppBridge* m_bridge = nullptr;
	QThread* m_thread_start = nullptr;

	QPushButton* m_btnSwitch = nullptr;
	QPushButton* m_btnGlobal = nullptr;
	QPushButton* m_btnSplit = nullptr;
	QPushButton* m_btnIntranet = nullptr;
	void refresh_mode_buttons();
	QPointer<Setting> m_setting;
	QPointer<QMessageBox> m_updateBox;
	QPointer<QPushButton> m_boxBtn;

	QString  m_updateUrl;
	QString  m_updateSha256;
	QString  m_updateLatest;
	quint64  m_updateSize = 0;
	bool m_lastDownloadOk = false;

	QPointer<QMessageBox> m_svcBox;
	bool m_svcCheckPending = false;
	QLabel* m_svcInfo = nullptr;
	QSystemTrayIcon* m_trayicon = nullptr;
	QMenu* m_menu = nullptr;
	QAction* m_actionShow = nullptr;
	QAction* m_actionQuit = nullptr;

};

// 连接市场：列出全部节点、实测 TCP 握手延迟，一键切换
class MarketDialog : public QDialog
{
public:
	MarketDialog(QWidget* parent, const QList<ServerEntry>& servers, int current);
	int chosen() const { return m_chosen; }

private:
	void build_ui();
	void rebuild_list();
	void start_probe();
	void apply_latency();
	QString region_of(const ServerEntry& e) const;

	// 探测状态放堆上共享，线程只碰这个结构，不碰窗口对象
	struct LatState
	{
		std::mutex mtx;
		std::vector<int> lat;
		std::atomic<bool> done{ false };
	};

	QList<ServerEntry>  m_servers;
	int                 m_current = -1;
	int                 m_chosen = -1;
	QString             m_filter;
	QString             m_region;
	QWidget*            m_listHost = nullptr;
	QVBoxLayout*        m_listLay = nullptr;
	class QLineEdit*    m_search = nullptr;
	QHash<int, class QLabel*> m_latLabels;
	std::shared_ptr<LatState> m_lat;
	class QTimer*       m_pollTimer = nullptr;
};

class Setting : public QDialog {
public:
	explicit Setting(QWidget* parent, AppBridge* bridge, int initialPage = 0);
	~Setting();
	void applyUpdateInfo(int status, int action, const QString& latest,
	                     const QString& notes, const QString& err,
	                     const QString& url, const QString& sha256, quint64 size);
	void applyDownloadProgress(int pct);
	void applyDownloadFinished(bool ok, const QString& err);
	void applyServiceInfo(int blocked, const QString& reason, const QString& fp,
	                      const QString& clientId, const QString& status,
	                      qulonglong expire, qulonglong quota, qulonglong used,
	                      const QString& error);
	void applyServiceServers(const QString& text);
private:
	void create_setting();
	void build_about_page(class QStackedWidget* stack, class QListWidget* nav);
	void build_service_page(class QStackedWidget* stack, class QListWidget* nav);
	void build_log_page(class QStackedWidget* stack, class QListWidget* nav);
	void refresh_log_view(bool rebuild);
	void refresh_traffic_stats();
	bool st_cfg_managed() const;
	QtWidgetsClass* m_owner = nullptr;
	QPlainTextEdit* m_logView = nullptr;
	QComboBox* m_logFilter = nullptr;
	QCheckBox* m_logAutoScroll = nullptr;
	QLabel* m_statTotal = nullptr;
	QLabel* m_statSpeed = nullptr;
	QLabel* m_statPeak = nullptr;
	quint64 m_logSeen = 0;
	quint64 m_statRxLast = 0;
	quint64 m_statTxLast = 0;
	double m_peakRx = 0.0;
	double m_peakTx = 0.0;
	QTimer* m_logTimer = nullptr;
	int m_initialPage = 0;
	QCheckBox* m_chkAutoStart = nullptr;
	AppBridge* m_bridge = nullptr;
	QLabel* m_aboutVer = nullptr;
	QLabel* m_aboutStatus = nullptr;
	QPushButton* m_btnCheck = nullptr;
	QPushButton* m_btnUpdateNow = nullptr;
	QString m_url, m_sha256, m_latest, m_notes;
	quint64 m_size = 0;
	QLabel* m_svcStatus = nullptr;
	QLabel* m_svcDetail = nullptr;
	QPushButton* m_btnSvcApply = nullptr;
	QPushButton* m_btnSvcRefresh = nullptr;
};
