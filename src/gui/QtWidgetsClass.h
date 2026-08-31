#pragma once
#include "AppBridge.h"
#include <QWidget>
#include <QString>
#include <QScrollArea>
#include <QVBoxLayout>
#include "ui_QtWidgetsClass.h"
#include <QFrame>
#include <QLabel>
#include <QPushButton>
#include <QThread>
#include<qlineedit.h>
#include <QPainter>
#include <QTimer>

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
		for (int i = 0; i < N - 1; ++i) {   // 左移环形窗口：尾部为最新
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

		// 卡片底
		p.setPen(Qt::NoPen);
		p.setBrush(QColor(0xff, 0xff, 0xff));
		p.drawRoundedRect(rect(), 14, 14);

		// 绘图区：左侧留刻度文字，顶部留图例/峰值行
		const QRectF area = rect().adjusted(46, 28, -12, -20);

		// 本窗口峰值（下载/上传取大者），量程与之联动
		double peak = 0.0;
		for (int i = 0; i < N; ++i)
			peak = qMax(peak, qMax(m_rx[i], m_tx[i]));
		const double vmax = qMax(1024.0, peak) * 1.15;

		// 网格 + 纵向刻度
		p.setFont(QFont("Segoe UI", 7));
		for (int g = 0; g <= 3; ++g) {
			const double y = area.bottom() - area.height() * g / 3.0;
			p.setPen(QColor(0xe8, 0xec, 0xf3));
			p.drawLine(QPointF(area.left(), y), QPointF(area.right(), y));
			p.setPen(QColor(0x9a, 0xa3, 0xb8));
			p.drawText(QRectF(0, y - 8, area.left() - 6, 16),
				Qt::AlignRight | Qt::AlignVCenter, format_speed(vmax * g / 3.0));
		}

		// 峰值虚线：横贯绘图区，标出当前窗口最大速率所在高度
		if (peak > 0) {
			const double py = area.bottom() - area.height() * (peak / vmax);
			QPen dashPen(QColor(0xd9, 0x77, 0x06), 1, Qt::DashLine);
			p.setPen(dashPen);
			p.drawLine(QPointF(area.left(), py), QPointF(area.right(), py));
		}

		// 折线：下载蓝 / 上传绿
		draw_series(p, area, m_rx, QColor(0x25, 0x63, 0xeb), vmax);
		draw_series(p, area, m_tx, QColor(0x10, 0xb9, 0x81), vmax);

		// 顶部行：左侧图例，右上方峰值数值
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
	static constexpr int N = 60;   // 保留 60 秒
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
	void clear_cards();                                  // 清空所有卡片（重建前调用）
	void create_card(const ServerEntry& entry);          // dia 中建一张可选卡片（点击选中）
	void show_switch_dialog();
	void select_card(int index);       // dia 中选中某卡：更新主页面 + 高亮 + 收起弹窗
	void show_home_card(int index);    // 主页面显示指定服务器卡片（连接/编辑）
	void update_glass_card();          // 刷新半透明区里的"当前服务器"摘要卡
	void update_home_btn();            // 按当前连接状态刷新主页面"连接/断开"按钮
	void update_dia_highlight();       // 刷新 dia 卡片列表的选中高亮
	bool eventFilter(QObject* obj, QEvent* ev) override;
	void resizeEvent(QResizeEvent* ev) override;   // 覆盖层随主窗口尺寸同步
	
private:
	Config* m_cfg = nullptr;
	Ui::QtWidgetsClassClass ui;

	QWidget*   m_diaCard = nullptr;   // Switch 覆盖层：主窗口内部，默认隐藏，点 Switch 显示
	QWidget*   m_glassTop = nullptr;  // 覆盖层顶部 200px 半透明区（点击收起）
	QScrollArea* m_scroll = nullptr;  // 卡片列表滚动区（挂在覆盖层内）

	// 半透明区里的"当前服务器"摘要卡（选择/最新添加的那张）
	QFrame*      m_glassCard = nullptr;
	QLabel*      m_glassName = nullptr;
	QLabel*      m_glassIp = nullptr;
	QLabel*      m_glassVip = nullptr;
	QLabel*      m_glassState = nullptr;
	QWidget* m_cardContainer = nullptr;
	QVBoxLayout* m_cardLayout = nullptr;

	// dia 中的可选卡片
	QList<QFrame*>      m_cards;
	QList<ServerEntry>  m_cardServers;   // 每张卡片绑定的服务器配置（含各自身份）
	int         m_selectedCard = -1;     // 主页面显示的服务器索引（选择优先于最新）

	// 主页面卡片（连接 + 编辑）
	QFrame*      m_homeCard = nullptr;
	QLabel*      m_homeName = nullptr;
	QLabel*      m_homeIp = nullptr;
	QLabel*      m_homeVip = nullptr;
	QPushButton* m_homeBtn = nullptr;     // 连接/断开
	QPushButton* m_homeEditBtn = nullptr; // 编辑
	QLabel*      m_homeHint = nullptr;    // 无服务器时的占位提示

	QString     m_serverIp;
	ConnState   m_state{ ConnState::Stopped };
	int         m_activeCard = -1;   // 当前正在连接/已连接的卡片索引；-1=无

	// 速度曲线采样
	SpeedChart* m_speedChart = nullptr;
	uint64_t    m_rxLast = 0;        // 上次采样的累计下载字节
	uint64_t    m_txLast = 0;        // 上次采样的累计上传字节
	bool        m_speedFirst = true; // 首次采样不产生速度值

	AppBridge* m_bridge = nullptr;
	QThread* m_thread_start = nullptr;

	QPushButton* m_btnSwitch = nullptr;   // Switch Server 按钮（主界面，控制弹窗显隐）

};
