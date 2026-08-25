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

class QtWidgetsClass : public QWidget
{
	Q_OBJECT
public:
	QtWidgetsClass(QWidget* parent = nullptr);
	~QtWidgetsClass();

	void Read_iniFile();
	void write_edit();
	void edit_card();
private:
	void clear_cards();                                  // 清空所有卡片（重建前调用）
	void create_card(const ServerEntry& entry);          // 建一张卡片（绑定自己的服务器+身份）
private:
	Config* m_cfg = nullptr;
	Ui::QtWidgetsClassClass ui;

	QScrollArea* m_scroll = nullptr;
	QWidget* m_cardContainer = nullptr;
	QVBoxLayout* m_cardLayout = nullptr;

	// 多卡片控件容器
	QList<QFrame*>      m_cards;
	QList<QLabel*>      m_cardNames;
	QList<QLabel*>      m_cardIps;
	QList<QLabel*>      m_cardVips;
	QList<QPushButton*> m_cardBtns;
	QList<ServerEntry>  m_cardServers;   // 每张卡片绑定的服务器配置（含各自身份）
	QLineEdit*  m_lineedit;
	QString     m_serverIp;
	ConnState   m_state{ ConnState::Stopped };
	int         m_activeCard = -1;   // 当前正在连接/已连接的卡片索引；-1=无

	AppBridge* m_bridge = nullptr;
	QThread* m_thread_start = nullptr;
};
