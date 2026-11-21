#pragma once

#include <QCheckBox>
#include <QDialog>
#include <QHBoxLayout>
#include <QPushButton>
#include <QTextBrowser>
#include <QVBoxLayout>

#include "../client/user_agreement.h"

inline bool show_user_agreement(QWidget* parent = nullptr)
{
	QDialog dlg(parent);
	dlg.setWindowTitle(QStringLiteral("ScholarVPN 用户协议"));
	dlg.setMinimumSize(720, 560);

	auto* lay = new QVBoxLayout(&dlg);
	auto* browser = new QTextBrowser(&dlg);
	browser->setPlainText(QString::fromUtf8(client::kUserAgreementText));
	lay->addWidget(browser);

	auto* check = new QCheckBox(QStringLiteral("我已阅读并同意以上用户协议"), &dlg);
	lay->addWidget(check);

	auto* row = new QHBoxLayout;
	auto* ok = new QPushButton(QStringLiteral("同意并继续"), &dlg);
	auto* no = new QPushButton(QStringLiteral("拒绝并退出"), &dlg);
	ok->setEnabled(false);
	row->addStretch();
	row->addWidget(no);
	row->addWidget(ok);
	lay->addLayout(row);

	QObject::connect(check, &QCheckBox::toggled, ok, &QPushButton::setEnabled);
	QObject::connect(no, &QPushButton::clicked, &dlg, &QDialog::reject);
	QObject::connect(ok, &QPushButton::clicked, &dlg, &QDialog::accept);

	dlg.exec();
	return check->isChecked() && dlg.result() == QDialog::Accepted;
}
