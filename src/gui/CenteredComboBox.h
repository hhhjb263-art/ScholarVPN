#pragma once

#include <QComboBox>
#include <QPaintEvent>
#include <QStyle>
#include <QStyleOptionComboBox>
#include <QStylePainter>
#include <QString>

class CenteredComboBox : public QComboBox
{
public:
    explicit CenteredComboBox(QWidget* parent = nullptr) : QComboBox(parent) {}

protected:
    void paintEvent(QPaintEvent*) override
    {
        QStylePainter painter(this);
        QStyleOptionComboBox opt;
        initStyleOption(&opt);

        const QString text = opt.currentText;

        opt.currentText.clear();
        painter.drawComplexControl(QStyle::CC_ComboBox, opt);

        const QRect field = style()->subControlRect(
            QStyle::CC_ComboBox, &opt, QStyle::SC_ComboBoxEditField, this);
        if (!text.isEmpty() && field.isValid())
        {
            painter.drawItemText(field, Qt::AlignCenter, palette(), isEnabled(),
                                 text, QPalette::ButtonText);
        }
    }
};
