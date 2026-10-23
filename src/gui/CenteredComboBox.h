#pragma once

#include <QComboBox>
#include <QPaintEvent>
#include <QStyle>
#include <QStyleOptionComboBox>
#include <QStylePainter>
#include <QString>

// ============================================================================
// CenteredComboBox —— 当前显示文本居中的 QComboBox
//
// 为什么不能用 QSS：
//   未展开时的那一行由 QStyle::CE_ComboBoxLabel 绘制，而 QStyleOptionComboBox
//   根本没有 alignment 字段 —— 写 `QComboBox { text-align: center; }` 不会生效。
//
// 为什么不用 setEditable(true) + lineEdit()->setAlignment()：
//   那会把控件切成可编辑模式，改变点击/键盘/currentText 的来源，
//   属于"为了对齐改行为"，不接受。
//
// 这里只重写 paintEvent：先把文本清空画控件（背景/边框/箭头），
// 再自己居中画一遍文本。其余行为 100% 继承 QComboBox。
//
// 不写 Q_OBJECT：本类不新增信号/槽/属性，无需 moc，也不用动构建配置。
// ============================================================================
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

        // 关键：先清空 currentText 再画复杂控件，
        // 否则 drawComplexControl 会顺带把左对齐的文本画一遍，出现重影。
        opt.currentText.clear();
        painter.drawComplexControl(QStyle::CC_ComboBox, opt);

        // 只取"编辑区"（不含右侧下拉箭头），在其中居中绘制文本
        const QRect field = style()->subControlRect(
            QStyle::CC_ComboBox, &opt, QStyle::SC_ComboBoxEditField, this);
        if (!text.isEmpty() && field.isValid())
        {
            painter.drawItemText(field, Qt::AlignCenter, palette(), isEnabled(),
                                 text, QPalette::ButtonText);
        }
    }
};
