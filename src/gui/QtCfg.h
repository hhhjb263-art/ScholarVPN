#pragma once

// ============================================================================
// src/gui/QtCfg.h —— cfgstr <-> QString 的唯一桥
//
// GUI 层只跟 cfgstr（配置）/ std::string（UTF-8）打交道，不直接碰 wchar_t：
//   Windows 上 cfgstr 是 UTF-16，Linux 上是 UTF-8，
//   用法永远统一走下面两个函数，界面上再也不会出现 fromStdWString/toStdWString
//   的 #ifdef 分叉。
// ============================================================================

#include <QString>

#include "src/platform/cfgstr.h"

inline QString toQString(const cfgstr& s)
{
    return QString::fromUtf8(cfg_to_utf8(s).c_str());
}

inline cfgstr fromQString(const QString& s)
{
    return cfg_from_utf8(s.toUtf8().constData());
}
