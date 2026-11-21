#pragma once

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
