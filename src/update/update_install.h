#pragma once

#include <QString>

namespace update {

bool launch_installer(const QString& exePath, QString& error);

bool install_package(const QString& pkgPath, QString& error);

}
