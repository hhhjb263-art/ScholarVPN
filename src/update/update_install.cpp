#include "update/update_install.h"

#include <QProcess>
#include <QDir>
#include <QFileInfo>
#include <QString>

#include <cstdlib>
#include <string>

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h>

#pragma comment(lib, "shell32.lib")

namespace update {

namespace {

std::wstring widen(const std::string& s)
{
    if (s.empty())
    {
        return std::wstring();
    }
    const int n = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 0)
    {
        return std::wstring();
    }
    std::wstring w(static_cast<std::size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
    if (!w.empty() && w.back() == L'\0')
    {
        w.pop_back();
    }
    return w;
}

std::string narrow_ansi(const wchar_t* s)
{
    const int n = ::WideCharToMultiByte(CP_UTF8, 0, s, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0)
    {
        return std::string();
    }
    std::string out(static_cast<std::size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, s, -1, &out[0], n, nullptr, nullptr);
    if (!out.empty() && out.back() == '\0')
    {
        out.pop_back();
    }
    return out;
}

} // namespace

bool install_package(const QString& pkgPath, QString& error)
{
    return launch_installer(pkgPath, error);   // Windows：Inno 静默派发
}

bool launch_installer(const QString& exePath, QString& error)
{
    if (exePath.isEmpty())
    {
        error = QStringLiteral("安装包路径为空");
        return false;
    }

    // 存在性先确认：否则 ShellExecute 会走"打开方式"对话框，用户看到的是怪异提示
    const DWORD attr = ::GetFileAttributesW(reinterpret_cast<const wchar_t*>(exePath.utf16()));
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
        error = "安装包不存在或不是文件";
        return false;
    }

    // /CLOSEAPPLICATIONS：让 Inno 关掉仍占用文件的进程（含本程序）
    // /NORESTART：绝不自动重启系统；/SUPPRESSMSGBOXES：静默失败不弹框
    const std::wstring file = exePath.toStdWString();
    const std::wstring params = L"/SILENT /SUPPRESSMSGBOXES /NORESTART /CLOSEAPPLICATIONS";

    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC;
    sei.lpVerb = L"open";
    sei.lpFile = file.c_str();
    sei.lpParameters = params.c_str();
    sei.nShow = SW_SHOWNORMAL;

    if (!::ShellExecuteExW(&sei))
    {
        const DWORD err = ::GetLastError();
        wchar_t buf[256]{};
        ::FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                         nullptr, err, 0, buf, 256, nullptr);
        error = QStringLiteral("启动安装器失败 (%1): %2")
                    .arg(static_cast<ulong>(err))
                    .arg(QString::fromWCharArray(buf));
        return false;
    }
    return true;
}

} // namespace update

#else // ---------------------------- POSIX ----------------------------

namespace update {

// Linux 安装：tar.gz -> 解包 -> pkexec 执行 install-linux.sh
// （polkit 弹认证框；安装脚本会把 vpn_client 装到 /opt/scholarvpn 并
//   更新 /usr/local/bin 启动器与桌面入口——即「取代旧版」）。
// 阻塞直到认证+安装完成（在下载线程里调用，GUI 只显示状态）。
static bool install_tarball(const QString& pkgPath, QString& error)
{
    const QFileInfo fi(pkgPath);
    const QString extractDir = fi.absolutePath() + QStringLiteral("/.scholarvpn-extract");

    QDir(extractDir).removeRecursively();   // 清掉上次残留
    if (!QDir().mkpath(extractDir))
    {
        error = QStringLiteral("无法创建解包目录");
        return false;
    }

    if (QProcess::execute(QStringLiteral("tar"),
                          {QStringLiteral("xzf"), pkgPath,
                           QStringLiteral("-C"), extractDir}) != 0)
    {
        error = QStringLiteral("解包失败（tar）");
        return false;
    }

    const QString installSh = extractDir + QStringLiteral("/install-linux.sh");
    const QString bin = extractDir + QStringLiteral("/vpn_client");
    if (!QFileInfo::exists(installSh) || !QFileInfo::exists(bin))
    {
        error = QStringLiteral("包内容不完整（缺 install-linux.sh 或 vpn_client）");
        return false;
    }

    // pkexec：polkit 认证框（用户输入密码）——com.scholarvpn.client.policy
    // 已随程序安装，认证框显示中文说明
    const int rc = QProcess::execute(QStringLiteral("pkexec"),
        {QStringLiteral("bash"), installSh, bin});
    QDir(extractDir).removeRecursively();
    if (rc != 0)
    {
        error = QStringLiteral("安装未完成（授权被取消或脚本出错）");
        return false;
    }
    return true;
}

bool install_package(const QString& pkgPath, QString& error)
{
    return install_tarball(pkgPath, error);
}

bool launch_installer(const QString& /*exePath*/, QString& error)
{
    error = QStringLiteral("Linux 使用 tar.gz 安装包（install_package 入口）");
    return false;
}



} // namespace update

#endif
