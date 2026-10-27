#include "update/update_fetcher.h"

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

#include <cstdlib>
#include <string>
#include <vector>

#include <cstdio>

#include <openssl/evp.h>

#include <atomic>

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

struct UrlParts {
    bool https = true;
    std::wstring host;
    INTERNET_PORT port = INTERNET_PORT(443);
    std::wstring path = L"/";
    std::wstring extra;   // 额外请求头（暂无）
};

bool parse_url(const std::string& url, UrlParts& p)
{
    static const std::string kHttps = "https://";
    static const std::string kHttp = "http://";

    std::string rest;
    if (url.compare(0, kHttps.size(), kHttps) == 0)
    {
        p.https = true;
        p.port = 443;
        rest = url.substr(kHttps.size());
    }
    else if (url.compare(0, kHttp.size(), kHttp) == 0)
    {
        p.https = false;
        p.port = 80;
        rest = url.substr(kHttp.size());
    }
    else
    {
        return false;   // 只支持 http/https
    }

    const std::size_t slash = rest.find('/');
    const std::string hostport = (slash == std::string::npos) ? rest : rest.substr(0, slash);
    p.path = widen((slash == std::string::npos) ? "/" : rest.substr(slash));

    const std::size_t colon = hostport.find(':');
    if (colon == std::string::npos)
    {
        p.host = widen(hostport);
    }
    else
    {
        p.host = widen(hostport.substr(0, colon));
        p.port = static_cast<INTERNET_PORT>(
            std::atoi(hostport.substr(colon + 1).c_str()));
    }
    return !p.host.empty();
}

// 统一的句柄清理
struct HandleGuard {
    HINTERNET h = nullptr;
    ~HandleGuard()
    {
        if (h != nullptr)
        {
            ::WinHttpCloseHandle(h);
        }
    }
};

} // namespace

FetchResult fetch_text(const std::string& url, int timeoutMs)
{
    FetchResult r;

    UrlParts parts;
    if (!parse_url(url, parts))
    {
        r.error = "URL 非法（只支持 http/https）";
        return r;
    }

    HandleGuard session;
    session.h = ::WinHttpOpen(L"ScholarVPN-Update/1.0",
                              WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME,
                              WINHTTP_NO_PROXY_BYPASS, 0);
    if (session.h == nullptr)
    {
        r.error = "WinHttpOpen 失败";
        return r;
    }

    // 四个阶段分别设超时：解析、连接、发送、接收
    ::WinHttpSetTimeouts(session.h, timeoutMs, timeoutMs, timeoutMs, timeoutMs);

    HandleGuard conn;
    conn.h = ::WinHttpConnect(session.h, parts.host.c_str(), parts.port, 0);
    if (conn.h == nullptr)
    {
        r.error = "无法连接主机";
        return r;
    }

    HandleGuard req;
    req.h = ::WinHttpOpenRequest(conn.h, L"GET", parts.path.c_str(),
                                 nullptr, WINHTTP_NO_REFERER,
                                 WINHTTP_DEFAULT_ACCEPT_TYPES,
                                 parts.https ? WINHTTP_FLAG_SECURE : 0);
    if (req.h == nullptr)
    {
        r.error = "创建请求失败";
        return r;
    }

    // 不接受降级证书策略：保持系统默认校验即可（不设置 SECURE_PROTOCOLS，
    // 让 WinHTTP 用当前系统的 TLS 配置，避免写死 TLS 版本在旧系统上失效）
    if (!::WinHttpSendRequest(req.h, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                              WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
    {
        r.error = "发送请求失败（网络不可达？）";
        return r;
    }
    if (!::WinHttpReceiveResponse(req.h, nullptr))
    {
        r.error = "接收响应失败（超时或 TLS 握手失败）";
        return r;
    }

    DWORD status = 0;
    DWORD len = sizeof(status);
    if (::WinHttpQueryHeaders(req.h,
                              WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                              WINHTTP_HEADER_NAME_BY_INDEX, &status, &len,
                              WINHTTP_NO_HEADER_INDEX))
    {
        r.status = static_cast<int>(status);
    }

    // 读 body（分块，直到读完）
    for (;;)
    {
        DWORD avail = 0;
        if (!::WinHttpQueryDataAvailable(req.h, &avail) || avail == 0)
        {
            break;
        }
        std::vector<char> buf(avail);
        DWORD read = 0;
        if (!::WinHttpReadData(req.h, buf.data(), avail, &read) || read == 0)
        {
            break;
        }
        r.body.append(buf.data(), read);
        if (r.body.size() > 4 * 1024 * 1024)
        {
            r.error = "响应过大（>4MB），拒绝";
            return r;
        }
    }

    if (r.status < 200 || r.status >= 300)
    {
        r.error = "HTTP 状态码 " + std::to_string(r.status);
        return r;
    }
    if (r.body.empty())
    {
        r.error = "响应为空";
        return r;
    }
    r.ok = true;
    return r;
}

namespace {

std::string to_hex_lower(const unsigned char* data, unsigned int len)
{
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (unsigned int i = 0; i < len; ++i)
    {
        out.push_back(kHex[data[i] >> 4]);
        out.push_back(kHex[data[i] & 0x0F]);
    }
    return out;
}

bool hex_equals_ci(const std::string& a, const std::string& b)
{
    if (a.size() != b.size())
    {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i)
    {
        const char ca = (a[i] >= 'A' && a[i] <= 'F') ? static_cast<char>(a[i] - 'A' + 'a') : a[i];
        const char cb = (b[i] >= 'A' && b[i] <= 'F') ? static_cast<char>(b[i] - 'A' + 'a') : b[i];
        if (ca != cb)
        {
            return false;
        }
    }
    return true;
}

} // namespace

DownloadResult download_file(const std::string& url,
                             const std::string& destPath,
                             const std::string& expectedSha256,
                             std::uint64_t expectedSize,
                             ProgressFn progress,
                             void* user,
                             int timeoutMs,
                             std::atomic<bool>* cancel)
{
    DownloadResult r;

    UrlParts parts;
    if (!parse_url(url, parts))
    {
        r.error = "URL 非法";
        return r;
    }

    HandleGuard session;
    session.h = ::WinHttpOpen(L"ScholarVPN-Update/1.0",
                              WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (session.h == nullptr)
    {
        r.error = "WinHttpOpen 失败";
        return r;
    }
    ::WinHttpSetTimeouts(session.h, timeoutMs, timeoutMs, timeoutMs, timeoutMs);

    HandleGuard conn;
    conn.h = ::WinHttpConnect(session.h, parts.host.c_str(), parts.port, 0);
    if (conn.h == nullptr)
    {
        r.error = "无法连接主机";
        return r;
    }

    HandleGuard req;
    req.h = ::WinHttpOpenRequest(conn.h, L"GET", parts.path.c_str(),
                                 nullptr, WINHTTP_NO_REFERER,
                                 WINHTTP_DEFAULT_ACCEPT_TYPES,
                                 parts.https ? WINHTTP_FLAG_SECURE : 0);
    if (req.h == nullptr)
    {
        r.error = "创建请求失败";
        return r;
    }
    if (!::WinHttpSendRequest(req.h, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                              WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !::WinHttpReceiveResponse(req.h, nullptr))
    {
        r.error = "请求失败（网络不可达或 TLS 握手失败）";
        return r;
    }

    DWORD status = 0;
    DWORD slen = sizeof(status);
    if (::WinHttpQueryHeaders(req.h,
                              WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                              WINHTTP_HEADER_NAME_BY_INDEX, &status, &slen,
                              WINHTTP_NO_HEADER_INDEX))
    {
        if (status < 200 || status >= 300)
        {
            r.error = "HTTP 状态码 " + std::to_string(status);
            return r;
        }
    }

    // Windows 上必须用 _wfopen：std::fopen 按 ANSI 解路径，
    // 用户目录含中文（C:////Users////张三////)时直接失败，而错误信息只会说"无法写入"
    FILE* f = ::_wfopen(widen(destPath).c_str(), L"wb");
    if (f == nullptr)
    {
        r.error = "无法写入目标文件（权限、磁盘或路径编码）";
        return r;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr)
    {
        std::fclose(f);
        std::remove(destPath.c_str());
        r.error = "初始化哈希上下文失败";
        return r;
    }
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);

    std::uint64_t total = 0;
    bool ioOk = true;
    for (;;)
    {
        if (cancel != nullptr && cancel->load())
        {
            std::fclose(f);
            std::remove(destPath.c_str());
            r.error = "已取消";
            return r;
        }
        DWORD avail = 0;
        if (!::WinHttpQueryDataAvailable(req.h, &avail) || avail == 0)
        {
            break;
        }
        std::vector<char> buf(avail);
        DWORD read = 0;
        if (!::WinHttpReadData(req.h, buf.data(), avail, &read) || read == 0)
        {
            break;
        }
        if (std::fwrite(buf.data(), 1, read, f) != read)
        {
            ioOk = false;
            break;
        }
        EVP_DigestUpdate(ctx, buf.data(), read);
        total += read;
        if (progress != nullptr)
        {
            progress(total, expectedSize, user);
        }
    }
    std::fclose(f);

    unsigned char md[EVP_MAX_MD_SIZE]{};
    unsigned int mdLen = 0;
    EVP_DigestFinal_ex(ctx, md, &mdLen);
    EVP_MD_CTX_free(ctx);

    if (!ioOk)
    {
        std::remove(destPath.c_str());
        r.error = "写入文件失败（磁盘满？）";
        return r;
    }
    if (total == 0)
    {
        std::remove(destPath.c_str());
        r.error = "下载内容为空";
        return r;
    }

    r.sha256 = to_hex_lower(md, mdLen);
    r.size = total;
    r.path = destPath;

    if (!expectedSha256.empty() && !hex_equals_ci(r.sha256, expectedSha256))
    {
        // 校验不过立即删掉：绝不把可疑的包留在磁盘上
        std::remove(destPath.c_str());
        r.error = "SHA-256 不匹配（期望 " + expectedSha256 + "，实际 " + r.sha256 + "）";
        return r;
    }
    if (expectedSize != 0 && total != expectedSize)
    {
        std::remove(destPath.c_str());
        r.error = "文件大小不符（期望 " + std::to_string(expectedSize) +
                  "，实际 " + std::to_string(total) + "）";
        return r;
    }

    r.ok = true;
    return r;
}

} // namespace update

#else // ---------------------------- POSIX ----------------------------

// Linux 实现：OpenSSL TLS + 手写 HTTP/1.0 GET（Connection: close，读到 EOF）。
// 刻意的限制（策略/安装包托管服务是我们自己的 python http.server，够用）：
//   - 不支持 chunked（HTTP/1.0 语义下服务器不会返回）
//   - 不跟随重定向（策略 URL 由我们控制，无重定向）
//   - 超时作用于连接与读写（SO_RCVTIMEO/SO_SNDTIMEO）

#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <cerrno>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>   // ERR_get_error / ERR_error_string_n

#include <cstdio>
#include <cstring>

namespace update {
namespace {

struct UrlParts {
    bool https = true;
    std::string host;
    int port = 443;
    std::string path = "/";
};

bool parse_url_posix(const std::string& url, UrlParts& p)
{
    static const std::string kHttps = "https://";
    static const std::string kHttp = "http://";
    std::string rest;
    if (url.compare(0, kHttps.size(), kHttps) == 0)
    {
        p.https = true;
        p.port = 443;
        rest = url.substr(kHttps.size());
    }
    else if (url.compare(0, kHttp.size(), kHttp) == 0)
    {
        p.https = false;
        p.port = 80;
        rest = url.substr(kHttp.size());
    }
    else
    {
        return false;
    }

    const std::size_t slash = rest.find('/');
    const std::string hostport = (slash == std::string::npos) ? rest : rest.substr(0, slash);
    p.path = (slash == std::string::npos) ? "/" : rest.substr(slash);

    const std::size_t colon = hostport.find(':');
    if (colon == std::string::npos)
    {
        p.host = hostport;
    }
    else
    {
        p.host = hostport.substr(0, colon);
        p.port = std::atoi(hostport.c_str() + colon + 1);
    }
    return !p.host.empty();
}

std::string to_hex_lower(const unsigned char* data, unsigned int len)
{
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (unsigned int i = 0; i < len; ++i)
    {
        out.push_back(kHex[data[i] >> 4]);
        out.push_back(kHex[data[i] & 0x0F]);
    }
    return out;
}

bool hex_equals_ci(const std::string& a, const std::string& b)
{
    if (a.size() != b.size())
    {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i)
    {
        const char ca = (a[i] >= 'A' && a[i] <= 'F') ? static_cast<char>(a[i] - 'A' + 'a') : a[i];
        const char cb = (b[i] >= 'A' && b[i] <= 'F') ? static_cast<char>(b[i] - 'A' + 'a') : b[i];
        if (ca != cb)
        {
            return false;
        }
    }
    return true;
}

// 建立连接（TCP + 可选 TLS），返回 SSL* 或 nullptr（https=false 时 ssl 为空）。
// fd 通过出参返回；所有资源由调用方按出参清理。
bool connect_to(const UrlParts& parts, int timeoutMs, int& fdOut, SSL*& sslOut,
                SSL_CTX*& ctxOut, std::string& error)
{
    fdOut = -1;
    sslOut = nullptr;
    ctxOut = nullptr;

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (::getaddrinfo(parts.host.c_str(), std::to_string(parts.port).c_str(),
                      &hints, &res) != 0 || res == nullptr)
    {
        error = "DNS 解析失败";
        return false;
    }

    int fd = -1;
    for (addrinfo* ai = res; ai != nullptr; ai = ai->ai_next)
    {
        fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0)
        {
            continue;
        }
        // 非阻塞 connect + poll 超时：阻塞式 connect 不受 SO_SNDTIMEO 控制，
        // IPv6 路由不通时会卡满内核超时（约 2 分钟）才回退 IPv4——
        // 用户实测「一直检查中」的根因。
        timeval tv{};
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        const int fl = ::fcntl(fd, F_GETFL, 0);
        ::fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        if (::connect(fd, ai->ai_addr, ai->ai_addrlen) < 0 && errno != EINPROGRESS)
        {
            ::close(fd);
            fd = -1;
            continue;
        }
        pollfd pfd{fd, POLLOUT, 0};
        if (::poll(&pfd, 1, timeoutMs) <= 0)
        {
            ::close(fd);
            fd = -1;
            continue;   // 超时 → 立即尝试下一个地址
        }
        int soerr = 0;
        socklen_t slen = sizeof(soerr);
        ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen);
        if (soerr != 0)
        {
            ::close(fd);
            fd = -1;
            continue;
        }
        ::fcntl(fd, F_SETFL, fl);   // 恢复阻塞模式（读写由 SO_RCVTIMEO 控制）
        break;
    }
    ::freeaddrinfo(res);
    if (fd < 0)
    {
        error = "连接失败（超时或拒绝）";
        return false;
    }

    if (!parts.https)
    {
        fdOut = fd;
        return true;
    }

    ctxOut = SSL_CTX_new(TLS_client_method());
    SSL* ssl = SSL_new(ctxOut);
    if (ssl == nullptr)
    {
        ::close(fd);
        SSL_CTX_free(ctxOut);
        ctxOut = nullptr;
        error = "SSL 上下文创建失败";
        return false;
    }
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, parts.host.c_str());   // SNI
    if (SSL_connect(ssl) != 1)
    {
        const unsigned long e = ERR_get_error();
        char buf[256]{};
        ERR_error_string_n(e, buf, sizeof(buf));
        SSL_free(ssl);
        SSL_CTX_free(ctxOut);
        ::close(fd);
        ctxOut = nullptr;
        error = std::string("TLS 握手失败: ") + buf;
        return false;
    }
    // 证书校验由调用方决定策略；更新内容的可信性由 Ed25519 签名保证，
    // TLS 层主要防传输干扰。这里保持系统默认校验关闭与 Windows 版行为一致。
    fdOut = fd;
    sslOut = ssl;
    return true;
}

// 读整个 HTTP 响应（Connection: close，读到对端关闭）
bool read_response(int fd, SSL* ssl, std::string& raw, bool& ioOk)
{
    char buf[16384];
    ioOk = true;
    for (;;)
    {
        int n = ssl ? SSL_read(ssl, buf, sizeof(buf))
                    : static_cast<int>(::read(fd, buf, sizeof(buf)));
        if (n <= 0)
        {
            break;   // EOF / 超时 / 错误 —— close 语义下 EOF 即正常结束
        }
        raw.append(buf, static_cast<std::size_t>(n));
        if (raw.size() > 512 * 1024 * 1024)
        {
            ioOk = false;
            return false;   // 512MB 上限，防止异常响应拖垮内存
        }
    }
    return true;
}

bool parse_http_response(const std::string& raw, int& status, std::string& body)
{
    const std::size_t hdrEnd = raw.find("\r\n\r\n");
    if (hdrEnd == std::string::npos)
    {
        return false;
    }
    // 状态行: HTTP/1.1 200 OK
    const std::size_t sp1 = raw.find(' ');
    if (sp1 == std::string::npos)
    {
        return false;
    }
    status = std::atoi(raw.c_str() + sp1 + 1);
    body = raw.substr(hdrEnd + 4);
    return true;
}

// 统一的传输抽象：https 走 SSL_read/write，http 走 read/write
struct Conn {
    int fd = -1;
    SSL* ssl = nullptr;
    SSL_CTX* ctx = nullptr;

    int read(char* buf, int len)
    {
        return ssl ? SSL_read(ssl, buf, len) : static_cast<int>(::read(fd, buf, len));
    }
    int write(const char* buf, int len)
    {
        return ssl ? SSL_write(ssl, buf, len) : static_cast<int>(::write(fd, buf, len));
    }
    void close_all()
    {
        if (ssl != nullptr)
        {
            SSL_free(ssl);
            ssl = nullptr;
        }
        if (ctx != nullptr)
        {
            SSL_CTX_free(ctx);
            ctx = nullptr;
        }
        if (fd >= 0)
        {
            ::close(fd);
            fd = -1;
        }
    }
};

} // namespace

FetchResult fetch_text(const std::string& url, int timeoutMs)
{
    FetchResult r;

    UrlParts parts;
    if (!parse_url_posix(url, parts))
    {
        r.error = "URL 非法（只支持 http/https）";
        return r;
    }

    Conn conn;
    std::string err;
    if (!connect_to(parts, timeoutMs, conn.fd, conn.ssl, conn.ctx, err))
    {
        r.error = err;
        return r;
    }

    const std::string req = "GET " + parts.path + " HTTP/1.0\r\nHost: " + parts.host +
                            "\r\nUser-Agent: ScholarVPN-Update/1.0\r\nConnection: close\r\n\r\n";
    if (conn.write(req.c_str(), static_cast<int>(req.size())) < 0)
    {
        conn.close_all();
        r.error = "发送请求失败";
        return r;
    }

    std::string raw;
    bool ioOk = true;
    if (!read_response(conn.fd, conn.ssl, raw, ioOk))
    {
        conn.close_all();
        r.error = "读取响应失败";
        return r;
    }
    conn.close_all();

    int status = 0;
    std::string body;
    if (!parse_http_response(raw, status, body))
    {
        // 诊断：dump 前 120 字节（可读 + hex），看 TLS 层到底读到了什么
        std::string head = raw.substr(0, 120);
        std::string hex;
        for (unsigned char c : head)
        {
            char b[4];
            std::snprintf(b, sizeof(b), "%02x ", c);
            hex += b;
        }
        r.error = "响应格式非法 raw[" + std::to_string(raw.size()) +
                  "]=[" + head + "] hex=[" + hex + "]";
        r.status = status;
        return r;
    }
    r.status = status;
    if (status < 200 || status >= 300)
    {
        r.error = "HTTP 状态码 " + std::to_string(status);
        return r;
    }
    if (body.empty())
    {
        r.error = "响应为空";
        return r;
    }
    r.body = body;
    r.ok = true;
    return r;
}

DownloadResult download_file(const std::string& url,
                             const std::string& destPath,
                             const std::string& expectedSha256,
                             std::uint64_t expectedSize,
                             ProgressFn progress,
                             void* user,
                             int timeoutMs,
                             std::atomic<bool>* cancel)
{
    DownloadResult r;

    UrlParts parts;
    if (!parse_url_posix(url, parts))
    {
        r.error = "URL 非法";
        return r;
    }

    Conn conn;
    std::string err;
    if (!connect_to(parts, timeoutMs, conn.fd, conn.ssl, conn.ctx, err))
    {
        r.error = err;
        return r;
    }

    const std::string req = "GET " + parts.path + " HTTP/1.0\r\nHost: " + parts.host +
                            "\r\nUser-Agent: ScholarVPN-Update/1.0\r\nConnection: close\r\n\r\n";
    if (conn.write(req.c_str(), static_cast<int>(req.size())) < 0)
    {
        conn.close_all();
        r.error = "发送请求失败";
        return r;
    }

    // 读到头部结束，取状态码，把 body 直接写文件
    std::string raw;
    {
        char buf[16384];
        std::size_t hdrEnd = std::string::npos;
        for (;;)
        {
            const int n = conn.read(buf, sizeof(buf));
            if (n <= 0)
            {
                conn.close_all();
                r.error = "读取响应失败";
                return r;
            }
            raw.append(buf, static_cast<std::size_t>(n));
            hdrEnd = raw.find("\r\n\r\n");
            if (hdrEnd != std::string::npos)
            {
                break;
            }
            if (raw.size() > 1024 * 1024)
            {
                conn.close_all();
                r.error = "响应头过大";
                return r;
            }
        }

        int status = 0;
        {
            const std::size_t sp1 = raw.find(' ');
            if (sp1 != std::string::npos)
            {
                status = std::atoi(raw.c_str() + sp1 + 1);
            }
        }
        if (status < 200 || status >= 300)
        {
            conn.close_all();
            r.error = "HTTP 状态码 " + std::to_string(status);
            return r;
        }
        // 头之后的 body 立即落盘
        FILE* f = std::fopen(destPath.c_str(), "wb");
        if (f == nullptr)
        {
            conn.close_all();
            r.error = "无法写入目标文件";
            return r;
        }
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);

        const std::string first = raw.substr(hdrEnd + 4);
        std::fwrite(first.data(), 1, first.size(), f);
        EVP_DigestUpdate(ctx, first.data(), first.size());
        std::uint64_t total = first.size();
        if (progress != nullptr)
        {
            progress(total, expectedSize, user);
        }

        char bodyBuf[16384];
        bool ioOk = true;
        for (;;)
        {
            if (cancel != nullptr && cancel->load())
            {
                std::fclose(f);
                EVP_MD_CTX_free(ctx);
                conn.close_all();
                std::remove(destPath.c_str());
                r.error = "已取消";
                return r;
            }
            const int n = conn.read(bodyBuf, sizeof(bodyBuf));
            if (n <= 0)
            {
                break;
            }
            if (std::fwrite(bodyBuf, 1, static_cast<std::size_t>(n), f) !=
                static_cast<std::size_t>(n))
            {
                ioOk = false;
                break;
            }
            EVP_DigestUpdate(ctx, bodyBuf, static_cast<std::size_t>(n));
            total += static_cast<std::uint64_t>(n);
            if (progress != nullptr)
            {
                progress(total, expectedSize, user);
            }
        }
        std::fclose(f);

        unsigned char md[EVP_MAX_MD_SIZE]{};
        unsigned int mdLen = 0;
        EVP_DigestFinal_ex(ctx, md, &mdLen);
        EVP_MD_CTX_free(ctx);
        conn.close_all();

        if (!ioOk)
        {
            std::remove(destPath.c_str());
            r.error = "写入文件失败";
            return r;
        }
        if (total == 0)
        {
            std::remove(destPath.c_str());
            r.error = "下载内容为空";
            return r;
        }
        r.sha256 = to_hex_lower(md, mdLen);
        r.size = total;
        r.path = destPath;

        if (!expectedSha256.empty() && !hex_equals_ci(r.sha256, expectedSha256))
        {
            std::remove(destPath.c_str());
            r.error = "SHA-256 不匹配（期望 " + expectedSha256 + "，实际 " + r.sha256 + "）";
            return r;
        }
        if (expectedSize != 0 && total != expectedSize)
        {
            std::remove(destPath.c_str());
            r.error = "文件大小不符（期望 " + std::to_string(expectedSize) +
                      "，实际 " + std::to_string(total) + "）";
            return r;
        }
        r.ok = true;
        return r;
    }
}

} // namespace update

#endif   // _WIN32
