// ============================================================================
// AdminWire.h —— 中转通道的极简线协议（vpn_controller ↔ admin_agent）
// ----------------------------------------------------------------------------
// 帧格式：[4 字节大端长度][JSON 载荷]，单帧上限 64KB。
// 只处理"扁平对象、值为字符串或整数"的 JSON——通道消息全是这个形状，
// 因此不引入任何 JSON 库，与项目零依赖风格一致（计划书 3.5）。
// 传输：一期为明文 TCP；TLS 属二期（计划书 3.5 备注）。
// ============================================================================
#pragma once

#include <cstdint>
#include <cstdlib>     // strtoll
#include <cstring>
#include <string>

#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

namespace wire {

constexpr size_t kMaxFrame = 64 * 1024;   // 单帧上限：装得下 1000 个令牌的 JSON
constexpr int    kTimeoutMs = 5000;       // 收发默认超时

// ---------------------------------------------------------------- JSON 生成
inline std::string escape(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;      break;
        }
    }
    return out;
}

// 极简构造器：wire::Json().str("type","hello").num("id",1).done()
class Json {
public:
    Json& str(const std::string& k, const std::string& v)
    {
        sep();
        s_ += "\"" + k + "\":\"" + escape(v) + "\"";
        return *this;
    }
    Json& num(const std::string& k, long long v)
    {
        sep();
        s_ += "\"" + k + "\":" + std::to_string(v);
        return *this;
    }
    std::string done() const { return s_ + "}"; }

private:
    void sep() { if (!first_) s_ += ","; first_ = false; }
    std::string s_ = "{";
    bool first_ = true;
};

// ---------------------------------------------------------------- JSON 解析
// 定位 "key" 冒号之后的第一个非空白字符；找不到返回 npos
inline size_t find_value(const std::string& obj, const std::string& key)
{
    const std::string pat = "\"" + key + "\"";
    const size_t k = obj.find(pat);
    if (k == std::string::npos) return std::string::npos;
    const size_t c = obj.find(':', k + pat.size());
    if (c == std::string::npos) return std::string::npos;
    size_t i = c + 1;
    while (i < obj.size() && (obj[i] == ' ' || obj[i] == '\t' ||
                              obj[i] == '\n' || obj[i] == '\r'))
        ++i;
    return i;
}

// 取字符串字段（值须为 "..."，含转义还原）。成功返回 true。
inline bool get_string(const std::string& obj, const std::string& key, std::string& out)
{
    size_t i = find_value(obj, key);
    if (i == std::string::npos || i >= obj.size() || obj[i] != '"') return false;
    ++i;
    std::string v;
    while (i < obj.size()) {
        const char c = obj[i++];
        if (c == '"') { out = v; return true; }
        if (c == '\\' && i < obj.size()) {
            const char e = obj[i++];
            switch (e) {
                case 'n':  v += '\n'; break;
                case 'r':  v += '\r'; break;
                case 't':  v += '\t'; break;
                case '"':  v += '"';  break;
                case '\\': v += '\\'; break;
                case '/':  v += '/';  break;
                default:   v += e;    break;   // 其他转义原样保留
            }
        } else {
            v += c;
        }
    }
    return false;   // 引号没闭合
}

// 取整数字段。成功返回 true。
inline bool get_int(const std::string& obj, const std::string& key, long long& out)
{
    const size_t i = find_value(obj, key);
    if (i == std::string::npos || i >= obj.size()) return false;
    char* end = nullptr;
    const long long v = std::strtoll(obj.c_str() + i, &end, 10);
    if (end == obj.c_str() + i) return false;
    out = v;
    return true;
}

// ---------------------------------------------------------------- 分帧
// 写一帧（阻塞、处理部分写）。@return false = 连接已坏
inline bool send_frame(int fd, const std::string& payload)
{
    if (payload.size() > kMaxFrame) return false;
    uint8_t hdr[4];
    const uint32_t n = static_cast<uint32_t>(payload.size());
    hdr[0] = uint8_t(n >> 24);
    hdr[1] = uint8_t(n >> 16);
    hdr[2] = uint8_t(n >> 8);
    hdr[3] = uint8_t(n);
    const char* parts[2] = { reinterpret_cast<const char*>(hdr), payload.data() };
    const size_t lens[2] = { 4, payload.size() };
    for (int p = 0; p < 2; ++p) {
        size_t off = 0;
        while (off < lens[p]) {
            const ssize_t w = ::send(fd, parts[p] + off, lens[p] - off, MSG_NOSIGNAL);
            if (w > 0) { off += static_cast<size_t>(w); continue; }
            if (w < 0 && errno == EINTR) continue;
            return false;
        }
    }
    return true;
}

// 读缓冲：把 recv 到的字节喂进来，按 4 字节长度前缀逐帧取出
class Framer {
public:
    void feed(const char* data, size_t n) { buf_.append(data, n); }

    // 缓冲里凑齐一帧则取到 out 并返回 true；否则返回 false（继续喂）
    bool next(std::string& out)
    {
        if (buf_.size() < 4) return false;
        const uint8_t* h = reinterpret_cast<const uint8_t*>(buf_.data());
        const uint32_t len = (uint32_t(h[0]) << 24) | (uint32_t(h[1]) << 16) |
                             (uint32_t(h[2]) << 8)  |  uint32_t(h[3]);
        if (len > kMaxFrame) { bad_ = true; return false; }   // 超限：调用方应断开
        if (buf_.size() < 4 + len) return false;
        out.assign(buf_, 4, len);
        buf_.erase(0, 4 + len);
        return true;
    }

    bool bad() const { return bad_; }

private:
    std::string buf_;
    bool bad_ = false;
};

}  // namespace wire
