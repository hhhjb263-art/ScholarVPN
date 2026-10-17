# AdminServer 参考实现（对接 ServerAdmin 客户端）

> 状态：学习版参考实现（未入构建）
> 日期：2026-10-01
> 对应文档：`后台管理服务计划书.md`（API 规范 / flock 约束 / 安全设计）
> 对接对象：`server/ServerAdmin/`（epoll HTTP 客户端，`info/list/gen/del` 四个子命令）
> 定位：单文件、零新依赖（OpenSSL 复用 `Crypt/` 现成符号）；主循环 epoll，与客户端对称，方便对照学习

---

## 1. 与客户端的对接关系

```
ServerAdmin 客户端（epoll）                        AdminServer（epoll，本文）
─────────────────────────────                    ─────────────────────────────
start():  非阻塞 connect → epoll_wait(EPOLLOUT)   listen_fd 进 epoll，可读 = 有新连接
          等连接完成                    ──TCP──▶   accept → 新连接 fd 进 epoll（EPOLLIN）
sendMsg(): EPOLLOUT send 请求报文                            │
           EPOLLIN  recv 响应                      recv 累积进该连接的缓冲
           recv==0 = 回合结束            ◀──JSON──  收齐 → parseRequest → route()
                                                  → makeResponse → send → close
                                                        （Connection: close）
```

两端靠两个约定咬合：

1. 客户端每个请求带 `Connection: close` → 服务端**回完一个请求就 close**；
2. 服务端 close → 客户端 `recv` 返回 0 → 客户端回合结束。**服务端忘关连接，客户端每条命令都会傻等 5 秒超时**——这是两端最容易踩的坑。

## 2. 完整代码

保存为 `server/Admin/admin_server.cpp`（`Admin/` 目录不存在就新建）：

```cpp
// admin_server.cpp —— AdminServer 学习版：server/ServerAdmin/ 客户端的对端
// 127.0.0.1:18080，四个 API（info / tokens 的 GET·POST·DELETE），
// Bearer 鉴权，令牌文件 flock，Connection: close 短连接
#include <iostream>
#include <cstring>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>     // flock
#include <sys/stat.h>     // chmod
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <poll.h>         // sendAll 里写缓冲满时单点救急
#include <openssl/evp.h>
#include "../Crypt/crypt.h"   // generate_register_token / load_ed25519_public_key

namespace {
constexpr int  kMaxEvents  = 16;
constexpr size_t kMaxRequest = 8192;   // 请求头+体上限 8KB（计划书第 7 节）
constexpr int  kIoTimeoutMs  = 5000;   // 与客户端对称的 5 秒
}

// ============ 极简 JSON 工具：只服务这组固定接口，不做完整解析 ============
// PEM 里有真实换行，拼进 JSON 字符串必须转义，否则就是非法 JSON
std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
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

// ============ HTTP 请求解析（客户端 parseResponse 的镜像） ============
struct HttpRequest {
    std::string method;
    std::string path;
    std::string version;
    std::string body;
    std::unordered_map<std::string, std::string> headers;   // key 统一小写
};

// 返回：0 = 数据没收全，继续等；1 = 解析成功；2 = 格式错误（回 400）
int parseRequest(const std::string& raw, HttpRequest& req, size_t& out_len) {
    size_t header_end = raw.find("\r\n\r\n");       // 空行 = 头结束
    if (header_end == std::string::npos) return 0;
    size_t body_start = header_end + 4;

    size_t line1_end = raw.find("\r\n");
    if (line1_end == std::string::npos) return 2;
    std::string line1 = raw.substr(0, line1_end);
    size_t sp1 = line1.find(' ');                   // "GET /api/info HTTP/1.1" 按空格切三段
    size_t sp2 = line1.find(' ', sp1 + 1);
    if (sp1 == std::string::npos || sp2 == std::string::npos) return 2;
    req.method  = line1.substr(0, sp1);
    req.path    = line1.substr(sp1 + 1, sp2 - sp1 - 1);
    req.version = line1.substr(sp2 + 1);
    if (req.version.rfind("HTTP/", 0) != 0) return 2;

    size_t pos = line1_end + 2;                     // 逐行切 headers，key 转小写
    while (pos < header_end) {
        size_t line_end = raw.find("\r\n", pos);
        if (line_end == std::string::npos) break;
        std::string hline = raw.substr(pos, line_end - pos);
        size_t colon = hline.find(':');
        if (colon != std::string::npos) {
            std::string key = hline.substr(0, colon);
            for (char& c : key)
                if (c >= 'A' && c <= 'Z') c += 32;
            size_t v = colon + 1;
            while (v < hline.size() && hline[v] == ' ') v++;
            req.headers[key] = hline.substr(v);
        }
        pos = line_end + 2;
    }

    long long cl = 0;                               // 客户端约定：GET/DELETE 也发 Content-Length: 0
    auto it = req.headers.find("content-length");
    if (it != req.headers.end()) cl = atoll(it->second.c_str());
    if (cl < 0) return 2;
    size_t total = body_start + static_cast<size_t>(cl);
    if (raw.size() < total) return 0;               // body 还没收全
    req.body = raw.substr(body_start, static_cast<size_t>(cl));
    out_len = total;
    return 1;
}

std::string makeResponse(int status, const std::string& reason, const std::string& body) {
    std::string res;
    res += "HTTP/1.1 " + std::to_string(status) + " " + reason + "\r\n";
    res += "Content-Type: application/json\r\n";
    res += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    res += "Connection: close\r\n";                 // 回完就关——客户端 recv==0 靠它收尾
    res += "\r\n";
    res += body;
    return res;
}

const char* reasonPhrase(int status) {
    switch (status) {
        case 200: return "OK";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 413: return "Payload Too Large";
        case 500: return "Internal Server Error";
        default:  return "OK";
    }
}

// ============ 令牌文件操作（计划书第 6 节：flock 是硬约束） ============
// CLI --gen-token、运行中的 vpn_server（消费删行）、本服务三方共用 <tokens>.lock 一把锁，
// 谁都不许裸读写 register_tokens.txt
class FileLock {                                    // RAII：构造加锁，析构解锁，异常也不漏
public:
    explicit FileLock(const std::string& lock_path, int op) {
        fd_ = open(lock_path.c_str(), O_CREAT | O_RDWR, 0600);
        if (fd_ >= 0 && flock(fd_, op) != 0) { close(fd_); fd_ = -1; }
    }
    ~FileLock() {
        if (fd_ >= 0) { flock(fd_, LOCK_UN); close(fd_); }
    }
    bool ok() const { return fd_ >= 0; }
    FileLock(const FileLock&) = delete;             // 锁的所有权不许拷贝
    FileLock& operator=(const FileLock&) = delete;
private:
    int fd_ = -1;
};

std::vector<std::string> listTokens(const std::string& tokens_path, bool& ok) {
    ok = false;
    FileLock lock(tokens_path + ".lock", LOCK_SH);  // 读锁：多个读者可并发
    if (!lock.ok()) return {};
    std::ifstream fin(tokens_path);
    ok = true;                                      // 文件不存在 = 还没有令牌，空列表不算错
    std::vector<std::string> out;
    std::string line;
    while (std::getline(fin, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        if (!line.empty()) out.push_back(line);
    }
    return out;
}

bool appendTokens(const std::string& tokens_path, int count, std::vector<std::string>& out) {
    FileLock lock(tokens_path + ".lock", LOCK_EX);
    if (!lock.ok()) return false;
    FILE* f = fopen(tokens_path.c_str(), "a");      // 追加模式，与 CLI --gen-token 同款
    if (!f) return false;
    for (int i = 0; i < count; ++i) {
        std::string tok = generate_register_token();    // 复用 Crypt 现成符号，不重写算法
        fprintf(f, "%s\n", tok.c_str());
        out.push_back(tok);
    }
    fclose(f);
    return true;
}

// 计划书同款语义：flock 持有期间 读全表 → 过滤 → 临时文件 → rename 原子替换
// 返回：1 = 删了，0 = 没找到，-1 = IO 失败
int removeToken(const std::string& tokens_path, const std::string& token) {
    FileLock lock(tokens_path + ".lock", LOCK_EX);
    if (!lock.ok()) return -1;
    std::ifstream fin(tokens_path);
    if (!fin) return 0;
    std::vector<std::string> keep;
    bool found = false;
    std::string line;
    while (std::getline(fin, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        if (line.empty()) continue;
        if (line == token) { found = true; continue; }  // 跳过要删的行
        keep.push_back(line);
    }
    fin.close();
    if (!found) return 0;
    const std::string tmp = tokens_path + ".tmp";
    {
        std::ofstream fout(tmp, std::ios::trunc);
        for (const auto& l : keep) fout << l << "\n";
    }
    if (rename(tmp.c_str(), tokens_path.c_str()) != 0) return -1;
    return 1;
}

// ============ 鉴权（计划书第 7 节的简化版） ============
bool checkAuth(const HttpRequest& req, const std::string& admin_token) {
    auto it = req.headers.find("authorization");
    if (it == req.headers.end()) return false;
    const std::string prefix = "Bearer ";
    if (it->second.rfind(prefix, 0) != 0) return false;
    return it->second.substr(prefix.size()) == admin_token;
    // 学习版用 == 直接比；正式版按计划书换 CRYPTO_memcmp 常量时间比较，防时序侧信道
}

// ============ 公钥：PEM 原文 + 32 字节原始公钥转 64 hex ============
bool readPubkey(const std::string& pem_path, std::string& pem_out, std::string& hex_out) {
    std::ifstream fin(pem_path, std::ios::binary);
    if (!fin) return false;                         // 文件不存在：回 null 字段（计划书 4.1）
    std::ostringstream ss;
    ss << fin.rdbuf();
    pem_out = ss.str();

    EVP_PKEY* pkey = nullptr;
    try {
        pkey = load_ed25519_public_key(pem_path);   // Crypt 现成的加载函数
    } catch (const std::exception& e) {             // 注意：它失败时是抛异常，不是返回 nullptr！
        std::cout << "load pubkey failed: " << e.what() << std::endl;
        return false;
    }
    unsigned char raw[64];
    size_t raw_len = sizeof(raw);                   // 入/出双用参数：传入=缓冲区大小！
    bool ok = EVP_PKEY_get_raw_public_key(pkey, raw, &raw_len) == 1;
    EVP_PKEY_free(pkey);                            // load 出来的必须自己还
    if (!ok) return false;
    static const char* hexd = "0123456789abcdef";
    for (size_t i = 0; i < raw_len; ++i) {
        hex_out += hexd[raw[i] >> 4];
        hex_out += hexd[raw[i] & 0xF];
    }
    return true;
}

// ============ 业务路由：整个服务端唯一的"业务逻辑"块 ============
// 输入解析好的请求，输出状态码 + JSON body。传输/解析都在上面，这里只认字符串。
std::string route(const HttpRequest& req, int& status,
                  const std::string& admin_token,
                  const std::string& tokens_path,
                  const std::string& pubkey_path,
                  const std::string& vpn_ip, int vpn_port) {
    // GET /api/info：公开访问（公钥/监听信息本来就是给客户端连的公开信息）
    if (req.method == "GET" && req.path == "/api/info") {
        std::string pk = "\"pubkey_pem\":null,\"pubkey_hex\":null";
        std::string pem, hex;
        if (readPubkey(pubkey_path, pem, hex)) {
            pk = "\"pubkey_pem\":\"" + jsonEscape(pem) + "\",\"pubkey_hex\":\"" + hex + "\"";
        }   // 文件不存在时回 null（计划书 4.1），页面显示"未找到公钥文件"
        status = 200;
        return "{\"version\":\"1.0\"," + pk +
               ",\"ip\":\"" + jsonEscape(vpn_ip) +
               "\",\"port\":" + std::to_string(vpn_port) + "}";
    }

    // 剩下三个接口都要 Bearer
    if (!checkAuth(req, admin_token)) {
        status = 401;
        return "{\"error\":\"unauthorized\"}";
    }

    if (req.method == "GET" && req.path == "/api/tokens") {
        bool ok = false;
        std::vector<std::string> toks = listTokens(tokens_path, ok);
        if (!ok) { status = 500; return "{\"error\":\"read tokens failed\"}"; }
        std::string body = "{\"tokens\":[";
        for (size_t i = 0; i < toks.size(); ++i) {
            if (i) body += ",";
            body += "\"" + toks[i] + "\"";          // 令牌是 64 hex，不需要转义
        }
        status = 200;
        return body + "]}";
    }

    if (req.method == "POST" && req.path == "/api/tokens") {
        // body 形如 {"count":5}——极简提取，不做完整 JSON 解析
        size_t p = req.body.find("\"count\"");
        p = (p == std::string::npos) ? std::string::npos : req.body.find(':', p);
        int count = (p == std::string::npos) ? -1 : atoi(req.body.c_str() + p + 1);
        if (count < 1 || count > 1000) {            // 上限与 CLI --gen-token 一致
            status = 400;
            return "{\"error\":\"count must be 1-1000\"}";
        }
        std::vector<std::string> fresh;
        if (!appendTokens(tokens_path, count, fresh)) {
            status = 500;
            return "{\"error\":\"append tokens failed\"}";
        }
        std::string body = "{\"tokens\":[";
        for (size_t i = 0; i < fresh.size(); ++i) {
            if (i) body += ",";
            body += "\"" + fresh[i] + "\"";
        }
        status = 200;
        return body + "]}";
    }

    if (req.method == "DELETE" && req.path.rfind("/api/tokens/", 0) == 0) {
        std::string token = req.path.substr(12);    // 掐掉 "/api/tokens/"
        int r = removeToken(tokens_path, token);
        if (r < 0) { status = 500; return "{\"error\":\"remove failed\"}"; }
        if (r == 0) { status = 404; return "{\"error\":\"token not found\"}"; }
        status = 200;
        return "{\"deleted\":true}";
    }

    if (req.path.rfind("/api/", 0) == 0) {          // 路径认识、方法不认识
        status = 405;
        return "{\"error\":\"method not allowed\"}";
    }
    status = 404;
    return "{\"error\":\"not found\"}";
}

// ============ 管理令牌：环境变量 > 文件 > 自动生成落盘 ============
std::string loadOrCreateAdminToken(const std::string& keys_dir, bool& from_env) {
    from_env = false;
    if (const char* env = getenv("ADMIN_TOKEN")) {
        from_env = true;
        return env;
    }
    const std::string path = keys_dir + "/admin_token.txt";
    std::ifstream fin(path);
    if (fin) {
        std::string t;
        std::getline(fin, t);
        while (!t.empty() && (t.back() == '\r' || t.back() == '\n')) t.pop_back();
        if (!t.empty()) return t;
    }
    std::string t = generate_register_token();      // 64 hex，和注册令牌同源
    FILE* f = fopen(path.c_str(), "w");
    if (f) {
        fprintf(f, "%s\n", t.c_str());
        fclose(f);
        chmod(path.c_str(), 0600);                  // 计划书：落盘 0600
    }
    return t;
}

// ============ 发送：小响应一次 send 通常就完，EAGAIN 时 poll(POLLOUT) 救急 ============
bool sendAll(int fd, const std::string& data) {
    size_t off = 0;
    while (off < data.size()) {
        ssize_t ns = send(fd, data.data() + off, data.size() - off, MSG_NOSIGNAL);
        if (ns > 0) { off += static_cast<size_t>(ns); continue; }
        if (ns < 0 && errno == EINTR) continue;
        if (ns < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            pollfd p{};                             // 只为这一处写阻塞，不污染主 epoll
            p.fd = fd;
            p.events = POLLOUT;
            if (poll(&p, 1, kIoTimeoutMs) <= 0) return false;
            continue;
        }
        return false;                               // 对端已关等真错误
    }
    return true;
}

int main() {
    // ---- 配置：全部可用环境变量覆盖，默认值与计划书一致 ----
    const char* env = nullptr;
    std::string bind_ip  = (env = getenv("ADMIN_BIND")) ? env : "127.0.0.1";
    int         port     = (env = getenv("ADMIN_PORT")) ? atoi(env) : 18080;
    std::string keys_dir = (env = getenv("KEYS_DIR"))   ? env : "keys";
    std::string vpn_ip   = (env = getenv("VPN_IP"))     ? env : "0.0.0.0";
    int         vpn_port = (env = getenv("VPN_PORT"))   ? atoi(env) : 51820;
    const std::string tokens_path = keys_dir + "/register_tokens.txt";
    const std::string pubkey_path = keys_dir + "/server_sig.pub";

    bool from_env = false;
    const std::string admin_token = loadOrCreateAdminToken(keys_dir, from_env);
    std::cout << "AdminServer: 管理令牌"
              << (from_env ? "来自 ADMIN_TOKEN 环境变量"
                           : "在 " + keys_dir + "/admin_token.txt（0600）")
              << std::endl;

    // ---- 监听 socket ----
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        std::cout << "socket failed: " << strerror(errno) << std::endl;
        return 1;
    }
    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));  // 重启免等 TIME_WAIT
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, bind_ip.c_str(), &addr.sin_addr) <= 0) {
        std::cout << "绑定地址格式错误: " << bind_ip << std::endl;
        return 1;
    }
    if (bind(listen_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cout << "bind failed: " << strerror(errno) << "（端口被占用？）" << std::endl;
        return 1;
    }
    if (listen(listen_fd, 16) < 0) {
        std::cout << "listen failed: " << strerror(errno) << std::endl;
        return 1;
    }
    int flags = fcntl(listen_fd, F_GETFL, 0);
    fcntl(listen_fd, F_SETFL, flags | O_NONBLOCK);  // 非阻塞 accept：没人来时返回 EAGAIN

    // ---- epoll：listen_fd 也要进 epoll！它的"可读"= 有新连接 ----
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        std::cout << "epoll_create1 failed: " << strerror(errno) << std::endl;
        return 1;
    }
    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = listen_fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &ev);

    std::unordered_map<int, std::string> conns;     // 每个连接一个收包缓冲，按 fd 索引
    std::cout << "AdminServer listening on " << bind_ip << ":" << port << std::endl;

    while (true) {
        epoll_event events[kMaxEvents];
        int n = epoll_wait(epfd, events, kMaxEvents, -1);   // 服务端没有回合超时需求，-1 = 一直等
        if (n < 0) {
            if (errno == EINTR) continue;
            std::cout << "epoll_wait failed: " << strerror(errno) << std::endl;
            break;
        }
        for (int i = 0; i < n; ++i) {
            const int fd = events[i].data.fd;

            // ---- 情况一：listen_fd 可读 = 有新连接进来 ----
            if (fd == listen_fd) {
                while (true) {                          // 可能一次来多个，accept 到 EAGAIN 为止
                    int cfd = accept(listen_fd, nullptr, nullptr);
                    if (cfd < 0) break;
                    int fl = fcntl(cfd, F_GETFL, 0);
                    fcntl(cfd, F_SETFL, fl | O_NONBLOCK);
                    epoll_event cev{};
                    cev.events = EPOLLIN;
                    cev.data.fd = cfd;
                    epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, &cev);
                    conns[cfd] = "";                    // 给新连接开一个空缓冲
                }
                continue;
            }

            // ---- 情况二：已有连接的事件 ----
            bool close_it = false;
            bool oversized = false;
            std::string& buf = conns[fd];

            if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                close_it = true;
            }
            if (!close_it && (events[i].events & EPOLLIN)) {
                char tmp[4096];
                while (true) {                          // 一轮读完：读到 EAGAIN 为止
                    ssize_t nr = recv(fd, tmp, sizeof(tmp), 0);
                    if (nr > 0) {
                        buf.append(tmp, static_cast<size_t>(nr));
                        if (buf.size() > kMaxRequest) { // 8KB 上限：头都没收齐也挡得住
                            oversized = true;
                            break;
                        }
                        continue;
                    }
                    if (nr == 0) { close_it = true; break; }   // 对端没发全就关了
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    if (errno == EINTR) continue;
                    close_it = true;
                    break;
                }
            }

            if (!close_it && oversized) {
                sendAll(fd, makeResponse(413, reasonPhrase(413),
                                         "{\"error\":\"request too large\"}"));
                close_it = true;
            }

            // 收齐一个完整请求？→ 处理并回包，然后按 Connection: close 关连接
            if (!close_it) {
                HttpRequest req;
                size_t used = 0;
                const int r = parseRequest(buf, req, used);
                if (r == 2) {                           // 格式错误：回 400 再关
                    sendAll(fd, makeResponse(400, reasonPhrase(400),
                                             "{\"error\":\"bad request\"}"));
                    close_it = true;
                } else if (r == 1) {                    // 成功 → 路由 → 回包 → 关
                    int status = 0;
                    std::string body = route(req, status, admin_token, tokens_path,
                                             pubkey_path, vpn_ip, vpn_port);
                    sendAll(fd, makeResponse(status, reasonPhrase(status), body));
                    close_it = true;                    // 一个连接只服务一个请求
                }
                // r == 0：还没收全，什么都不做，继续等下一轮 EPOLLIN
            }

            if (close_it) {
                epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);   // 先摘再关，顺序别反
                close(fd);
                conns.erase(fd);
            }
        }
    }

    close(listen_fd);
    close(epfd);
    return 0;
}
```

## 3. 编译与运行

```bash
cd /home/user/vscode/server
g++ -std=c++17 -Wall -Wextra -o AdminServer Admin/admin_server.cpp Crypt/crypt.cpp -lcrypto -pthread

# 运行（注意 keys/ 是相对路径，和客户端一样的坑——在 server/ 目录下启动）
./AdminServer
# 可用环境变量覆盖：ADMIN_BIND / ADMIN_PORT / KEYS_DIR / VPN_IP / VPN_PORT / ADMIN_TOKEN
```

首次启动会打印管理令牌的来源：没有 `ADMIN_TOKEN` 环境变量时，自动生成 64 hex 写入 `keys/admin_token.txt`（0600）。

## 4. 测试

```bash
# 终端 1
cd /home/user/vscode/server && ./AdminServer

# 终端 2 —— curl 四连
curl http://127.0.0.1:18080/api/info
TOKEN=$(cat keys/admin_token.txt)
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:18080/api/tokens
curl -X POST -H "Authorization: Bearer $TOKEN" -d '{"count":3}' http://127.0.0.1:18080/api/tokens
curl -X DELETE -H "Authorization: Bearer $TOKEN" http://127.0.0.1:18080/api/tokens/<某个令牌>

# 错误路径
curl http://127.0.0.1:18080/api/tokens                    # 401
curl -X POST -H "Authorization: Bearer $TOKEN" \
     -d '{"count":9999}' http://127.0.0.1:18080/api/tokens # 400

# 用自家客户端测（等价于上面四条 curl）
ADMIN_TOKEN=$TOKEN ./ServerAdmin info
ADMIN_TOKEN=$TOKEN ./ServerAdmin list
ADMIN_TOKEN=$TOKEN ./ServerAdmin gen 3
ADMIN_TOKEN=$TOKEN ./ServerAdmin del <某个令牌>
```

注意：客户端有 recvbuf 8KB 上限，`list`/`gen` 的响应太长（约 120 个令牌以上）会被客户端拒绝——学习版测试时数量别太大，正式版要么调大上限要么分页。

## 5. 学习要点：epoll 服务端和客户端的六个差异

| # | 客户端（ServerAdmin） | 服务端（本文） |
|---|---|---|
| 1 | 一个固定 fd（connect 出来的） | **listen_fd 也进 epoll**——它的"可读"不是数据，是**有新连接** |
| 2 | 连接只有一个，收包缓冲用类成员 `recvbuf` 就够 | 连接同时有多个，收包缓冲按 fd 索引：`unordered_map<int, string>` |
| 3 | 事件循环出口是"发完 + 对端关闭" | 事件循环**永不退出**；单条连接的生命周期 = 一个请求（Connection: close） |
| 4 | `epoll_wait(…, 5000)`：回合有 5 秒超时 | `epoll_wait(…, -1)`：服务端没事干就该一直睡，来活再醒 |
| 5 | 超时 = 失败（对端不可达） | 没有对端超时概念；防的是**单个连接**吃 8KB 限额 |
| 6 | fd 生命周期 = 进程生命周期，析构统一 close | fd 高频生灭：**accept 出来 ADD，回完请求 DEL+close，map 同步 erase**——漏一步就 fd 泄漏 |

还有一个两端呼应的细节：服务端 `Connection: close` 回完就关，客户端 `recv` 才会返回 0。**把服务端这行去掉试试**，你会看到客户端每条命令都等满 5 秒——这是验证"你真的理解回合怎么结束"的最好实验。

## 6. 与计划书正式版的差距

学习版刻意省掉的（正式版落地时按计划书补）：

| 项 | 学习版 | 计划书正式版 |
|---|---|---|
| 鉴权比较 | `==` 直接比 | `CRYPTO_memcmp` 常量时间比较 |
| 失败限速 | 无 | 按来源 IP 令牌桶（5 次/分钟） |
| 审计日志 | 无 | 每次申请/删除/鉴权失败写 `logs/` |
| JSON | 手拼 + 单字段提取 | 仍可手写（接口固定），但要补转义边界测试 |
| 读超时 | 无——客户端若在 body 收齐前死掉，服务端会一直等满 Content-Length | 读写超时 5s，超时关连接 |
| 并发模型 | 单线程 epoll | 计划书说"管理流量极低，accept + 单连接顺序处理"也够——**选 epoll 是为了和客户端对称、练 accept**，不是性能必须 |
| 部署 | 独立进程手动跑 | 内嵌 `vpn_server` 管理线程，随主服务启停 |
