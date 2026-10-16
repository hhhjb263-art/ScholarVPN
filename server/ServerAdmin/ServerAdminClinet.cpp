
#include "ServerAdminClient.h"
#include <iostream>
#include <cstring>
#include <cerrno>
#include <cstdio>
#include <cstdlib>        // atoi / getenv
#include <filesystem>
#include <system_error>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>     // flock
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include<fstream>
namespace {
constexpr int kTimeoutMs = 5000;          // 连接/收发共用 5 秒超时
constexpr int kMaxEvents = 16;            // 一次 epoll_wait 最多取回的事件数
}

ServerAdmin::~ServerAdmin(){
    if(m_fd >= 0){
        close(m_fd);
        m_fd = -1;
    }
    if(epfd >= 0){                        // epfd 也是描述符，一样要还
        close(epfd);
        epfd = -1;
    }
}

bool ServerAdmin::start(const std::string& IP, int Port){
    m_ip = IP;                            // 记下目标，buildRequest 拼 Host 头要用
    m_port = Port;
    if(epfd >= 0){                        // 重复调用 start 时先关旧 epfd，不泄漏
        close(epfd);
        epfd = -1;
    }
    epfd = epoll_create1(0);
    if(epfd < 0){
        std::cout << "epoll_create failed: " << strerror(errno) << std::endl;
        return false;
    }
    if(m_fd >= 0){
        close(m_fd);
        m_fd = -1;
    }
    m_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(m_fd < 0){
        std::cout << "sock is created failed" << std::endl;
        return false;
    }
    sockaddr_in serv{};
    serv.sin_family = AF_INET;
    serv.sin_port = htons(Port);
    if(inet_pton(AF_INET, IP.c_str(), &serv.sin_addr) <= 0){
        std::cout << "IP地址格式错误" << std::endl;
        close(m_fd);
        m_fd = -1;
        return false;
    }
    // 非阻塞 connect + epoll 等待可写，IP 不可达时最多等 kTimeoutMs
    int flags = fcntl(m_fd, F_GETFL, 0);
    fcntl(m_fd, F_SETFL, flags | O_NONBLOCK);
    struct epoll_event ev{};
    ev.events = EPOLLOUT;                 // "可写" = 连接完成
    ev.data.fd = m_fd;                    // 统一用 data.fd，别和 data.ptr 混用
    if(epoll_ctl(epfd, EPOLL_CTL_ADD, m_fd, &ev) < 0){
        std::cout << "epoll add failed: " << strerror(errno) << std::endl;
        close(m_fd);
        m_fd = -1;
        return false;
    }
    int con = connect(m_fd, (sockaddr*)&serv, sizeof(serv));
    if(con < 0 && errno != EINPROGRESS){
        std::cout << "connect is failed: " << strerror(errno) << std::endl;
        close(m_fd);
        m_fd = -1;
        return false;
    }
    if(con < 0){                          // 连接进行中，等它完成
        struct epoll_event events[kMaxEvents];
        int n = 0;
        while(true){                      // EINTR（被信号打断）就重新等，别的结果才往下走
            n = epoll_wait(epfd, events, kMaxEvents, kTimeoutMs);
            if(n < 0 && errno == EINTR) continue;
            break;
        }
        if(n == 0){
            std::cout << "connect is failed: 连接超时" << std::endl;
            epoll_ctl(epfd, EPOLL_CTL_DEL, m_fd, nullptr);
            close(m_fd);
            m_fd = -1;
            return false;
        }
        if(n < 0){
            std::cout << "epoll_wait failed: " << strerror(errno) << std::endl;
            close(m_fd);
            m_fd = -1;
            return false;
        }
        for(int i = 0; i < n; ++i){       // 逐个处理本轮取回的事件
            if(events[i].events & (EPOLLERR | EPOLLHUP)){
                std::cout << "socket error during connect" << std::endl;
                epoll_ctl(epfd, EPOLL_CTL_DEL, m_fd, nullptr);   // DEL 才允许传 nullptr
                close(m_fd);
                m_fd = -1;
                return false;
            }
            if(events[i].events & EPOLLOUT){
                int err = 0;              // 可写不代表成功，真实结果要从 SO_ERROR 拿
                socklen_t len = sizeof(err);
                getsockopt(m_fd, SOL_SOCKET, SO_ERROR, &err, &len);
                if(err != 0){
                    std::cout << "connect is failed: " << strerror(err) << std::endl;
                    epoll_ctl(epfd, EPOLL_CTL_DEL, m_fd, nullptr);
                    close(m_fd);
                    m_fd = -1;
                    return false;
                }
            }
        }
    }
    isconnect = true;
    return true;                          // 保持非阻塞，后面 sendMsg 的事件循环要用
}

bool ServerAdmin::sendMsg(const std::string& msg)
{
    if(m_fd < 0){
        std::cout << "未连接，无法发送" << std::endl;
        return false;
    }
    sendbuf += msg;
    struct epoll_event ev{};
    ev.events = EPOLLOUT | EPOLLIN;       // 既要发也要收
    ev.data.fd = m_fd;
    if(epoll_ctl(epfd, EPOLL_CTL_MOD, m_fd, &ev) < 0){
        std::cout << "epoll_ctl failed: " << strerror(errno) << std::endl;
        return false;
    }
    while(true){                          // 事件循环：等事件 → 发 → 发完改听读 → 收到对端关闭为止
        struct epoll_event events[kMaxEvents];
        int n = epoll_wait(epfd, events, kMaxEvents, kTimeoutMs);
        if(n == 0){
            if(sendbuf.empty()){
                std::cout << "对端 " << kTimeoutMs / 1000
                          << " 秒未关闭连接，结束接收（收到 "
                          << recvbuf.size() << " 字节）" << std::endl;
                return true;              // 数据都发完了，对端不关连接不算失败
            }
            std::cout << "send is failed: 发送超时" << std::endl;
            return false;
        }
        if(n < 0){
            if(errno == EINTR) continue;
            std::cout << "epoll_wait failed: " << strerror(errno) << std::endl;
            return false;
        }
        for(int i = 0; i < n; ++i){       // 逐个处理本轮取回的事件
            if(events[i].events & EPOLLERR){
                std::cout << "socket error during send" << std::endl;
                return false;
            }
            if(events[i].events & EPOLLOUT && !sendbuf.empty()){
                ssize_t ns = send(m_fd, sendbuf.data(), sendbuf.size(), MSG_NOSIGNAL);
                if(ns < 0){
                    if(errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                        continue;         // 缓冲区满/被打断不是失败，跳过本事件等下一轮
                    std::cout << "send error: " << strerror(errno) << std::endl;
                    return false;
                }
                sendbuf.erase(0, static_cast<size_t>(ns));   // 删掉已发出的部分
                if(sendbuf.empty()){
                    struct epoll_event ev2{};
                    ev2.events = EPOLLIN;     // 发完了，只关心读——MOD 的正确用法
                    ev2.data.fd = m_fd;
                    epoll_ctl(epfd, EPOLL_CTL_MOD, m_fd, &ev2);
                }
            }
            if(events[i].events & EPOLLIN){
                char tmp[4096];
                ssize_t nr = recv(m_fd, tmp, sizeof(tmp), 0);
                if(nr == 0){                  // 对端关闭连接 = 本轮回合结束
                    return true;
                }
                if(nr < 0){
                    if(errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                        continue;
                    std::cout << "recv error: " << strerror(errno) << std::endl;
                    return false;
                }
                recvbuf.append(tmp, static_cast<size_t>(nr));
                if(recvbuf.size() > 8192){  // 响应上限 8KB，防对端失控回海量数据
                    std::cout << "recvbuf 超过 8KB，疑似非 HTTP 服务或响应异常" << std::endl;
                    return false;
                }
            }
        }
    }
    return true;
}
std::string ServerAdmin::readFile(const std::string &path)
{
    std::ifstream fin(path,std::ios::in | std::ios::binary);
    if(!fin){
        std::cout<<"open file is failed"<<std::endl;
        return "";
    }
    fin.seekg(0,std::ios::end);
    std::streampos pos = fin.tellg();
    if (pos == -1)
    {
        std::cout << "get file size fail" << std::endl;
        return "err : get size error";
    }
    fin.seekg(0,std::ios::beg);
    size_t filesize = static_cast<size_t> (pos);
    std::string content;
    content.reserve(static_cast<size_t> (filesize));
    content.assign(std::istreambuf_iterator<char>(fin),std::istreambuf_iterator<char>());
    if(!fin){
        std::cout << "read io error" << std::endl;
        return "";
    }
    return content;
}

std::vector<std::string> ServerAdmin::applyToken(int count, std::string* err)
{
    auto fail = [err](const std::string& msg) -> std::vector<std::string> {
        std::cout << "applyToken failed: " << msg << std::endl;
        if (err != nullptr) {
            *err = msg;
        }
        return {};
    };

    if (count < 1 || count > 1000) {          // 数量上限与 CLI --gen-token 一致
        return fail("count 超出范围（1-1000）: " + std::to_string(count));
    }

    std::error_code ec;
    const std::filesystem::path tokens_path(Token_path);
    std::filesystem::path keys_dir = tokens_path.parent_path();
    if (keys_dir.empty()) {
        keys_dir = ".";
    }
    std::filesystem::create_directories(keys_dir, ec);

    const std::string lock_path = tokens_path.string() + ".lock";
    const int lock_fd = open(lock_path.c_str(), O_CREAT | O_RDWR, 0600);
    if (lock_fd < 0) {
        return fail("无法打开锁文件 " + lock_path + ": " + strerror(errno));
    }
    if (flock(lock_fd, LOCK_EX) != 0) {
        const std::string msg = "flock(" + lock_path + ") 失败: " + strerror(errno);
        close(lock_fd);
        return fail(msg);
    }

    FILE* f = fopen(tokens_path.string().c_str(), "a");   // 追加模式，每行一个令牌
    if (f == nullptr) {
        const std::string msg = "无法写入 " + tokens_path.string() + ": " + strerror(errno);
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
        return fail(msg);
    }
    std::vector<std::string> tokens;
    tokens.reserve(static_cast<size_t>(count));
    for (int i = 0; i < count; ++i) {
        const std::string tok = generate_register_token();
        fprintf(f, "%s\n", tok.c_str());
        tokens.push_back(tok);
    }
    fclose(f);
    flock(lock_fd, LOCK_UN);
    close(lock_fd);
    std::cout << "applyToken: 已生成 " << count << " 个令牌并追加到 "
              << tokens_path.string() << std::endl;
    return tokens;
}

std::string ServerAdmin::buildRequest(const std::string& method, const std::string& path,
                                      const std::string& body)
{
    std::string req;
    req += method + " " + path + " HTTP/1.1\r\n";
    req += "Host: " + m_ip + ":" + std::to_string(m_port) + "\r\n";
    if(!body.empty()){
        req += "Content-Type: application/json\r\n";
    }
    // Content-Length 一律 body.size()——字节数不是字符数，中文 UTF-8 别手数；GET/DELETE 发 0 也带上
    req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    if(!admin_token.empty()){
        req += "Authorization: Bearer " + admin_token + "\r\n";
    }
    req += "Connection: close\r\n";       // 必带：服务端回完就关，sendMsg 的 recv==0 才能立刻结束
    req += "\r\n";
    req += body;
    return req;
}

bool ServerAdmin::parseResponse(const std::string& raw, HttpResponse& out)
{
    out.status = 0;
    out.reason.clear();
    out.headers.clear();
    out.body.clear();

    size_t header_end = raw.find("\r\n\r\n");     // 之前是头、之后是 body
    if(header_end == std::string::npos){
        std::cout << "响应头不完整（没找到 \\r\\n\\r\\n）" << std::endl;
        return false;
    }
    size_t body_start = header_end + 4;
    size_t line1_end = raw.find("\r\n");
    if(line1_end == std::string::npos){
        return false;
    }
    std::string line1 = raw.substr(0, line1_end);
    if(line1.rfind("HTTP/", 0) != 0){     // 对端不是 HTTP（比如裸 TCP 测试服务），报错不死等
        std::cout << "非 HTTP 响应: " << line1 << std::endl;
        return false;
    }
    size_t sp1 = line1.find(' ');         // "HTTP/1.1 200 OK" 按空格切三段
    size_t sp2 = line1.find(' ', sp1 + 1);
    if(sp1 == std::string::npos){
        std::cout << "状态行格式不对: " << line1 << std::endl;
        return false;
    }
    size_t status_end = (sp2 == std::string::npos) ? line1.size() : sp2;
    out.status = atoi(line1.substr(sp1 + 1, status_end - sp1 - 1).c_str());
    if(sp2 != std::string::npos){
        out.reason = line1.substr(sp2 + 1);
    }

    size_t pos = line1_end + 2;           // 逐行切 headers，key 统一转小写（HTTP 头大小写不敏感）
    while(pos < header_end){
        size_t line_end = raw.find("\r\n", pos);
        if(line_end == std::string::npos){
            break;
        }
        std::string hline = raw.substr(pos, line_end - pos);
        size_t colon = hline.find(':');
        if(colon != std::string::npos){
            std::string key = hline.substr(0, colon);
            for(char& c : key){
                if(c >= 'A' && c <= 'Z') c += 32;
            }
            size_t val_start = colon + 1;
            while(val_start < hline.size() && hline[val_start] == ' '){
                val_start++;
            }
            out.headers[key] = hline.substr(val_start);
        }
        pos = line_end + 2;
    }

    auto it = out.headers.find("transfer-encoding");
    if(it != out.headers.end() && it->second.find("chunked") != std::string::npos){
        std::cout << "暂不支持 chunked 编码" << std::endl;
        return false;
    }

    out.body = raw.substr(body_start);    // Connection: close 下收到对端关闭为止，后面全是 body
    return true;
}

HttpResponse ServerAdmin::sendRequest(const std::string& method, const std::string& path,
                                      const std::string& body)
{
    HttpResponse resp;
    if(m_fd < 0){
        std::cout << "未连接，先调用 start()" << std::endl;
        return resp;
    }
    sendbuf.clear();                      // 一回合一条短连接，清掉上回残留
    recvbuf.clear();
    if(!sendMsg(buildRequest(method, path, body))){   
        return resp;
    }
    parseResponse(recvbuf, resp);
    return resp;
}

int main(int argc, char* argv[])
{
    if(argc < 2){
        std::cout << "用法:\n"
                  << "  ServerAdmin info            查看公钥/IP/端口\n"
                  << "  ServerAdmin list            列出未消费令牌（需 ADMIN_TOKEN）\n"
                  << "  ServerAdmin gen <n>         申请 n 个令牌（需 ADMIN_TOKEN）\n"
                  << "  ServerAdmin del <token>     删除指定令牌（需 ADMIN_TOKEN）" << std::endl;
        return 1;
    }

    std::string cmd = argv[1];
    std::string method, path, body;
    if(cmd == "info"){
        method = "GET";  path = "/api/info";
    }else if(cmd == "list"){
        method = "GET";  path = "/api/tokens";
    }else if(cmd == "gen"){
        if(argc < 3){
            std::cout << "用法: ServerAdmin gen <数量>" << std::endl;
            return 1;
        }
        method = "POST"; path = "/api/tokens";
        body = "{\"count\":" + std::string(argv[2]) + "}";
    }else if(cmd == "del"){
        if(argc < 3){
            std::cout << "用法: ServerAdmin del <token>" << std::endl;
            return 1;
        }
        method = "DELETE"; path = "/api/tokens/" + std::string(argv[2]);
    }else{
        std::cout << "未知命令: " << cmd << std::endl;
        return 1;
    }

    ServerAdmin admin;
    const char* env = std::getenv("ADMIN_TOKEN"); // 令牌走环境变量，不进 shell history
    if(env != nullptr){
        admin.set_admin_token(env);
    }
    std::string host = "127.0.0.1";               // 默认对接本机 AdminServer
    int port = 18080;
    if(const char* h = std::getenv("ADMIN_HOST")) host = h;   // 调试时可换目标
    if(const char* p = std::getenv("ADMIN_PORT")) port = atoi(p);
    if(!admin.start(host, port)){
        return 1;
    }
    HttpResponse resp = admin.sendRequest(method, path, body);
    if(resp.status == 0){
        return 1;                         // 没拿到状态码，失败原因已在内部分别打印
    }
    std::cout << "HTTP " << resp.status;
    if(!resp.reason.empty()){
        std::cout << " " << resp.reason;
    }
    std::cout << std::endl;
    if(resp.status == 401){
        std::cout << "管理令牌无效或未提供（设置环境变量 ADMIN_TOKEN）" << std::endl;
    }else if(resp.status == 404){
        std::cout << "路径或令牌不存在" << std::endl;
    }
    std::cout << resp.body << std::endl;
    return (resp.status / 100 == 2) ? 0 : 1;
}
