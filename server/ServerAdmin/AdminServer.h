#ifndef ADMINSERVER_H
#define ADMINSERVER_H

#include <string>
#include <unordered_map>
#include <ctime>
#include <memory>
#include <unistd.h>       // Session 析构里用 close(fd)：头文件自己负责包含
#include <netinet/in.h>   // sockaddr_in——头文件里用到的类型

struct HttpRequest;       // 定义在 AdminServer.cpp 里，这里只前置声明（参数用引用不需要完整类型）

// 业务处理结果：你算出状态码和 body，框架负责拼 HTTP 报文、发送、关连接
struct HttpReply {
    int status = 501;
    std::string body;
};
struct Session{
    int fd = -1;
    std::string ip;
    uint16_t port;
    bool is_running  = false;
    std::string s_recvbuf;
    std::string s_sendbuf;
    time_t last_active = 0;
    ~Session(){
        if(fd >= 0){
            close(fd);
            fd = -1;
        }
    }
};
class AdminServer{
private:
    int m_port = 0;
    std::string m_ip;
    int m_fd = -1;                 // 监听 socket
    int m_epfd = -1;
    bool m_isrunning = false;
    sockaddr_in serv{};

    std::unordered_map<int, std::unique_ptr<Session>> conns;                                // 每条连接的状态
    std::unordered_map<std::string, std::pair<time_t,int>> auth_fails;  // IP → (窗口起点, 失败次数)

    std::string admin_token;       // Bearer 管理令牌（start 里从 env/文件/自动生成）
    std::string keys_dir = "keys";
    std::string tokens_path;       // start 里按 keys_dir 拼好
    std::string pubkey_path;
    std::string vpn_ip = "0.0.0.0";    // /api/info 展示用（数据面监听信息，与管理端口无关）
    int vpn_port = 51820;

    void closeConn(int fd);                               // 摘 epoll → close → 删连接表
    void sweep();                                         // 节拍清扫：读超时连接、过期限速记录
    bool authBlocked(const std::string& ip);              // 该 IP 是否已被限速拉黑（进业务前拦截）
protected:
    virtual HttpReply onRequest(const HttpRequest& req, const std::string& ip) {
        (void)req; (void)ip;
        return {501, "{\"error\":\"handler not set\"}"};  // 没写业务时统一 501
    }
    bool checkAuth(const HttpRequest& req);               // Bearer 鉴权（常量时间比较）
    void noteAuthFail(const std::string& ip);             // 业务侧鉴权失败时调它喂限速器
public:
    AdminServer();
    ~AdminServer();
    bool start(std::string ip,int port);
    void runloop();
    void stop(){ m_isrunning = false; }
    void set_keys_dir(const std::string& d){ keys_dir = d; }
};

#endif

