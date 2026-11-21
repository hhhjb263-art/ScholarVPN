#ifndef ADMINSERVER_H
#define ADMINSERVER_H

#include <string>
#include <unordered_map>
#include <ctime>
#include <memory>
#include <unistd.h>
#include <netinet/in.h>

struct HttpRequest;

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
    int m_fd = -1;
    int m_epfd = -1;
    bool m_isrunning = false;
    sockaddr_in serv{};

    std::unordered_map<int, std::unique_ptr<Session>> conns;
    std::unordered_map<std::string, std::pair<time_t,int>> auth_fails;

    std::string admin_token;
    std::string keys_dir = "keys";
    std::string tokens_path;
    std::string pubkey_path;
    std::string vpn_ip = "0.0.0.0";
    int vpn_port = 51820;

    void closeConn(int fd);
    void sweep();
    bool authBlocked(const std::string& ip);
protected:
    virtual HttpReply onRequest(const HttpRequest& req, const std::string& ip) {
        (void)req; (void)ip;
        return {501, "{\"error\":\"handler not set\"}"};
    }
    bool checkAuth(const HttpRequest& req);
    void noteAuthFail(const std::string& ip);
public:
    AdminServer();
    ~AdminServer();
    bool start(std::string ip,int port);
    void runloop();
    void stop(){ m_isrunning = false; }
    void set_keys_dir(const std::string& d){ keys_dir = d; }
};

#endif
