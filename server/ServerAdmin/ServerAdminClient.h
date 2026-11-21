#ifndef SERVERADMIN_H
#define SERVERADMIN_H

#include <string>
#include <vector>
#include <unordered_map>
#include "../Crypt/crypt.h"

struct HttpResponse{
        int status = 0;
        std::string reason;
        std::unordered_map<std::string,std::string> headers;
        std::string body;
};
class ServerAdmin{
private:
    int m_fd = -1;
    int epfd = -1;
    std::string m_ip = "192.168.1.169";
    int m_port = 18889;
    std::string sendbuf;
    std::string recvbuf;
    std::string Token_path = "../keys/register_tokens.txt";
    std::string Serversign_pub = "../keys/server_sig.pub";
    std::string admin_token;
    bool isconnect = false;
public:

    ServerAdmin() = default;
    ServerAdmin(const ServerAdmin&) = delete;
    ServerAdmin& operator=(const ServerAdmin&) = delete;
    ~ServerAdmin();

    bool start(const std::string& IP, int Port);
    bool sendMsg(const std::string& msg);
    std::string readFile(const std::string & path);
    std::vector<std::string> applyToken(int count, std::string* err = nullptr);

    void set_admin_token(const std::string& t){
        admin_token = t;
    }
    HttpResponse sendRequest(const std::string& method, const std::string& path,
                             const std::string& body);
private:
    std::string buildRequest(const std::string& method, const std::string& path,
                             const std::string& body);
    bool parseResponse(const std::string& raw, HttpResponse& out);
public:
    std::string get_IP() const{
        return m_ip;
    }
    int get_port() const{
        return m_port;
    }
    std::string get_Tonken_Path() const{
        return Token_path;
    }
    std::string get_Pub_Path() const{
        return Serversign_pub;
    }
};

#endif
