#pragma once

#include "../UDP/UDP.h"
#include "../UDP/Session.h"

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

class TCPServer
{
public:
    explicit TCPServer(UDP& udp);
    ~TCPServer();

    TCPServer(const TCPServer&) = delete;
    TCPServer& operator=(const TCPServer&) = delete;

    bool start(const std::string& listen_ip, uint16_t port);
    void stop();
    bool is_running() const { return m_running.load(); }

private:
private:
    struct Conn
    {
        std::shared_ptr<Session> session;
        std::vector<uint8_t> rxBuf;
        std::vector<uint8_t> readTmp;
        std::vector<uint8_t> txBuf;
        size_t txOff = 0;
        bool want_epollout = false;
    };

    void event_loop();
    void handle_accept();
    bool read_conn(int fd, Conn& c);
    bool flush_conn_tx(int fd, Conn& c);
    void pump_tx();
    void wake();
    void drop_conn(int fd, const char* reason);

    UDP& m_udp;
    int m_listen_fd = -1;
    int m_epoll_fd = -1;
    int m_wake_fd = -1;
    std::string m_listen_ip;
    uint16_t m_port = 0;
    std::atomic<bool> m_running{ false };
    std::thread m_event_thread;
    std::unordered_map<int, Conn> m_conns;
};
