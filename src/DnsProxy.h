#pragma once

#include "platform/cfgstr.h"

#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

class DnsProxy
{
public:
    bool start(const cfgstr& listFile, const std::string& upstreamDomestic,
               const std::string& upstreamForeign);
    void stop();
    bool running() const { return m_running.load(); }

private:
    void run_loop();

    std::atomic<bool> m_running{ false };
    std::thread m_thread;

    void* m_listenSock = nullptr;
    void* m_domSock = nullptr;
    void* m_forSock = nullptr;

    std::string m_upDomestic;
    std::string m_upForeign;

    std::unordered_set<std::string> m_domestic;
};
