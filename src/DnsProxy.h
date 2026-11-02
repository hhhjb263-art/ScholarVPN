// ============================================================================
// src/DnsProxy.h —— 本地 DNS 代理（流量分流 P3：按域名分流上游）
//
// 解决智能分流模式的 DNS 污染：分流模式 DNS 走国内服务器，国外域名解析被
// 污染（谷歌等不可用）。本代理监听 127.0.0.1:53：
//   · 域名命中 chn-domains.txt（国内域名表，~11 万条）→ 转发 223.5.5.5
//     （该地址在国内网段内，分流路由自动直连）
//   · 未命中 → 转发 8.8.8.8（走隧道，无污染）
//
// 线程模型：单接收线程 poll 三个 socket（监听/国内上游/国外上游），
// 收包即转发；事务表 txid→客户端地址，应答按事务回送；10s 超时清理。
//
// 安全边界：只代理 UDP 53；只应答能对上事务表的报文；畸形报文丢弃；
// 监听地址 127.0.0.1（不对外）。生命周期：受管连接不启用（强制全局隧道）；
// 仅自建分流模式 + 域名表加载成功时启动，失败则回落原 DNS 行为。
// ============================================================================
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
    // upstreamDomestic：国内域名上游（223.5.5.5，分流路由下自动直连）
    // upstreamForeign：国外域名上游（配置 DNS 首选，分流路由下走隧道）
    // listFile：国内域名表（每行一个域名，'#' 注释）
    bool start(const cfgstr& listFile, const std::string& upstreamDomestic,
               const std::string& upstreamForeign);
    void stop();
    bool running() const { return m_running.load(); }

private:
    void run_loop();

    std::atomic<bool> m_running{ false };
    std::thread m_thread;

    // socket 句柄（平台相关，实现内定义存储）
    void* m_listenSock = nullptr;
    void* m_domSock = nullptr;
    void* m_forSock = nullptr;

    std::string m_upDomestic;
    std::string m_upForeign;

    // 国内域名后缀表（小写；匹配：等于或以其为后缀）
    std::unordered_set<std::string> m_domestic;
};
