#pragma once

// ============================================================================
// src/update/update_fetcher.h —— 拉取更新策略文件
//
// 只做一件事：GET 一个 http(s) 地址，把响应体拿回来。
// 刻意不依赖 libcurl：
//   - Windows 用系统自带 WinHTTP（零分发成本）；
//   - Linux 用 OpenSSL + 手写 HTTP/1.1（下面 update_fetcher.cpp 的 #else 分支）。
//
// ⚠️ 这里**不做任何信任判断**：拿到的内容必须由调用方验签后才可使用。
//    明文 HTTP 是可接受的，因为可信性由签名保证，不靠传输层。
// ============================================================================

#include <atomic>
#include <cstdint>
#include <string>

namespace update {

struct FetchResult {
    bool ok = false;         // 传输层成功且 HTTP 2xx
    int status = 0;          // HTTP 状态码（0 = 没拿到响应）
    std::string body;        // 响应体（原文，未解析）
    std::string error;       // 失败原因（给日志与界面）
};

// timeoutMs 同时作用于连接、发送、接收三个阶段的单次超时
FetchResult fetch_text(const std::string& url, int timeoutMs = 5000);

struct DownloadResult {
    bool ok = false;
    std::string path;        // 保存路径（成功时）
    std::string sha256;      // 实际算出的哈希（小写十六进制）
    std::uint64_t size = 0;  // 实际字节数
    std::string error;
};

// 进度回调：已接收 / 预期总量（0 表示未知）
using ProgressFn = void (*)(std::uint64_t received, std::uint64_t total, void* user);

// 流式下载到文件，边写边算 SHA-256。
// expectedSha256 非空时必须匹配，否则删除文件并返回失败——
// 绝不把未校验的包留在磁盘上，避免被上层误用。
// cancel 非空时，下载循环每收到一块都检查它：置位即停止、删文件并返回
// "已取消"。程序退出（或用户主动放弃）时用它避免傻等 48MB 下完。
DownloadResult download_file(const std::string& url,
                             const std::string& destPath,
                             const std::string& expectedSha256,
                             std::uint64_t expectedSize = 0,
                             ProgressFn progress = nullptr,
                             void* user = nullptr,
                             int timeoutMs = 15000,
                             std::atomic<bool>* cancel = nullptr);

} // namespace update
