#pragma once

#include <atomic>
#include <cstdint>
#include <map>
#include <string>

namespace update {

struct FetchResult {
    bool ok = false;
    int status = 0;
    std::string body;
    std::string error;
    std::map<std::string, std::string> headers;
};

FetchResult fetch_text(const std::string& url, int timeoutMs = 5000);

struct DownloadResult {
    bool ok = false;
    std::string path;
    std::string sha256;
    std::uint64_t size = 0;
    std::string error;
};

using ProgressFn = void (*)(std::uint64_t received, std::uint64_t total, void* user);

DownloadResult download_file(const std::string& url,
                             const std::string& destPath,
                             const std::string& expectedSha256,
                             std::uint64_t expectedSize = 0,
                             ProgressFn progress = nullptr,
                             void* user = nullptr,
                             int timeoutMs = 15000,
                             std::atomic<bool>* cancel = nullptr);

}
