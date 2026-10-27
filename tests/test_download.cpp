// ============================================================================
// tests/test_download.cpp —— 下载 + SHA-256 校验（需要外网）
//
// 验证四件事：
//   1. 流式下载能落盘，字节数正确
//   2. 边下边算的哈希，与独立算出来的哈希一致
//   3. 哈希不符时失败，且**文件被删除**（不留可疑包在磁盘上）
//   4. 大小不符时同样失败并清理
// ============================================================================

#include "update/update_fetcher.h"

#include <openssl/evp.h>

#include <cstdio>
#include <string>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace {

int g_pass = 0;
int g_fail = 0;

void check(bool ok, const std::string& what)
{
    if (ok)
    {
        ++g_pass;
        return;
    }
    ++g_fail;
    std::printf("  FAIL  %s\n", what.c_str());
}

std::string sha256_of(const std::string& data)
{
    unsigned char md[EVP_MAX_MD_SIZE]{};
    unsigned int len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    EVP_DigestFinal_ex(ctx, md, &len);
    EVP_MD_CTX_free(ctx);

    static const char* kHex = "0123456789abcdef";
    std::string out;
    for (unsigned int i = 0; i < len; ++i)
    {
        out.push_back(kHex[md[i] >> 4]);
        out.push_back(kHex[md[i] & 0x0F]);
    }
    return out;
}

bool file_exists(const char* p)
{
    FILE* f = std::fopen(p, "rb");
    if (f == nullptr)
    {
        return false;
    }
    std::fclose(f);
    return true;
}

} // namespace

int main()
{
#if defined(_WIN32)
    ::SetConsoleOutputCP(CP_UTF8);
#endif

    const std::string url = "https://www.baidu.com/robots.txt";

    std::printf("== 先取内容并独立算哈希 ==\n");
    const auto text = update::fetch_text(url, 8000);
    if (!text.ok)
    {
        std::printf("  取不到样本（%s），本测试跳过\n", text.error.c_str());
        return 0;
    }
    const std::string expect = sha256_of(text.body);
    std::printf("  样本 %zu 字节，sha256=%s...\n", text.body.size(), expect.substr(0, 16).c_str());

    std::printf("== 正常下载 + 哈希匹配 ==\n");
    {
        const char* dest = "dl_ok.bin";
        std::remove(dest);
        const auto r = update::download_file(url, dest, expect, text.body.size());
        check(r.ok, "下载应成功");
        check(r.size == text.body.size(), "字节数应一致");
        check(r.sha256 == expect, "哈希应一致");
        check(file_exists(dest), "文件应存在");
        std::remove(dest);
    }

    std::printf("== 哈希不符：必须失败且删除文件 ==\n");
    {
        const char* dest = "dl_bad_hash.bin";
        std::remove(dest);
        const std::string wrong = "0000000000000000000000000000000000000000000000000000000000000000";
        const auto r = update::download_file(url, dest, wrong, 0);
        check(!r.ok, "哈希不符应失败");
        check(!file_exists(dest), "失败后不应留下文件");
        std::printf("  错误信息: %s\n", r.error.c_str());
    }

    std::printf("== 只给期望大小（不校验哈希）也能过 ==\n");
    {
        const char* dest = "dl_size.bin";
        std::remove(dest);
        const auto r = update::download_file(url, dest, "", text.body.size());
        check(r.ok, "只校验大小应成功");
        std::remove(dest);
    }

    std::printf("== 大小不符：必须失败且删除文件 ==\n");
    {
        const char* dest = "dl_bad_size.bin";
        std::remove(dest);
        const auto r = update::download_file(url, dest, "", text.body.size() + 123);
        check(!r.ok, "大小不符应失败");
        check(!file_exists(dest), "失败后不应留下文件");
    }

    std::printf("\n结果: %d 通过, %d 失败\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
