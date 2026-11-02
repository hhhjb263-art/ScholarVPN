// ============================================================================
// tests/test_machine_id.cpp —— 机器指纹模块的单元测试（本机采集 + 纯函数）
//
// 隐私红线检查：
//   - MachineInfo 结构里没有 MAC 明文字段（编译期保证）；
//   - MAC 只以 SHA-256 参与指纹；
//   - 日志/UI 不打印任何采集内容（模块内无任何输出语句）。
//
// 编译运行（MSVC，需 OpenSSL）：
//   cl /MD /DNDEBUG /std:c++20 /EHsc /utf-8 /Zc:__cplusplus /I. /Isrc ^
//      tests\test_machine_id.cpp src\service\machine_id.cpp ^
//      /link /LIBPATH:third_party\openssl\lib libcrypto.lib ws2_32.lib iphlpapi.lib advapi32.lib
// ============================================================================

#include "service/machine_id.h"

#include <cstdio>
#include <string>
#include <vector>

namespace {

int g_pass = 0;
int g_fail = 0;

void check(bool ok, const char* what)
{
    if (ok)
    {
        ++g_pass;
        return;
    }
    ++g_fail;
    std::printf("  FAIL  %s\n", what);
}

bool is_lower_hex64(const std::string& s)
{
    if (s.size() != 64)
    {
        return false;
    }
    for (char c : s)
    {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
        {
            return false;
        }
    }
    return true;
}

} // namespace

int main()
{
    std::printf("== 指纹纯函数（v2：只用系统级设备标识）==\n");

    // 同输入同输出；不同输入必不同
    const std::string a1 = service::fingerprint_of("machine-guid-1");
    const std::string a2 = service::fingerprint_of("machine-guid-1");
    check(is_lower_hex64(a1), "指纹是 64 位小写 hex");
    check(a1 == a2, "同输入产出相同指纹");
    check(a1 != service::fingerprint_of("machine-guid-2"), "不同设备标识 → 不同指纹");
    check(service::fingerprint_of("").empty(), "空标识返回空指纹（不产生假设备身份）");

    // 稳定性（老板要求：机器码必须是固定值）：
    // os/cpu/ram/mac 为展示字段【不参与】指纹——网卡切换、系统补丁、
    // 内存差异都不会让同一台机器变成"新设备"

    std::printf("== MAC 哈希规范化 ==\n");

    // 大小写/分隔符归一 + 排序去重：不同写法同一结果
    const std::string m1 = service::hash_macs({"AA:BB:CC:DD:EE:FF", "11-22-33-44-55-66"});
    const std::string m2 = service::hash_macs({"aabbccddeeff", "112233445566"});
    const std::string m3 = service::hash_macs({"11:22:33:44:55:66", "aa-bb-cc-dd-ee-ff",
                                               "aa:bb:cc:dd:ee:ff"});
    check(!m1.empty() && is_lower_hex64(m1), "MAC 哈希是 64 位小写 hex");
    check(m1 == m2, "分隔符/大小写不影响结果");
    check(m1 == m3, "顺序与重复条目不影响结果（排序去重）");

    // 全零 MAC 与非法长度被拒
    check(service::hash_macs({"00:00:00:00:00:00"}).empty(), "全零 MAC 被拒绝");
    check(service::hash_macs({"aa:bb:cc"}).empty(), "非法长度被拒绝");
    check(service::hash_macs({}).empty(), "空集合返回空串");

    std::printf("== 本机采集 ==\n");

    const service::MachineInfo info1 = service::collect_machine_info();
    const service::MachineInfo info2 = service::collect_machine_info();
    check(is_lower_hex64(info1.fp), "本机指纹是 64 位小写 hex");
    check(!info1.os.empty(), "OS 采集非空");
    check(!info1.cpu.empty(), "CPU 型号采集非空");
    check(info1.ram_mb > 0, "内存大小采集 > 0");
    check(info1.fp == info2.fp, "两次采集指纹稳定（可作试用主键）");
    check(info1.os.rfind("Windows 11 build", 0) == 0 ||
          info1.os.rfind("Windows 10 build", 0) == 0,
          "OS 显示含正确的 Windows 家族名");
    check(!info1.machine_id.empty(), "系统级设备标识采集非空");
    check(info1.fp == service::fingerprint_of(info1.machine_id), "本机指纹 = 设备标识指纹");

    std::printf("\n结果: %d 通过, %d 失败\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
