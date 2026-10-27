// ============================================================================
// tests/test_iplist.cpp —— 国内 IP 列表加载的单元测试
//
// 编译运行：
//   g++ -std=c++17 -Isrc tests/test_iplist.cpp src/platform/iplist.cpp -o test_iplist.exe
// ============================================================================

#include "platform/iplist.h"

#include <cstdio>
#include <string>
#include <vector>

namespace {

int g_pass = 0;
int g_fail = 0;

void check(bool ok, const char* what, const std::string& detail = {})
{
    if (ok)
    {
        ++g_pass;
        return;
    }
    ++g_fail;
    std::printf("  FAIL  %s%s%s\n", what, detail.empty() ? "" : "  ->  ", detail.c_str());
}

} // namespace

int main()
{
    std::printf("== 文本解析与统计 ==\n");
    {
        const std::string text =
            "# comment line\n"
            "1.0.1.0/24\n"
            "\n"
            "  1.0.2.0/23   \r\n"
            "bad line\n"
            "; another comment\n"
            "2.0.0.0/8\n";

        std::vector<cidr::Cidr> list;
        iplist::Stats st;
        iplist::parse_text(text, list, &st);

        check(st.lines == 6, "lines 应为 6", std::to_string(st.lines));
        check(st.valid == 3, "valid 应为 3", std::to_string(st.valid));
        check(st.comments == 2, "comments 应为 2", std::to_string(st.comments));
        check(st.malformed == 1, "malformed 应为 1", std::to_string(st.malformed));
        check(list.size() == 3, "条目数应为 3", std::to_string(list.size()));
    }

    std::printf("== 换行与空白容忍 ==\n");
    {
        const std::string crlf = "1.0.1.0/24\r\n1.0.2.0/23\r\n";
        std::vector<cidr::Cidr> list;
        iplist::Stats st;
        iplist::parse_text(crlf, list, &st);
        check(list.size() == 2, "CRLF 应解析出 2 条", std::to_string(list.size()));
        check(st.malformed == 0, "CRLF 不应产生坏行", std::to_string(st.malformed));
        check(cidr::to_string(list[0]) == "1.0.1.0/24", "第 1 条内容正确", cidr::to_string(list[0]));
        check(cidr::to_string(list[1]) == "1.0.2.0/23", "第 2 条内容正确", cidr::to_string(list[1]));
    }

    std::printf("== 主机位规范化 ==\n");
    {
        const std::string text = "1.0.1.99/24\n";
        std::vector<cidr::Cidr> list;
        iplist::parse_text(text, list, nullptr);
        check(list.size() == 1 && cidr::to_string(list[0]) == "1.0.1.0/24",
              "带主机位的条目应被规范化", list.empty() ? "<空>" : cidr::to_string(list[0]));
    }

    std::printf("== 重复条目去重 ==\n");
    {
        const std::string text =
            "1.0.1.0/24\n"
            "2.0.0.0/8\n"
            "1.0.1.0/24\n"
            "1.0.1.0/24\n";
        std::vector<cidr::Cidr> list;
        iplist::parse_text(text, list, nullptr);
        check(list.size() == 4, "解析后应为 4 条（未去重）", std::to_string(list.size()));
        iplist::sort_unique(list);
        check(list.size() == 2, "去重后应为 2 条", std::to_string(list.size()));
        check(cidr::to_string(list[0]) == "1.0.1.0/24", "排序后第 1 条", cidr::to_string(list[0]));
        check(cidr::to_string(list[1]) == "2.0.0.0/8", "排序后第 2 条", cidr::to_string(list[1]));
    }

    std::printf("== 空输入与文件不存在 ==\n");
    {
        std::vector<cidr::Cidr> list;
        iplist::Stats st;
        iplist::parse_text("", list, &st);
        check(list.empty() && st.lines == 0, "空文本应产生 0 条");

        std::vector<cidr::Cidr> list2;
        const bool ok = iplist::load_file(CS("__not_exist__.txt"), list2, nullptr);
        check(!ok, "不存在的文件应返回 false");
        check(list2.empty(), "失败时不应写入任何条目");
    }

    std::printf("\n结果: %d 通过, %d 失败\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
