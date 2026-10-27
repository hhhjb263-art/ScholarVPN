#!/usr/bin/env python3
# ============================================================================
# scripts/gen_chnroute.py —— 生成客户端内置的国内 IPv4 网段列表
#
# 用法：
#   python scripts/gen_chnroute.py --in all_cn.txt --out docs/routing/chnroute.txt
#   python scripts/gen_chnroute.py --url https://ispip.clang.cn/all_cn.txt --out ...
#
# 为什么要聚合：
#   上游列表通常已按 /24 拆得很碎，且存在重叠。合并成最小 CIDR 集合后，
#   客户端注入的路由条目能少 20%~40%，直接决定连接时那段等待的长度。
#
# 算法：CIDR → 闭区间 → 合并重叠/相邻 → 贪心拆回最小 CIDR 集合。
# 纯标准库，无第三方依赖。
# ============================================================================

import argparse
import datetime
import ipaddress
import sys
import urllib.request


def load_lines(path, url):
    if path:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read().splitlines()
    req = urllib.request.Request(url, headers={"User-Agent": "ScholarVPN-chnroute/1"})
    with urllib.request.urlopen(req, timeout=40) as resp:
        return resp.read().decode("utf-8", errors="replace").splitlines()


def parse_ranges(lines):
    """返回 [(start, end)]，跳过空行/注释/坏行并计数。"""
    ranges = []
    bad = 0
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            bad += 1
            continue
        if net.version != 4:
            bad += 1
            continue
        ranges.append((int(net.network_address), int(net.broadcast_address)))
    return ranges, bad


def merge_ranges(ranges):
    """合并重叠与首尾相接的区间。"""
    ranges.sort()
    merged = []
    for start, end in ranges:
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def range_to_cidrs(start, end):
    """把闭区间拆成最小数量的 CIDR（贪心：每次取起点对齐的最大块）。"""
    out = []
    while start <= end:
        # 起点对齐决定最大可用块大小；0.0.0.0 特殊处理为 2^32
        max_size = (start & -start) if start else (1 << 32)
        while start + max_size - 1 > end:
            max_size >>= 1
        prefix = 32 - (max_size.bit_length() - 1)
        out.append(ipaddress.ip_network((start, prefix)))
        start += max_size
    return out


def main():
    ap = argparse.ArgumentParser()
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--in", dest="infile", help="本地输入文件")
    src.add_argument("--url", dest="url", help="远程输入 URL")
    ap.add_argument("--out", default="docs/routing/chnroute.txt")
    args = ap.parse_args()

    lines = load_lines(args.infile, args.url)
    ranges, bad = parse_ranges(lines)
    if not ranges:
        print("没有解析到任何有效网段，终止", file=sys.stderr)
        return 1

    merged = merge_ranges(ranges)
    cidrs = []
    for s, e in merged:
        cidrs.extend(range_to_cidrs(s, e))

    total_addrs = sum(n.num_addresses for n in cidrs)
    header = [
        "# ScholarVPN 国内 IPv4 网段（客户端分流用）",
        f"# 来源: {args.infile or args.url}",
        f"# 生成: {datetime.date.today().isoformat()}",
        "# 说明: 已合并重叠与相邻区间；每行一个 CIDR，# 开头为注释",
        f"# 原始: {len(lines)} 行，有效 {len(ranges)} 条，坏行 {bad}",
        f"# 聚合: {len(ranges)} → {len(merged)} 个区间 → {len(cidrs)} 条 CIDR"
        f"（覆盖 {total_addrs} 个地址）",
        "",
    ]
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(header))
        for net in cidrs:
            f.write(f"{net.network_address}/{net.prefixlen}\n")

    print(f"输出 {args.out}")
    print(f"  原始 {len(ranges)} 条 → 聚合后 {len(cidrs)} 条（{len(merged)} 个区间）")
    print(f"  坏行 {bad}，覆盖地址 {total_addrs}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
