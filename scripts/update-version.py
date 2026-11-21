#!/usr/bin/env python

import io
import re
import sys
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def read_version_h():
    text = io.open(os.path.join(ROOT, "src", "version.h"), encoding="utf-8").read()
    major = re.search(r"#define\s+SCHOLARVPN_VER_MAJOR\s+(\d+)", text)
    minor = re.search(r"#define\s+SCHOLARVPN_VER_MINOR\s+(\d+)", text)
    patch = re.search(r"#define\s+SCHOLARVPN_VER_PATCH\s+(\d+)", text)
    if not (major and minor and patch):
        print("错误：src/version.h 里找不到 SCHOLARVPN_VER_MAJOR/MINOR/PATCH", file=sys.stderr)
        sys.exit(1)
    m, n, p = major.group(1), minor.group(1), patch.group(1)
    return f"{m}.{n}.{p}", (m, n, p)

def sync_iss(ver, parts):
    path = os.path.join(ROOT, "ScholarVPN.iss")
    with io.open(path, encoding="utf-8-sig", newline="") as f:
        s = f.read()
    new, n = re.subn(r'(#define\s+MyAppVersion\s+)"[^"]*"', rf'\g<1>"{ver}"', s)
    if n == 0:
        print("警告：ScholarVPN.iss 里没找到 MyAppVersion", file=sys.stderr)
        return
    with io.open(path, "w", encoding="utf-8-sig", newline="") as f:
        f.write(new)
    print(f"ScholarVPN.iss  MyAppVersion -> {ver}（{n} 处）")

def main():
    if len(sys.argv) > 1:
        ver_arg = sys.argv[1]
        if not re.fullmatch(r"\d+\.\d+\.\d+", ver_arg):
            print(f"错误：版本号格式应为 x.y.z，收到 {ver_arg}", file=sys.stderr)
            sys.exit(1)
        vh = os.path.join(ROOT, "src", "version.h")
        s = io.open(vh, encoding="utf-8").read()
        m, n, p = ver_arg.split(".")
        s = re.sub(r"(#define\s+SCHOLARVPN_VER_MAJOR\s+)\d+", rf"\g<1>{m}", s)
        s = re.sub(r"(#define\s+SCHOLARVPN_VER_MINOR\s+)\d+", rf"\g<1>{n}", s)
        s = re.sub(r"(#define\s+SCHOLARVPN_VER_PATCH\s+)\d+", rf"\g<1>{p}", s)
        s = re.sub(r'(#define\s+SCHOLARVPN_VER_STRING\s+)"[^"]*"', rf'\g<1>"{ver_arg}"', s)
        io.open(vh, "w", encoding="utf-8", newline="").write(s)
        print(f"src/version.h -> {ver_arg}")

    ver, parts = read_version_h()
    print(f"版本来源 src/version.h: v{ver}")
    sync_iss(ver, parts)
    print("完成。记得重编译并重新打包（package.bat / build-linux.sh）。")

if __name__ == "__main__":
    main()
