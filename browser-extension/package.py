#!/usr/bin/env python3
"""打包浏览器插件分发件：python package.py [输出目录，默认 ../dist]

产物：<输出目录>/ScholarVPN-browser-extension-v<版本>.zip

内容：扩展本体（manifest / background / popup / icons）
      + 安装说明.md + config.json.example + 导入证书(管理员运行).bat
排除：config.json（含代理密码，绝不入包）、tests/、package.py、README.md（开发文档）

用法：改完扩展代码 → 改 manifest.json 的 version → 运行本脚本 → 把 zip 发出去。
"""
import json
import os
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "..", "dist")

# 显式清单：避免误把含密码的 config.json 或开发文件打进分发包
INCLUDE_FILES = [
    "manifest.json",
    "background.js",
    "popup.html",
    "popup.css",
    "popup.js",
    "config.json.example",
    "安装说明.md",
    "导入证书(管理员运行).bat",
]
INCLUDE_DIRS = ["icons"]


def main():
    with open(os.path.join(HERE, "manifest.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    version = manifest.get("version", "0.0.0")

    os.makedirs(OUT_DIR, exist_ok=True)
    zip_path = os.path.join(OUT_DIR, f"ScholarVPN-browser-extension-v{version}.zip")

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for name in INCLUDE_FILES:
            src = os.path.join(HERE, name)
            if not os.path.exists(src):
                print(f"  跳过（不存在）: {name}")
                continue
            z.write(src, name)
            print(f"  + {name}")
        for d in INCLUDE_DIRS:
            dpath = os.path.join(HERE, d)
            if not os.path.isdir(dpath):
                continue
            for root, _dirs, files in os.walk(dpath):
                for f in sorted(files):
                    full = os.path.join(root, f)
                    rel = os.path.relpath(full, HERE).replace("\\", "/")
                    z.write(full, rel)
                    print(f"  + {rel}")

    size = os.path.getsize(zip_path)
    with zipfile.ZipFile(zip_path) as z:
        names = z.namelist()
        assert "manifest.json" in names, "缺少 manifest.json"
        assert "config.json" not in names, "安全校验失败：包内出现了 config.json！"
        assert not any(n.startswith("tests/") for n in names), "包内不应包含 tests/"
        print(f"\n打包完成: {zip_path}")
        print(f"  版本 {version}，{len(names)} 个文件，{size / 1024:.1f} KB，已确认不含 config.json")


if __name__ == "__main__":
    main()
