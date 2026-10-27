#!/usr/bin/env bash
# ============================================================================
# scripts/build-linux.sh —— Linux 一键构建 + 打包
#
# 用法（在项目根或任意位置）：
#   ./scripts/build-linux.sh               # 增量编译 + 打包
#   ./scripts/build-linux.sh --clean       # 干净重编译（删除 build 目录）
#   ./scripts/build-linux.sh --install     # 编译后安装到本机（需 sudo）
#
# 产物：dist/scholarvpn-linux-x64-<版本>.tar.gz
#       （vpn_client + install-linux.sh + 桌面集成 + chnroute.txt）
# ============================================================================

set -euo pipefail

CLEAN=0
INSTALL=0
for arg in "$@"; do
    case "$arg" in
        --clean)  CLEAN=1 ;;
        --install) INSTALL=1 ;;
        *) echo "未知参数: $arg"; exit 1 ;;
    esac
done

# 项目根（脚本在 scripts/ 下）
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# ---- 依赖检查（缺什么直接给安装命令，不让人猜）----
MISSING=""
command -v cmake  >/dev/null 2>&1 || MISSING="$MISSING cmake"
command -v g++    >/dev/null 2>&1 || MISSING="$MISSING g++"
command -v make   >/dev/null 2>&1 || MISSING="$MISSING make"
pkg-config --exists Qt6Widgets 2>/dev/null || MISSING="$MISSING qt6-base-dev"
[ -f /usr/include/openssl/ssl.h ] || MISSING="$MISSING libssl-dev"
if [ -n "$MISSING" ]; then
    echo "缺少依赖:$MISSING"
    echo "Ubuntu/Debian 安装：sudo apt install build-essential cmake qt6-base-dev libssl-dev"
    exit 1
fi

# ---- 版本号：唯一来源 src/version.h（不在此处重复维护）----
VER="$(grep -oP '(?<=#define SCHOLARVPN_VER_STRING ")[^"]+' src/version.h || true)"
VER="${VER:-0.0.0}"
echo "=== ScholarVPN v$VER Linux 构建 ==="

# ---- 清理 ----
if [ "$CLEAN" = 1 ]; then
    echo "清理 build 目录..."
    rm -rf build
fi

# ---- 配置 + 编译 ----
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release >/dev/null
if ! cmake --build build -j"$(nproc)" 2>&1 | tail -3; then
    echo "构建失败。可用 --clean 干净重试。"
    exit 1
fi
[ -x build/vpn_client ] || { echo "产物缺失：build/vpn_client"; exit 1; }

# ---- 打包 ----
DIST="$ROOT/dist"
PKGDIR="$DIST/scholarvpn-linux-x64-$VER"
mkdir -p "$PKGDIR"
cp build/vpn_client "$PKGDIR/"
cp docs/routing/chnroute.txt "$PKGDIR/"
cp scripts/linux/install-linux.sh \
   scripts/linux/scholarvpn-gui \
   scripts/linux/scholarvpn.desktop \
   scripts/linux/scholarvpn.png \
   scripts/linux/com.scholarvpn.client.policy "$PKGDIR/"
tar -czf "$DIST/scholarvpn-linux-x64-$VER.tar.gz" -C "$PKGDIR" .

echo "=== 完成 ==="
echo "二进制 : build/vpn_client"
echo "分发包 : $DIST/scholarvpn-linux-x64-$VER.tar.gz"
echo "安装   : 解包后 sudo ./install-linux.sh（或重跑本脚本加 --install）"

# ---- 可选：本机安装 ----
if [ "$INSTALL" = 1 ]; then
    echo "安装到本机..."
    sudo "$PKGDIR/install-linux.sh" "$PKGDIR/vpn_client"
fi
