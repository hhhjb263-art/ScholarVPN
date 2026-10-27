#!/usr/bin/env bash
# ============================================================================
# ScholarVPN Linux 安装脚本
#
#   sudo ./install-linux.sh [vpn_client 路径]
#
# 做的事：
#   1. 装二进制到 /opt/scholarvpn/
#   2. 装图标到 hicolor 主题（应用菜单/桌面显示）
#   3. 装 .desktop 到应用菜单 + 用户桌面
#   4. 装 polkit policy（pkexec 提权时显示中文说明，认证一次记 5 分钟）
#   5. 装启动器 /usr/local/bin/scholarvpn
#
# 卸载：sudo rm -rf /opt/scholarvpn /usr/local/bin/scholarvpn \
#         /usr/share/applications/scholarvpn.desktop \
#         /usr/share/polkit-1/actions/com.scholarvpn.client.policy \
#         /usr/share/icons/hicolor/256x256/apps/scholarvpn.png
#   （chnroute.txt 随 /opt/scholarvpn 一起删除）
# ============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${1:-$HERE/vpn_client}"
PREFIX=/opt/scholarvpn

if [ ! -x "$BIN" ]; then
    echo "找不到可执行的 vpn_client：$BIN" >&2
    echo "先在源码目录构建：cmake -S . -B build && cmake --build build -j" >&2
    exit 1
fi

# 非 root 时自动提权（保留当前目录与环境）
if [ "$(id -u)" -ne 0 ]; then
    exec sudo -E bash "$0" "$@"
fi

install -d -m 0755 "$PREFIX"
install -m 0755 "$BIN" "$PREFIX/vpn_client"
install -m 0755 "$HERE/scholarvpn-gui" /usr/local/bin/scholarvpn

# 国内网段列表：智能分流依赖它。缺失时客户端会降级为"全流量走隧道"，
# 不会崩，但分流不生效——所以必须随程序一起装。
# 分流数据：发布包内（与脚本同目录）优先，其次源码树（开发机直接跑）
CHNROUTE=""
for c in "$HERE/chnroute.txt" "$HERE/../../docs/routing/chnroute.txt"; do
    if [ -f "$c" ]; then
        CHNROUTE="$c"
        break
    fi
done
if [ -n "$CHNROUTE" ]; then
    install -m 0644 "$CHNROUTE" "$PREFIX/chnroute.txt"
    echo "已安装国内网段列表: $PREFIX/chnroute.txt"
else
    echo "警告：找不到 chnroute.txt，智能分流将不可用（会降级为全局模式）" >&2
fi

install -Dm644 "$HERE/scholarvpn.png" \
    /usr/share/icons/hicolor/256x256/apps/scholarvpn.png
install -Dm644 "$HERE/scholarvpn.desktop" \
    /usr/share/applications/scholarvpn.desktop
install -Dm644 "$HERE/com.scholarvpn.client.policy" \
    /usr/share/polkit-1/actions/com.scholarvpn.client.policy

gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true
update-desktop-database /usr/share/applications 2>/dev/null || true

# 桌面快捷方式：放在调用者（sudo 前的用户）桌面
REAL_USER="${SUDO_USER:-$(id -un)}"
USER_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"
if [ -n "$USER_HOME" ]; then
    for d in "$USER_HOME/桌面" "$USER_HOME/Desktop"; do
        if [ -d "$d" ]; then
            install -m 0755 -o "$REAL_USER" -g "$REAL_USER" \
                "$HERE/scholarvpn.desktop" "$d/scholarvpn.desktop"
            # GNOME 的桌面图标扩展要求标记 trusted，否则只显示成文本文件
            sudo -u "$REAL_USER" gio set "$d/scholarvpn.desktop" \
                metadata::trusted true 2>/dev/null || true
            break
        fi
    done
fi

echo
echo "安装完成："
echo "  程序    $PREFIX/vpn_client"
echo "  启动器  /usr/local/bin/scholarvpn"
echo "  菜单    /usr/share/applications/scholarvpn.desktop"
echo "  图标    /usr/share/icons/hicolor/256x256/apps/scholarvpn.png"
echo
echo "启动方式：应用菜单搜索 ScholarVPN，或双击桌面图标（首次会弹一次认证框）"
