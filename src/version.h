#pragma once

// ============================================================================
// src/version.h —— 版本号唯一来源
//
// 规则：只改这里的数字，其它位置一律引用宏，禁止再出现字面量版本号。
// 需要同步的位置：
//   - VPN_.rc          引用 SCHOLARVPN_VER_*（VERSIONINFO，资源管理器里可见）
//   - ScholarVPN.iss   安装包版本（Inno 的脚本预处理读不了 C 头，需手工同步）
//   - CMakeLists.txt   project(... VERSION ...)
//
// 历史问题：版本号曾只写在 ScholarVPN.iss:11（"1.5"），exe 本身没有版本资源，
// 导致"安装包显示 1.5、程序内部不知道自己是几" —— 更新系统没法比较版本。
// ============================================================================

#define SCHOLARVPN_VER_MAJOR 1
#define SCHOLARVPN_VER_MINOR 7
#define SCHOLARVPN_VER_PATCH 0

// 用于日志、界面、服务端上报；必须与上面三段保持一致
#define SCHOLARVPN_VER_STRING "1.7.0"

// 便于打包脚本 / 资源脚本拼四段版本号（第四段固定 0）
#define SCHOLARVPN_VER_COMMA SCHOLARVPN_VER_MAJOR, SCHOLARVPN_VER_MINOR, SCHOLARVPN_VER_PATCH, 0

// 数值形式，供快速比较（不用于跨大版本判定，正式比较见 update::compare_version）
#define SCHOLARVPN_VER_NUM \
    ((SCHOLARVPN_VER_MAJOR << 16) | (SCHOLARVPN_VER_MINOR << 8) | SCHOLARVPN_VER_PATCH)
