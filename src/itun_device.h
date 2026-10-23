#pragma once

#include <cstdint>
#include <string>

#if defined(_WIN32)

// 必须在 windows.h 之前：阻止 min/max 宏污染 std::min / std::max
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define _WINSOCKAPI_
#include <winsock2.h>
// windows.h 必须在 ntddndis.h 之前：
//   ntddndis.h（NDIS 头）会先定义 _NTDEF_ 之类的前置宏，
//   导致随后 winnt.h 里的 `typedef LONG NTSTATUS` 被条件跳过；
//   而 netioapi.h 的 NETIO_STATUS 就是 NTSTATUS —— 结果整份 netioapi.h
//   全部报"缺少类型说明符"（C4430/C2143/C2086 刷屏）。
//   winsock2.h 自己已经会引入 windows.h，这里显式写出来是为了固定顺序。
#include <windows.h>
#include <ntddndis.h>
#include "tun_macro.h"

// Windows：网卡用 LUID 标识（IP Helper 的地址/路由 API 全吃它）
using tun_id_t = NET_LUID;
using tun_len_t = uint32_t;
// 读等待对象：Wintun 会话的 ring 事件句柄
using tun_event_t = HANDLE;

#else

#include "tun_macro.h"   // 日志宏（内部已按平台工作）

// Linux：用接口名标识 —— ioctl 与 ip 命令都按名字操作，ifindex 在实现里自查。
// tun_id_t 在这里不是 POD，AdapterConfig / RouteManager 的 Linux 分支直接接受它。
using tun_id_t = std::string;
using tun_len_t = uint32_t;
// 读等待对象：tun 的 fd 本身，交给 poll()
using tun_event_t = int;

#endif

// ============================================================================
// 虚拟网卡抽象。两端差异全部收敛在这三个别名 + 具体实现里，
// ClientApp 只通过 ITunDevice / create_tun_device() 使用。
// ============================================================================
class ITunDevice {
public:
    virtual ~ITunDevice() = default;

    virtual bool init_tun(const std::string& TunName, const std::string& tunnelType) = 0;
    virtual uint8_t* read_packet(tun_len_t* outPackLen) = 0;      // 无包时返回 nullptr
    virtual void release_read_packet(const uint8_t* pkt) = 0;     // 释放读取缓冲
    virtual bool write_packet(const uint8_t* rawIPdata, tun_len_t len) = 0;
    virtual tun_id_t get_interface_id() const = 0;                // Win: LUID / Linux: 接口名
    virtual bool is_ready() const = 0;
    // 环形缓冲空时等它（Windows 事件句柄 / Linux fd）；
    // 不可用时返回无效值（Windows nullptr / Linux -1），调用方退回短 sleep
    virtual tun_event_t read_wait_event() const = 0;

protected:
    virtual void cleanup_resource() = 0;
};
