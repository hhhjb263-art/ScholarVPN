#pragma once

#include <cstdint>
#include <string>

#if defined(_WIN32)

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define _WINSOCKAPI_
#include <winsock2.h>
#include <windows.h>
#include <ntddndis.h>
#include "tun_macro.h"

using tun_id_t = NET_LUID;
using tun_len_t = uint32_t;
using tun_event_t = HANDLE;

#else

#include "tun_macro.h"

using tun_id_t = std::string;
using tun_len_t = uint32_t;
using tun_event_t = int;

#endif

// 虚拟网卡抽象：Windows 用 Wintun，Linux 用 /dev/net/tun
class ITunDevice {
public:
    virtual ~ITunDevice() = default;

    virtual bool init_tun(const std::string& TunName, const std::string& tunnelType) = 0;
    virtual uint8_t* read_packet(tun_len_t* outPackLen) = 0;
    virtual void release_read_packet(const uint8_t* pkt) = 0;
    virtual bool write_packet(const uint8_t* rawIPdata, tun_len_t len) = 0;
    virtual tun_id_t get_interface_id() const = 0;
    virtual bool is_ready() const = 0;
    virtual tun_event_t read_wait_event() const = 0;

protected:
    virtual void cleanup_resource() = 0;
};
