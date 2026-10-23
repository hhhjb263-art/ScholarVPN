#pragma once
#include "itun_device.h"
#include <atomic>
#include <memory>

#if defined(_WIN32)

#include "wintun.h"
/*
*	使用 wintun.h 官方声明的函数类型。
	详见third_party/wintun-0.14.1/wintun/include/wintun.h源码
*/
class WintunTun : public ITunDevice {
public:
	WintunTun() = default;
	~WintunTun() override;

	WintunTun(const WintunTun&) = delete;
	WintunTun& operator=(const WintunTun&) = delete;

	bool init_tun(const std::string& TunName, const std::string& tunnelType) override;
	uint8_t* read_packet(tun_len_t* outPackLen) override;
	void release_read_packet(const uint8_t* pkt) override;
	bool write_packet(const uint8_t* RawIPdata, tun_len_t len) override;
	tun_id_t get_interface_id() const override;
	bool is_ready() const override;
	uint64_t receive_count() const;
	// 读等待事件句柄（WintunGetReadWaitEvent）：环形缓冲空时 WaitForSingleObject
	// 等它，有包到达立即唤醒——替代读循环固定 sleep 轮询；不可用时返回 nullptr
	tun_event_t read_wait_event() const override;
protected:
	void cleanup_resource() override;
private:
	bool load_wintun_api();
	bool open_or_create_adapter(const std::wstring& TunName, const std::wstring& tunnelType);
	bool fetch_adapter_luid();
	void reset_api_pointers() noexcept; // 无需抛出异常
private:
	HMODULE m_hDll = nullptr;
	WINTUN_ADAPTER_HANDLE m_hAdapter = nullptr;
	WINTUN_SESSION_HANDLE m_hsession = nullptr;
	NET_LUID m_ifliud = { };
	bool m_bInited = false;
private:
	WINTUN_CREATE_ADAPTER_FUNC* m_fnCreateAdapter = nullptr;
	WINTUN_OPEN_ADAPTER_FUNC* m_fnOpenAdapter = nullptr;
	WINTUN_CLOSE_ADAPTER_FUNC* m_fnCloseAdapter = nullptr;
	WINTUN_GET_ADAPTER_LUID_FUNC* m_fnGetAdapterLuid = nullptr;

	WINTUN_START_SESSION_FUNC* m_fnStartSession = nullptr;
	WINTUN_END_SESSION_FUNC* m_fnEndSession = nullptr;
	WINTUN_GET_READ_WAIT_EVENT_FUNC* m_fnGetReadWaitEvent = nullptr;
	WINTUN_RECEIVE_PACKET_FUNC* m_fnReceivePacket = nullptr;
	WINTUN_RELEASE_RECEIVE_PACKET_FUNC* m_fnReleaseReceivePacket = nullptr;

	WINTUN_ALLOCATE_SEND_PACKET_FUNC* m_fnAllocateSendPacket = nullptr;
	WINTUN_SEND_PACKET_FUNC* m_fnSendPacket = nullptr;
	mutable std::atomic<uint64_t> m_recv_count{ 0 };
};

#else // ---------------------------- Linux ----------------------------

#include <string>
#include <vector>

// ============================================================================
// Linux：/dev/net/tun + ioctl(TUNSETIFF, IFF_TUN | IFF_NO_PI)
//
//   - IFF_NO_PI：内核不追加 4 字节协议头，读到的就是裸 IP 包（与 Wintun 一致）
//   - 非阻塞 fd + poll()：读循环无包时等 fd（read_wait_event 直接返回 fd）
//   - 设备随 fd 关闭自动消失：不像 Wintun 是持久适配器，但"重连换 IP"仍需
//     显式 flush 地址（见 AdapterConfigLinux::clear_IPv4_addresses）
// ============================================================================
class LinuxTun : public ITunDevice {
public:
	LinuxTun() = default;
	~LinuxTun() override;

	LinuxTun(const LinuxTun&) = delete;
	LinuxTun& operator=(const LinuxTun&) = delete;

	bool init_tun(const std::string& TunName, const std::string& tunnelType) override;
	uint8_t* read_packet(tun_len_t* outPackLen) override;
	void release_read_packet(const uint8_t* pkt) override;
	bool write_packet(const uint8_t* RawIPdata, tun_len_t len) override;
	tun_id_t get_interface_id() const override;
	bool is_ready() const override;
	uint64_t receive_count() const;
	tun_event_t read_wait_event() const override;
protected:
	void cleanup_resource() override;
private:
	int m_fd = -1;
	std::string m_ifname;
	std::vector<uint8_t> m_buf;
	std::atomic<uint64_t> m_recvCount{ 0 };
};

#endif

// 平台工厂：ClientApp 只认这个，不再直接写 WintunTun / LinuxTun
std::unique_ptr<ITunDevice> create_tun_device();
