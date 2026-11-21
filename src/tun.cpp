#pragma once

#include "tun.h"

#if defined(_WIN32)
#include <atomic>
#include <cstring>
#include <type_traits>
#include <cstdint>
#include <iostream>
#include <string>
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace {
	constexpr DWORD kSessionRingCapacity = 4u * 1024u * 1024u;

	template <typename Function>
	bool load_function(
		HMODULE module,
		const char* functionName,
		Function*& output) noexcept
	{
		output = nullptr;
		if (module == nullptr || functionName == nullptr) {
			::SetLastError(ERROR_INVALID_PARAMETER);
			return false;
		}
		FARPROC address = ::GetProcAddress(module, functionName);
		if (address == nullptr) {
			return false;
		}
		output = reinterpret_cast<Function*>(address);
		return true;
	}

	std::wstring StringToWString(const std::string& s)
	{
		if (s.empty()) return L"";
		int wcharCount = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
		std::wstring wBuf(wcharCount, 0);
		MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &wBuf[0], wcharCount);
		return wBuf;
	}
	std::string hex_summary(const uint8_t* data, size_t len, size_t max_print = 32)
	{
		if (data == nullptr || len == 0) return "<empty>";
		std::ostringstream oss;
		oss << std::hex << std::setfill('0');
		size_t to = (std::min)(len, max_print);
		for (size_t i = 0; i < to; ++i) {
			oss << std::setw(2) << static_cast<int>(data[i]);
			if (i + 1 != to) oss << ' ';
		}
		if (len > max_print) oss << " ...";
		return oss.str();
	}
}

WintunTun::~WintunTun()
{
	cleanup_resource();
	if (m_hDll != nullptr)
	{
		::FreeLibrary(m_hDll);
		m_hDll = nullptr;
	}
}

bool WintunTun::init_tun(const std::string& TunName, const std::string& tunnelType)
{
	if (m_bInited) {
		LOG_ERROR("DLL 已加载，禁止重复加载");
		return false;
	}
	if (TunName.empty() || tunnelType.empty()) {
		LOG_ERROR("参数名称不能为空");
		::SetLastError(ERROR_INVALID_PARAMETER);
		return false;
	}
	cleanup_resource();

	m_hDll = ::LoadLibraryExW(
		L"wintun.dll",
		nullptr,
		LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32
	);
	if (m_hDll == nullptr) {
		DWORD err = ::GetLastError();
		LOG_ERROR("wintun.dll 加载失败 err=%lu", err);
		return false;
	}

	if (!load_wintun_api())
	{
		DWORD err = ::GetLastError();
		LOG_ERROR("批量加载Wintun导出函数失败, err=%lu", err);
		cleanup_resource();
		return false;
	}

	std::wstring wTun = StringToWString(TunName);
	std::wstring wType = StringToWString(tunnelType);
	if (!open_or_create_adapter(wTun, wType))
	{
		DWORD err = ::GetLastError();
		LOG_ERROR("网卡创建/打开失败，err = %lu", err);
		cleanup_resource();
		return false;
	}

	if (!fetch_adapter_luid())
	{
		DWORD err = ::GetLastError();
		LOG_ERROR("获取网卡LUID失败，err = %lu", err);
		cleanup_resource();
		return false;
	}

	m_hsession = m_fnStartSession(m_hAdapter, kSessionRingCapacity);
	if (m_hsession == nullptr) {
		DWORD err = ::GetLastError();
		LOG_ERROR("启动Wintun会话失败，err = %lu", err);
		cleanup_resource();
		return false;
	}

	m_bInited = true;
	::SetLastError(ERROR_SUCCESS);
	LOG_INFO("Tun适配器初始化完成");
	return true;
}

bool WintunTun::load_wintun_api()
{
	if (m_hDll == nullptr) {
		::SetLastError(ERROR_INVALID_HANDLE);
		LOG_ERROR("DLL模块句柄为空");
		return false;
	}
	bool success = true;
	if (!load_function(m_hDll, "WintunCreateAdapter", m_fnCreateAdapter))
	{
		LOG_ERROR("加载 WintunCreateAdapter 失败"); success = false;
	}
	if (!load_function(m_hDll, "WintunOpenAdapter", m_fnOpenAdapter))
	{
		LOG_ERROR("加载 WintunOpenAdapter 失败"); success = false;
	}
	if (!load_function(m_hDll, "WintunCloseAdapter", m_fnCloseAdapter))
	{
		LOG_ERROR("加载 WintunCloseAdapter 失败"); success = false;
	}
	if (!load_function(m_hDll, "WintunGetAdapterLUID", m_fnGetAdapterLuid))
	{
		LOG_ERROR("加载 WintunGetAdapterLUID 失败"); success = false;
	}
	if (!load_function(m_hDll, "WintunStartSession", m_fnStartSession))
	{
		LOG_ERROR("加载 WintunStartSession 失败"); success = false;
	}
	if (!load_function(m_hDll, "WintunEndSession", m_fnEndSession))
	{
		LOG_ERROR("加载 WintunEndSession 失败"); success = false;
	}
	if (!load_function(m_hDll, "WintunGetReadWaitEvent", m_fnGetReadWaitEvent))
	{
		LOG_ERROR("加载 WintunGetReadWaitEvent 失败"); success = false;
	}
	if (!load_function(m_hDll, "WintunReceivePacket", m_fnReceivePacket))
	{
		LOG_ERROR("加载 WintunReceivePacket 失败"); success = false;
	}
	if (!load_function(m_hDll, "WintunReleaseReceivePacket", m_fnReleaseReceivePacket))
	{
		LOG_ERROR("加载 WintunReleaseReceivePacket 失败"); success = false;
	}
	if (!load_function(m_hDll, "WintunAllocateSendPacket", m_fnAllocateSendPacket))
	{
		LOG_ERROR("加载 WintunAllocateSendPacket 失败"); success = false;
	}
	if (!load_function(m_hDll, "WintunSendPacket", m_fnSendPacket))
	{
		LOG_ERROR("加载 WintunSendPacket 失败"); success = false;
	}

	if (!success) {
		DWORD errorCode = ::GetLastError();
		if (errorCode == ERROR_SUCCESS)
			errorCode = ERROR_PROC_NOT_FOUND;
		reset_api_pointers();
		::SetLastError(errorCode);
		return false;
	}
	LOG_INFO("全部Wintun API加载完成");
	return true;
}

bool WintunTun::open_or_create_adapter(const std::wstring& TunName, const std::wstring& tunnelType)
{
	if (m_fnOpenAdapter == nullptr || m_fnCreateAdapter == nullptr) {
		::SetLastError(ERROR_PROC_NOT_FOUND);
		LOG_ERROR("Open/CreateAdapter函数未加载");
		return false;
	}

	m_hAdapter = m_fnOpenAdapter(TunName.c_str());
	if (m_hAdapter != nullptr) {
		LOG_DEBUG("适配器 %ls 已存在，直接打开", TunName.c_str());
		return true;
	}
	DWORD openError = ::GetLastError();
	if (openError != ERROR_FILE_NOT_FOUND && openError != ERROR_NOT_FOUND)
	{
		LOG_ERROR("打开适配器失败，错误码:%lu", openError);
		::SetLastError(openError);
		return false;
	}
	m_hAdapter = m_fnCreateAdapter(TunName.c_str(), tunnelType.c_str(), nullptr);
	if (m_hAdapter == nullptr)
	{
		DWORD err = ::GetLastError();
		LOG_ERROR("创建适配器失败 err=%lu", err);
		return false;
	}
	LOG_DEBUG("创建新适配器 %ls 成功", TunName.c_str());
	return true;
}

bool WintunTun::fetch_adapter_luid()
{
	m_ifliud = {};
	if (m_hAdapter == nullptr || m_fnGetAdapterLuid == nullptr) {
		::SetLastError(ERROR_INVALID_HANDLE);
		LOG_ERROR("适配器句柄或API为空");
		return false;
	}

	m_fnGetAdapterLuid(m_hAdapter, &m_ifliud);
	if (m_fnGetAdapterLuid == nullptr)
	{
		DWORD err = ::GetLastError();
		LOG_ERROR("获取LUID接口调用失败 err=%lu", err);
		return false;
	}
	if (m_ifliud.Value == 0) {
		::SetLastError(ERROR_INVALID_DATA);
		LOG_ERROR("获取到无效LUID");
		return false;
	}
	LOG_DEBUG("适配器LUID获取成功");
	return true;
}

uint8_t* WintunTun::read_packet(tun_len_t* outPackLen)
{
	if (outPackLen) *outPackLen = 0;
	if (!is_ready() || m_fnReceivePacket == nullptr) {
		::SetLastError(ERROR_INVALID_HANDLE);
		LOG_ERROR("read_packet：实例未就绪或API未加载");
		return nullptr;
	}
	DWORD len = 0;
	BYTE* packet = m_fnReceivePacket(m_hsession, &len);
	if (packet != nullptr) {
		if (outPackLen) *outPackLen = static_cast<tun_len_t>(len);
		return reinterpret_cast<uint8_t*>(packet);
	}
	return nullptr;
}

tun_event_t WintunTun::read_wait_event() const
{
	if (!is_ready() || m_fnGetReadWaitEvent == nullptr) {
		return nullptr;
	}
	return m_fnGetReadWaitEvent(m_hsession);
}

bool WintunTun::write_packet(const uint8_t* RawIPdata, tun_len_t len)
{
	if (!is_ready()) {
		::SetLastError(ERROR_INVALID_HANDLE);
		LOG_ERROR("write_packet：实例未就绪");
		return false;
	}
	if (RawIPdata == nullptr || len == 0 || len > WINTUN_MAX_IP_PACKET_SIZE) {
		::SetLastError(ERROR_INVALID_PARAMETER);
		LOG_ERROR("write_packet：数据包长度非法 len=%u", static_cast<unsigned>(len));
		return false;
	}
	if (m_fnAllocateSendPacket == nullptr || m_fnSendPacket == nullptr) {
		::SetLastError(ERROR_PROC_NOT_FOUND);
		LOG_ERROR("write_packet：发包API未加载");
		return false;
	}

	BYTE* send_packet = m_fnAllocateSendPacket(m_hsession, len);
	if (send_packet == nullptr) {
		DWORD err = ::GetLastError();
		static std::atomic<uint64_t> s_ringDropTotal{ 0 };
		static std::atomic<uint64_t> s_ringDropLastLogTick{ 0 };
		const uint64_t total = s_ringDropTotal.fetch_add(1) + 1;
		const uint64_t nowTick = ::GetTickCount64();
		const uint64_t lastTick = s_ringDropLastLogTick.load();
		if (nowTick - lastTick >= 1000) {
			s_ringDropLastLogTick.store(nowTick);
			LOG_WARN("分配发送缓冲区失败 err=%lu（环形缓冲区满），累计丢弃 %llu 包",
				err, static_cast<unsigned long long>(total));
		}
		return false;
	}
	std::memcpy(send_packet, RawIPdata, len);
	m_fnSendPacket(m_hsession, send_packet);
	LOG_TRACE("发送IP数据包，长度：%u", static_cast<unsigned>(len));
	return true;
}

tun_id_t WintunTun::get_interface_id() const
{
	return m_ifliud;
}

void WintunTun::release_read_packet(const uint8_t* pkt)
{
	if (!is_ready() || pkt == nullptr || m_fnReleaseReceivePacket == nullptr) {
		LOG_ERROR("release_read_packet：状态异常");
		return;
	}
	m_fnReleaseReceivePacket(m_hsession, reinterpret_cast<const BYTE*>(pkt));
}

bool WintunTun::is_ready() const
{
	return m_bInited && m_hDll != nullptr && m_hAdapter != nullptr && m_hsession != nullptr;
}

void WintunTun::cleanup_resource()
{
	if (m_hsession != nullptr) {
		if (m_fnEndSession != nullptr) {
			m_fnEndSession(m_hsession);
		}
		m_hsession = nullptr;
	}
	if (m_hAdapter != nullptr) {
		if (m_fnCloseAdapter != nullptr) {
			m_fnCloseAdapter(m_hAdapter);
		}
		m_hAdapter = nullptr;
	}
	reset_api_pointers();
}

void WintunTun::reset_api_pointers() noexcept
{
	m_fnCreateAdapter = nullptr;
	m_fnOpenAdapter = nullptr;
	m_fnCloseAdapter = nullptr;
	m_fnGetAdapterLuid = nullptr;
	m_fnStartSession = nullptr;
	m_fnEndSession = nullptr;
	m_fnGetReadWaitEvent = nullptr;
	m_fnReceivePacket = nullptr;
	m_fnReleaseReceivePacket = nullptr;
	m_fnAllocateSendPacket = nullptr;
	m_fnSendPacket = nullptr;
}

#else

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/if.h>
#include <linux/if_tun.h>

namespace {
constexpr size_t kLinuxTunBuf = 2048;
}

LinuxTun::~LinuxTun()
{
	cleanup_resource();
}

bool LinuxTun::init_tun(const std::string& TunName, const std::string&)
{
	if (m_fd >= 0) {
		LOG_WARN("LinuxTun: 已经打开 %s", m_ifname.c_str());
		return false;
	}
	m_fd = ::open("/dev/net/tun", O_RDWR | O_NONBLOCK);
	if (m_fd < 0) {
		LOG_FATAL("LinuxTun: 打开 /dev/net/tun 失败: %s"
			"（需要 CAP_NET_ADMIN；容器内还需 --device /dev/net/tun）",
			std::strerror(errno));
		return false;
	}
	struct ifreq ifr{};
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	std::strncpy(ifr.ifr_name, TunName.c_str(), IFNAMSIZ - 1);
	if (::ioctl(m_fd, TUNSETIFF, &ifr) < 0) {
		LOG_FATAL("LinuxTun: TUNSETIFF(%s) 失败: %s（接口名是否已被占用？）",
			TunName.c_str(), std::strerror(errno));
		cleanup_resource();
		return false;
	}
	m_ifname.assign(ifr.ifr_name);
	m_buf.resize(kLinuxTunBuf);
	LOG_INFO("LinuxTun: 已创建 %s (fd=%d)", m_ifname.c_str(), m_fd);
	return true;
}

uint8_t* LinuxTun::read_packet(tun_len_t* outPackLen)
{
	if (outPackLen) *outPackLen = 0;
	if (m_fd < 0) return nullptr;
	const ssize_t n = ::read(m_fd, m_buf.data(), m_buf.size());
	if (n <= 0) {
		return nullptr;
	}
	m_recvCount.fetch_add(1, std::memory_order_relaxed);
	if (outPackLen) *outPackLen = static_cast<tun_len_t>(n);
	return m_buf.data();
}

void LinuxTun::release_read_packet(const uint8_t*)
{
}

bool LinuxTun::write_packet(const uint8_t* RawIPdata, tun_len_t len)
{
	if (m_fd < 0 || RawIPdata == nullptr || len == 0) {
		return false;
	}
	const ssize_t n = ::write(m_fd, RawIPdata, len);
	if (n != static_cast<ssize_t>(len)) {
		static std::atomic<uint64_t> s_drop{ 0 };
		const uint64_t total = s_drop.fetch_add(1) + 1;
		if (total <= 3 || total % 1000 == 0) {
			LOG_WARN("LinuxTun: write 返回 %zd（期望 %u），累计异常 %llu 次",
				n, static_cast<unsigned>(len), static_cast<unsigned long long>(total));
		}
		return false;
	}
	return true;
}

tun_id_t LinuxTun::get_interface_id() const
{
	return m_ifname;
}

bool LinuxTun::is_ready() const
{
	return m_fd >= 0;
}

uint64_t LinuxTun::receive_count() const
{
	return m_recvCount.load();
}

tun_event_t LinuxTun::read_wait_event() const
{
	return m_fd;
}

void LinuxTun::cleanup_resource()
{
	if (m_fd >= 0) {
		::close(m_fd);
		m_fd = -1;
	}
	m_ifname.clear();
}

#endif

// 虚拟网卡工厂：新增平台时在这里返回新的 ITunDevice 实现
std::unique_ptr<ITunDevice> create_tun_device()
{
#if defined(_WIN32)
	return std::make_unique<WintunTun>();
#else
	return std::make_unique<LinuxTun>();
#endif
}
