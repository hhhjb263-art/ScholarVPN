#if defined(_WIN32)

#include "route_manager.h"

namespace {
	bool parse(const cfgstr& text, IN_ADDR &out) {
		out = {};
		const INT result = ::InetPtonW(AF_INET,text.c_str(),&out);
		return result == 1;
	}
	bool make_ipv4_to_sockaddr(const cfgstr& ip, SOCKADDR_INET& out) {
		out = {};
		out.Ipv4.sin_family = AF_INET;
		out.Ipv4.sin_port = 0;
		return parse(ip,out.Ipv4.sin_addr);
	}
}

RouteManager::RouteManager(
	tun_id_t tunnelId
)
	: m_tunnelId(tunnelId)
{
}

RouteManager::~RouteManager()
{
	clear_routes();
}

bool RouteManager::add_ipv4_route(const Ipv4RouteParam& param)
{
	if (param.destination.empty() ||
		param.nexthop.empty() ||
		param.prefixLength > 32 ||
		param.interfaceId.Value == 0) {

		return false;
	}
	MIB_IPFORWARD_ROW2 row2{};
	InitializeIpForwardEntry(&row2);
	row2.InterfaceLuid = m_tunnelId;
	row2.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
	if (!parse(param.destination, row2.DestinationPrefix.Prefix.Ipv4.sin_addr)) {
		::SetLastError(ERROR_INVALID_PARAMETER);
		return false;
	}
	row2.DestinationPrefix.PrefixLength = param.prefixLength;
	row2.NextHop.Ipv4.sin_family = AF_INET;
	if (!parse(param.nexthop,row2.NextHop.Ipv4.sin_addr)) {
		::SetLastError(ERROR_INVALID_PARAMETER);
		return false;
	}
	row2.Metric = param.metric;
	return create_route(row2);
}

bool RouteManager::add_tunnel_route(const cfgstr& destination,
	uint8_t prefixLength,uint32_t metric)
{
	if (m_tunnelId.Value == 0) {
		::SetLastError(ERROR_INVALID_HANDLE);
		return false;
	}
	Ipv4RouteParam param;
	param.destination = destination;
	param.prefixLength = prefixLength;
	param.metric = metric;
	param.nexthop = CS("0.0.0.0");
	param.interfaceId = m_tunnelId;
	return add_ipv4_route(param);
}

bool RouteManager::add_default_route(uint32_t metric)
{
	return add_tunnel_route(CS("0.0.0.0"),0,metric);
}

bool RouteManager::add_ipv6_default_route(uint32_t metric)
{
	// 默认不参与连接流程：本地静默丢弃 v6 包会让 V6 优先应用卡到超时
	if (m_tunnelId.Value == 0) {
		::SetLastError(ERROR_INVALID_HANDLE);
		return false;
	}
	MIB_IPFORWARD_ROW2 row{};
	InitializeIpForwardEntry(&row);
	row.InterfaceLuid = m_tunnelId;
	row.DestinationPrefix.Prefix.si_family = AF_INET6;
	row.DestinationPrefix.PrefixLength = 0;
	row.NextHop.si_family = AF_INET6;
	row.Metric = metric;
	return create_route(row);
}

// 给服务器地址加一条走物理网关的 /32 排除路由，保证握手包不进隧道
bool RouteManager::add_server_bypass_route(const cfgstr& serverIp)
{
	SOCKADDR_INET destination{};
	if (!make_ipv4_to_sockaddr(serverIp, destination)) {
		::SetLastError(ERROR_INVALID_PARAMETER);
		return false;
	}
	MIB_IPFORWARD_ROW2 bestRoute{};
	SOCKADDR_INET bestSource{};
	NETIO_STATUS status = ::GetBestRoute2(nullptr,0,nullptr,&destination,0,&bestRoute,&bestSource);
	if (status != NO_ERROR)
	{
		::SetLastError(status);
		return false;
	}
	MIB_IPFORWARD_ROW2 bypass_row2{};
	InitializeIpForwardEntry(&bypass_row2);
	bypass_row2.InterfaceLuid = bestRoute.InterfaceLuid;
	bypass_row2.DestinationPrefix.Prefix = destination;
	bypass_row2.DestinationPrefix.PrefixLength = 32;
	bypass_row2.NextHop = bestRoute.NextHop;
	bypass_row2.Metric = 0;
	return create_route(bypass_row2);
}

void RouteManager::remove_default_route() noexcept
{
	for (auto it = m_createdRoutes.rbegin(); it != m_createdRoutes.rend(); ++it)
	{
		if (it->DestinationPrefix.PrefixLength == 0 &&
			it->DestinationPrefix.Prefix.si_family == AF_INET &&
			it->DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr == 0)
		{
			::DeleteIpForwardEntry2(&(*it));
			m_createdRoutes.erase(std::next(it).base());
			return;
		}
	}
}

void RouteManager::clear_routes() noexcept
{
	remove_split_routes();
	for (auto it = m_createdRoutes.rbegin(); it != m_createdRoutes.rend(); it++) {
		::DeleteIpForwardEntry2(&(*it));
	}
	m_createdRoutes.clear();
}

bool RouteManager::create_route(const MIB_IPFORWARD_ROW2& route)
{
	NETIO_STATUS status = CreateIpForwardEntry2(&route);
	if (status == NO_ERROR) {
		m_createdRoutes.push_back(route);
		return true;
	}
	if (status == ERROR_OBJECT_ALREADY_EXISTS) {
		return true;
	}
	::SetLastError(status);
	return false;
}

int RouteManager::add_bypass_routes(const std::vector<cidr::Cidr>& cidrs, const cfgstr& probeIp)
{
	// 分流前缀比隧道的 0.0.0.0/1 更长，最长前缀匹配下优先命中，走物理网关
	if (cidrs.empty()) {
		return 0;
	}
	SOCKADDR_INET probe{};
	if (!make_ipv4_to_sockaddr(probeIp, probe)) {
		LOG_ERROR("add_bypass_routes: 探测地址非法");
		return 0;
	}

	MIB_IPFORWARD_ROW2 best{};
	SOCKADDR_INET bestSource{};
	const NETIO_STATUS gst = ::GetBestRoute2(nullptr, 0, nullptr, &probe, 0, &best, &bestSource);
	if (gst != NO_ERROR) {
		LOG_ERROR("add_bypass_routes: GetBestRoute2(%s) 失败 err=%lu",
			cfg_to_utf8(probeIp).c_str(), gst);
		return 0;
	}

	int ok = 0;
	m_splitRoutes.reserve(m_splitRoutes.size() + cidrs.size());
	for (const auto& c : cidrs) {
		const uint64_t key = (static_cast<uint64_t>(c.addr) << 8) | c.prefix;
		if (!m_splitKeys.insert(key).second) {
			continue;
		}
		MIB_IPFORWARD_ROW2 row{};
		InitializeIpForwardEntry(&row);
		row.InterfaceLuid = best.InterfaceLuid;
		row.DestinationPrefix.Prefix.si_family = AF_INET;
		row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr = ::htonl(c.addr);
		row.DestinationPrefix.PrefixLength = c.prefix;
		row.NextHop = best.NextHop;
		row.Metric = 1;

		const NETIO_STATUS st = ::CreateIpForwardEntry2(&row);
		if (st == NO_ERROR || st == ERROR_OBJECT_ALREADY_EXISTS) {
			m_splitRoutes.push_back(row);
			++ok;
		}
		else {
			m_splitKeys.erase(key);
		}
	}
	LOG_INFO("分流路由: 注入 %d / %zu 条（出口 LUID=%llu）",
		ok, cidrs.size(), static_cast<unsigned long long>(best.InterfaceLuid.Value));
	return ok;
}

// 只撤分流路由，保留默认路由与服务器排除路由（split→full 切换时用）
void RouteManager::remove_split_routes() noexcept
{
	for (auto it = m_splitRoutes.rbegin(); it != m_splitRoutes.rend(); ++it) {
		::DeleteIpForwardEntry2(&(*it));
	}
	m_splitRoutes.clear();
	m_splitKeys.clear();
}

std::size_t RouteManager::split_route_count() const noexcept
{
	return m_splitRoutes.size();
}

// 读回系统路由表统计真正生效的分流条目：接口返回成功不等于写进去了
int RouteManager::count_active_split_routes() const
{
	if (m_splitKeys.empty()) {
		return 0;
	}
	PMIB_IPFORWARD_TABLE2 table = nullptr;
	const NETIO_STATUS st = ::GetIpForwardTable2(AF_INET, &table);
	if (st != NO_ERROR || table == nullptr) {
		return -1;
	}
	int found = 0;
	for (ULONG i = 0; i < table->NumEntries; ++i) {
		const MIB_IPFORWARD_ROW2& r = table->Table[i];
		if (r.DestinationPrefix.Prefix.si_family != AF_INET) {
			continue;
		}
		const uint32_t addr = ::ntohl(r.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr);
		const uint64_t key = (static_cast<uint64_t>(addr) << 8)
			| static_cast<uint8_t>(r.DestinationPrefix.PrefixLength);
		if (m_splitKeys.count(key) != 0) {
			++found;
		}
	}
	::FreeMibTable(table);
	return found;
}

#else

#include "route_manager.h"
#include "platform/exec.h"

#include <arpa/inet.h>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>
#include <linux/if.h>

namespace {

bool valid_ipv4(const std::string& ip)
{
    struct in_addr a{};
    return ::inet_pton(AF_INET, ip.c_str(), &a) == 1;
}

bool safe_ifname(const std::string& name)
{
    if (name.empty() || name.size() >= IFNAMSIZ)
    {
        return false;
    }
    for (char c : name)
    {
        const unsigned char u = static_cast<unsigned char>(c);
        if (!(std::isalnum(u) || c == '.' || c == '_' || c == '-'))
        {
            return false;
        }
    }
    return true;
}

struct BestRoute {
    std::string dev;
    std::string via;
};

BestRoute best_route_for(const std::string& ip)
{
    BestRoute r;
    std::string out;
    if (run_cmd("ip route get " + ip, &out) != 0 || out.empty())
    {
        return r;
    }
    const std::size_t nl = out.find('\n');
    const std::string line = (nl == std::string::npos) ? out : out.substr(0, nl);

    auto token_after = [&line](const char* key) -> std::string {
        const std::string k = std::string(" ") + key + " ";
        const std::size_t p = line.find(k);
        if (p == std::string::npos)
        {
            return {};
        }
        const std::size_t b = p + k.size();
        const std::size_t e = line.find(' ', b);
        return line.substr(b, e == std::string::npos ? std::string::npos : e - b);
    };
    r.dev = token_after("dev");
    r.via = token_after("via");
    return r;
}

bool add_route_tracked(const std::string& route_spec, std::vector<std::string>& added)
{
    const std::string add = "ip route add " + route_spec;
    if (run_cmd(add) == 0)
    {
        added.push_back("ip route del " + route_spec);
        return true;
    }
    std::string cur;
    run_cmd("ip route show " + route_spec, &cur);
    if (!cur.empty())
    {
        return true;
    }
    LOG_ERROR("路由添加失败: %s", add.c_str());
    return false;
}

}

RouteManager::RouteManager(tun_id_t tunnelId)
    : m_tunnelId(std::move(tunnelId))
{
}

RouteManager::~RouteManager()
{
    clear_routes();
}

bool RouteManager::add_ipv4_route(const Ipv4RouteParam& param)
{
    const std::string dest = cfg_to_utf8(param.destination);
    const std::string next = cfg_to_utf8(param.nexthop);
    if (!valid_ipv4(dest) || (!next.empty() && !valid_ipv4(next)) || !safe_ifname(m_tunnelId))
    {
        return false;
    }
    std::string spec = dest + "/" + std::to_string(static_cast<unsigned>(param.prefixLength));
    if (!next.empty())
    {
        spec += " via " + next;
    }
    spec += " dev " + m_tunnelId;
    if (param.metric != 0)
    {
        spec += " metric " + std::to_string(param.metric);
    }
    return add_route_tracked(spec, m_addedRoutes);
}

bool RouteManager::add_tunnel_route(const cfgstr& destination, uint8_t prefixLength, uint32_t metric)
{
    Ipv4RouteParam param;
    param.destination = destination;
    param.prefixLength = prefixLength;
    param.metric = metric;
    param.interfaceId = m_tunnelId;
    return add_ipv4_route(param);
}

bool RouteManager::add_default_route(uint32_t metric)
{
    if (!safe_ifname(m_tunnelId))
    {
        LOG_ERROR("add_default_route: 非法接口名");
        return false;
    }
    const std::string m = std::to_string(metric);
    bool ok = true;
    for (const char* prefix : { "0.0.0.0/1", "128.0.0.0/1" })
    {
        std::string spec = std::string(prefix) + " dev " + m_tunnelId;
        if (metric != 0)
        {
            spec += " metric " + m;
        }
        if (add_route_tracked(spec, m_addedRoutes))
        {
            LOG_INFO("默认路由: %s", spec.c_str());
        }
        else
        {
            ok = false;
        }
    }
    return ok;
}

bool RouteManager::add_ipv6_default_route(uint32_t)
{
    LOG_WARN("add_ipv6_default_route: Linux 端未启用（与 Windows 行为一致，避免 IPv6 黑洞）");
    return false;
}

// 同 Windows：服务器地址的排除路由必须先于默认路由存在
bool RouteManager::add_server_bypass_route(const cfgstr& serverIp)
{
    const std::string ip = cfg_to_utf8(serverIp);
    if (!valid_ipv4(ip))
    {
        LOG_ERROR("add_server_bypass_route: 非法服务器 IP %s", ip.c_str());
        return false;
    }
    const BestRoute br = best_route_for(ip);
    if (br.dev.empty() || !safe_ifname(br.dev))
    {
        LOG_ERROR("add_server_bypass_route: 查不到到 %s 的物理路由（服务器地址不可达？）", ip.c_str());
        return false;
    }
    std::string spec = ip + "/32";
    if (!br.via.empty())
    {
        spec += " via " + br.via;
    }
    spec += " dev " + br.dev;
    if (!add_route_tracked(spec, m_addedRoutes))
    {
        return false;
    }
	LOG_INFO("bypass 路由: %s（保证握手走物理网卡 %s）", spec.c_str(), br.dev.c_str());
	return true;
}

int RouteManager::add_bypass_routes(const std::vector<cidr::Cidr>& cidrs, const cfgstr& probeIp)
{
	if (cidrs.empty()) {
		return 0;
	}
	const BestRoute br = best_route_for(cfg_to_utf8(probeIp));
	if (br.dev.empty() || !safe_ifname(br.dev)) {
		LOG_ERROR("add_bypass_routes: 查不到到 %s 的物理出口", cfg_to_utf8(probeIp).c_str());
		return 0;
	}

	const std::string batchPath = "/tmp/scholarvpn-routes-add.batch";
	FILE* f = std::fopen(batchPath.c_str(), "w");
	if (f == nullptr) {
		LOG_ERROR("add_bypass_routes: 无法创建 batch 文件 %s", batchPath.c_str());
		return 0;
	}
	std::vector<cidr::Cidr> fresh;
	fresh.reserve(cidrs.size());
	for (const auto& c : cidrs) {
		const uint64_t key = (static_cast<uint64_t>(c.addr) << 8) | c.prefix;
		if (!m_splitKeys.insert(key).second) {
			continue;
		}
		fresh.push_back(c);
		std::fprintf(f, "route replace %s", cidr::to_string(c).c_str());
		if (!br.via.empty()) {
			std::fprintf(f, " via %s", br.via.c_str());
		}
		std::fprintf(f, " dev %s metric 1\n", br.dev.c_str());
	}
	std::fclose(f);

	const int rc = run_cmd("ip -batch " + batchPath);
	std::remove(batchPath.c_str());
	if (rc != 0) {
		LOG_ERROR("add_bypass_routes: ip -batch 失败 rc=%d", rc);
		for (const auto& c : fresh) {
			m_splitKeys.erase((static_cast<uint64_t>(c.addr) << 8) | c.prefix);
		}
		return 0;
	}

	m_splitRoutes.reserve(m_splitRoutes.size() + fresh.size());
	for (const auto& c : fresh) {
		std::string del = "route del " + cidr::to_string(c);
		if (!br.via.empty()) {
			del += " via " + br.via;
		}
		del += " dev " + br.dev;
		m_splitRoutes.push_back(std::move(del));
	}
	LOG_INFO("分流路由: 注入 %zu 条（出口 %s%s%s）",
		fresh.size(), br.dev.c_str(),
		br.via.empty() ? "" : " via ", br.via.c_str());
	return static_cast<int>(fresh.size());
}

// 只撤分流路由，保留默认路由与服务器排除路由
void RouteManager::remove_split_routes() noexcept
{
	if (m_splitRoutes.empty()) {
		return;
	}
	const std::string batchPath = "/tmp/scholarvpn-routes-del.batch";
	FILE* f = std::fopen(batchPath.c_str(), "w");
	if (f != nullptr) {
		for (const auto& line : m_splitRoutes) {
			std::fprintf(f, "%s\n", line.c_str());
		}
		std::fclose(f);
		run_cmd("ip -batch " + batchPath);
		std::remove(batchPath.c_str());
	}
	m_splitRoutes.clear();
	m_splitKeys.clear();
}

std::size_t RouteManager::split_route_count() const noexcept
{
	return m_splitRoutes.size();
}

// 解析 ip route 输出，核对分流条目是否真的落表
int RouteManager::count_active_split_routes() const
{
	if (m_splitKeys.empty()) {
		return 0;
	}
	const std::vector<std::string> lines = run_cmd_lines("ip -4 route show table main");
	int found = 0;
	for (const auto& line : lines) {
		const std::size_t sp = line.find(' ');
		const std::string tok = (sp == std::string::npos) ? line : line.substr(0, sp);
		cidr::Cidr c{};
		if (!cidr::parse(tok, c)) {
			continue;
		}
		const uint64_t key = (static_cast<uint64_t>(c.addr) << 8) | c.prefix;
		if (m_splitKeys.count(key) != 0) {
			++found;
		}
	}
	return found;
}

void RouteManager::remove_default_route() noexcept
{
    for (auto it = m_addedRoutes.begin(); it != m_addedRoutes.end();)
    {
        const bool is_split_default =
            it->find("0.0.0.0/1 ") != std::string::npos ||
            it->find("128.0.0.0/1 ") != std::string::npos;
        if (!is_split_default)
        {
            ++it;
            continue;
        }
        run_cmd(*it);
        it = m_addedRoutes.erase(it);
    }
}

void RouteManager::clear_routes() noexcept
{
    remove_split_routes();
    for (auto it = m_addedRoutes.rbegin(); it != m_addedRoutes.rend(); ++it)
    {
        run_cmd(*it);
    }
    m_addedRoutes.clear();
}

#endif
