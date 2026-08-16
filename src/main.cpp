#include <iostream>
#include <cstdio>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <cstdint>
#include <exception>
#include <fstream>
#include <iterator>
#include <vector>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <wincrypt.h>

#include "UDP.h"
#include "tun.h"
#include "AdapterConfig.h"
#include "route_manager.h"
#include "reconnect_manager.h"
#include "Crypt.h"
#include "Config.h"
#include "logger.h"
#include <memory>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Crypt32.lib")


static std::wstring to_wstring(const std::string& str)
{
    return std::wstring(str.begin(), str.end());
}

static std::string narrow(const std::wstring& str)
{
    if (str.empty())
    {
        return std::string();
    }
    const int len = ::WideCharToMultiByte(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<size_t>(len), 0);
    ::WideCharToMultiByte(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), &out[0], len, nullptr, nullptr);
    return out;
}

namespace
{
    std::atomic<bool> g_running{ true };
    std::once_flag g_shutdownFlag;
    RouteManager* g_route = nullptr;
    ReconnectManager* g_mgr = nullptr;
#ifndef _DEBUG
    std::atomic<unsigned long long> g_tx_pkts{ 0 };   // 客户端 -> 服务器（TUN 读入）
    std::atomic<unsigned long long> g_tx_bytes{ 0 };
    std::atomic<unsigned long long> g_rx_pkts{ 0 };   // 服务器 -> 客户端（写入 TUN）
    std::atomic<unsigned long long> g_rx_bytes{ 0 };
#endif

    // 将字节数格式化为带单位的可读字符串（自动 B/KB/MB/GB/TB）
    std::string format_bytes(unsigned long long bytes)
    {
        static const char* units[] = { "B", "KB", "MB", "GB", "TB", "PB" };
        double value = static_cast<double>(bytes);
        int unit = 0;
        while (value >= 1024.0 && unit < 5)
        {
            value /= 1024.0;
            ++unit;
        }
        char buf[64]{};
        if (unit == 0)
        {
            std::snprintf(buf, sizeof(buf), "%llu B", bytes);
        }
        else
        {
            std::snprintf(buf, sizeof(buf), "%.2f %s", value, units[unit]);
        }
        return buf;
    }

    // Request shutdown: triggered by Ctrl+C or other events
    void request_shutdown()
    {
        std::call_once(g_shutdownFlag, []()
            {
                LOG_KEY("Shutting down, cleaning up...");
                g_running.store(false);
                if (g_mgr)
                {
                    g_mgr->stop();
                }
                if (g_route)
                {
                    g_route->clear_routes();
                }
            });
    }

    // Ctrl+C / Ctrl+Break / Close / Shutdown events: request shutdown
    BOOL WINAPI console_ctrl_handler(DWORD ctrlType)
    {
        if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT ||
            ctrlType == CTRL_CLOSE_EVENT || ctrlType == CTRL_SHUTDOWN_EVENT)
        {
            request_shutdown();
            ::ExitProcess(0);
        }
        return TRUE;
    }

    bool parse_port(const std::string& text, uint16_t& out)
    {
        try
        {
            const int v = std::stoi(text);
            if (v < 1 || v > 65535)
            {
                return false;
            }
            out = static_cast<uint16_t>(v);
            return true;
        }
        catch (const std::exception&)
        {
            return false;
        }
    }

    bool is_valid_ipv4(const std::string& ip)
    {
        IN_ADDR addr{};
        std::wstring w = to_wstring(ip);
        return ::InetPtonW(AF_INET, w.c_str(), &addr) == 1;
    }

    void print_usage(const char* exe)
    {
        std::cerr << "Usage: " << exe << " [serverIP] [port]\n"
                  << "  Settings are read from config.ini; the optional arguments override them\n"
                  << "  Example: " << exe << " 38.76.211.127 51820\n"
                  << "  Enter 'r' to force a reconnect for testing, or press Enter to exit\n";
    }
}

// Resolve key files relative to the exe directory (admin runs may change cwd).
static std::string get_exe_dir()
{
    wchar_t buffer[MAX_PATH]{};
    const DWORD n = ::GetModuleFileNameW(nullptr, buffer, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
    {
        return "";
    }
    const std::wstring path(buffer, n);
    const std::size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos)
    {
        return "";
    }
    std::string result;
    result.reserve(slash + 1);
    for (std::size_t i = 0; i <= slash; ++i)
    {
        result.push_back(static_cast<char>(path[i]));
    }
    return result;
}

// Look for the key file in the AppData keys directory first, then next to the exe.
static std::string find_key_file(const std::string& appdata_keys_dir, const std::string& exe_dir, const std::string& filename)
{
    const std::string candidates[] = {
        appdata_keys_dir + filename,
        exe_dir + filename,
        exe_dir + "keys\\" + filename
    };
    for (const auto& candidate : candidates)
    {
        if (std::ifstream probe{candidate, std::ios::binary})
        {
            return candidate;
        }
    }
    return appdata_keys_dir + filename;
}

// DPAPI：客户端身份私钥本地加密存储
// 用当前 Windows 用户的 DPAPI 密钥加密/解密 SIG_CLI_PRI（磁盘不落明文 PEM）。

static bool dpapi_protect(const std::vector<uint8_t>& plain, std::vector<uint8_t>& out)
{
    DATA_BLOB in{ static_cast<DWORD>(plain.size()), const_cast<BYTE*>(plain.data()) };
    DATA_BLOB enc{};
    if (!::CryptProtectData(&in, L"ScholarVPN Client Identity", nullptr, nullptr, nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN, &enc))
    {
        return false;
    }
    out.assign(enc.pbData, enc.pbData + enc.cbData);
    ::LocalFree(enc.pbData);
    return true;
}

static bool dpapi_unprotect(const std::vector<uint8_t>& enc, std::vector<uint8_t>& plain)
{
    DATA_BLOB in{ static_cast<DWORD>(enc.size()),
                  const_cast<BYTE*>(const_cast<uint8_t*>(enc.data())) };
    DATA_BLOB dec{};
    if (!::CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr,
                              CRYPTPROTECT_UI_FORBIDDEN, &dec))
    {
        return false;
    }
    plain.assign(dec.pbData, dec.pbData + dec.cbData);
    ::LocalFree(dec.pbData);
    return true;
}

// 服务器身份公钥 SIG_SRV_PUB（硬编码编译进客户端）
// 把服务器首次运行生成的 keys/server_sig.pub 内容（含 BEGIN/END 行）粘贴到这里，
// 客户端将用它验证服务器签名（防中间人）。留空时回退读取 keys\server.pub 文件（开发调试用）。
// 按构建配置区分：Debug 构建用本地测试服务器的公钥；Release 构建用正式服务器的公钥。
#ifdef _DEBUG
static const std::string kServerSigPubPem = R"(-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA+A73aBlJFR3H7ozQ0os5SduqQIga6zIpfI5VSFlGE0A=
-----END PUBLIC KEY-----
)";
#else
static const std::string kServerSigPubPem = R"(-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAPGjH684MS+FZNgngx2mK/I06A6a88Up5Gkr1jU4fFM8=
-----END PUBLIC KEY-----
)";
#endif

int main(int argc, char** argv)
{
    // 客户端启动流程（对照看更易理解）：
    //   1) 设置控制台 UTF-8 + 初始化日志
    //   2) 读取 %APPDATA%\ScholarVPN\config.ini（首次运行自动生成）
    //   3) 生成/加载 Ed25519 身份密钥（SIG_CLI_PRI 经 DPAPI 加密存储）
    //   4) 确定服务器地址与端口（Debug 优先 DebugServerIP，Release 用 ServerIP）
    //   5) 创建 Wintun 网卡 → 配 IP/MTU/DNS/路由
    //   6) 启动 ReconnectManager（UDP 隧道 + 三阶段认证 + 断线重连）
    //   7) 两个桥接线程：TUN→UDP（上行）、UDP→TUN（下行）
    //   8) 认证通过后若服务端通告了虚拟 IP（多用户），自动覆盖网卡 IP
    ::SetConsoleOutputCP(CP_UTF8);
    ::SetConsoleCP(CP_UTF8);

    Logger::Init();

    // Load client settings from the INI file; the first run creates it with defaults.
    const std::wstring configDir = Config::GetAppDataRoaming() + L"\\ScholarVPN";
    const std::wstring configPath = configDir + L"\\config.ini";
    ClientConfig cfg;
    Config config(configPath, configDir);

    // Keys live in %APPDATA%\ScholarVPN\keys; create it on first run.
    Config::CreateDir(configDir);
    const std::wstring keysDirW = configDir + L"\\keys";
    Config::CreateDir(keysDirW);
    const std::string keysDir = narrow(keysDirW) + "\\";

    // ---- Ed25519 身份密钥（SIG_CLI_PRI 本地加密存储 / SIG_CLI_PUB）----
    // 私钥经 Windows DPAPI（当前用户）加密后存为 client.id.enc，磁盘不落明文；
    // 公钥明文存为 client.id.pub，提交给服务器管理员完成注册。
    const std::wstring idPubPathW = keysDirW + L"\\client.id.pub";
    const std::wstring idEncPathW = keysDirW + L"\\client.id.enc";
    if (!Config::FileExists(idPubPathW))
    {
        try
        {
            const std::string tmpPriv = keysDir + "client.id.priv.tmp";
            std::string pubPem;
            if (!generate_ed25519_keypair(tmpPriv, narrow(idPubPathW), pubPem))
            {
                LOG_ERR("Failed to generate Ed25519 identity key pair");
                return 1;
            }
            std::ifstream in(tmpPriv, std::ios::binary);
            std::vector<uint8_t> privPem(
                (std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            in.close();
            ::DeleteFileW(std::wstring(tmpPriv.begin(), tmpPriv.end()).c_str());
            std::vector<uint8_t> blob;
            if (!dpapi_protect(privPem, blob) ||
                !Config::WriteTextFile(idEncPathW, std::string(blob.begin(), blob.end())))
            {
                LOG_ERR("Failed to encrypt identity private key (DPAPI)");
                return 1;
            }
            LOG_KEY("[Identity] New Ed25519 identity key pair generated\n"
        "--- client.id.pub (register this public key with the server admin) ---\n"
        "%s"
        "------------------------------------------------------------------",
        pubPem.c_str());
        }
        catch (const std::exception& e)
        {
            LOG_ERR("Failed to generate Ed25519 identity key pair: %s", e.what());
            return 1;
        }
    }
    std::shared_ptr<EVP_PKEY> ed_priv;
    try
    {
        const std::string encData = Config::ReadTextFile(idEncPathW);
        std::vector<uint8_t> blob(encData.begin(), encData.end());
        std::vector<uint8_t> privPem;
        if (!dpapi_unprotect(blob, privPem))
        {
            LOG_ERR("Failed to decrypt identity private key (DPAPI). "
                    "client.id.enc is bound to this Windows user account.");
            return 1;
        }
        ed_priv.reset(
            load_ed25519_private_key_pem(std::string(privPem.begin(), privPem.end())),
            EVP_PKEY_free);
        LOG_KEY("[Identity] SIG_CLI_PUB loaded");
    }
    catch (const std::exception& e)
    {
        LOG_ERR("Error loading identity keys: %s", e.what());
        return 1;
    }

    // ---- 服务器身份公钥 SIG_SRV_PUB：优先用硬编码常量（kServerSigPubPem，按 Debug/Release 区分），
    //      否则回退读取 keys\server.pub（开发调试用）----
    std::string server_sig_pub_pem = kServerSigPubPem;
    if (server_sig_pub_pem.find("-----BEGIN PUBLIC KEY-----") == std::string::npos)
    {
        const std::string exe_dir = get_exe_dir();
        const std::string pub_path = find_key_file(keysDir, exe_dir, "server.pub");
        std::ifstream in(pub_path, std::ios::binary);
        if (!in)
        {
            LOG_ERR("No server identity public key: neither kServerSigPubPem in source "
                    "nor %s exists. Embed the server's server_sig.pub into the client.",
                    pub_path.c_str());
            return 1;
        }
        server_sig_pub_pem.assign(
            std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
        LOG_KEY("[Identity] No hardcoded SIG_SRV_PUB, falling back to %s "
                "(consider embedding it into kServerSigPubPem)", pub_path.c_str());
    }

#ifndef _DEBUG
    if (!Config::FileExists(configPath))
    {
        if (!config.SaveClientConfig(cfg))
        {
            LOG_ERR("Failed to create config.ini at %s", narrow(configPath).c_str());
            return 1;
        }
        LOG_KEY("First run: config.ini created at %s\n"
        "Client keys are stored at %s\n"
        "Please fill in ServerIP in config.ini, put server.pub (from the server admin) into %s, then run the client again.",
        narrow(configPath).c_str(), keysDir.c_str(), keysDir.c_str());
        return 0;
    }
#endif
    // 所有构建都读取 config.ini（Debug 构建存在 ini 时同样生效，
    // 这样 ClientID / RegisterToken 在本地联调时也能配置）
    if (Config::FileExists(configPath))
    {
        if (!config.LoadClientConfig(cfg))
        {
            LOG_ERR("Failed to read config.ini: %s", narrow(configPath).c_str());
            return 1;
        }
        LOG_KEY("[Config] config.ini loaded: ClientID=%ls, RegisterToken=%s, DebugServerIP=%ls",
                cfg.ClientID.c_str(),
                cfg.RegisterToken.empty() ? "(empty -> login mode)" : "(set -> register mode)",
                cfg.DebugServerIP.c_str());
    }
    else
    {
        LOG_KEY("[Config] config.ini not found (%s), using defaults", narrow(configPath).c_str());
    }

#ifndef _DEBUG
    std::string remote = narrow(cfg.ServerIP);
    if (!is_valid_ipv4(remote))
    {
        LOG_ERR("Invalid ServerIP in config.ini: %s", remote.c_str());
        return 1;
    }
    if (cfg.ServerPort < 1 || cfg.ServerPort > 65535)
    {
        LOG_ERR("Invalid ServerPort in config.ini: %d", static_cast<int>(cfg.ServerPort));
        return 1;
    }
    uint16_t port = static_cast<uint16_t>(cfg.ServerPort);
#else
    // Debug 构建路径：优先用新增的 DebugServerIP 键（本地测试服务器），
    // 其次用 ServerIP，最后才落到默认 192.168.1.12；Release 构建完全不用 DebugServerIP。
    std::string remote = "192.168.1.12";
    uint16_t port = 51820;
    if (Config::FileExists(configPath))
    {
        if (cfg.ServerPort >= 1 && cfg.ServerPort <= 65535)
            port = static_cast<uint16_t>(cfg.ServerPort);
        const std::string d = narrow(cfg.DebugServerIP);
        if (is_valid_ipv4(d))
            remote = d;
        else
        {
            const std::string r = narrow(cfg.ServerIP);
            if (is_valid_ipv4(r))
                remote = r;
        }
    }
#endif
    if (argc > 1)
    {
        remote = argv[1];
        if (!is_valid_ipv4(remote))
        {
            LOG_ERR("Invalid IP: %s", remote.c_str());
            print_usage(argv[0]);
            return 1;
        }
    }
    if (argc > 2 && !parse_port(argv[2], port))
    {
        LOG_ERR("Invalid port: %s (must be 1-65535)", argv[2]);
        print_usage(argv[0]);
        return 1;
    }

    LOG_KEY("VPN starting, connecting to %s:%d", remote.c_str(), static_cast<int>(port));

    ::SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

    try
    {
        WintunTun tun;
        if (!tun.init_tun("MyTunAdapter", "MyTunnel"))
        {
            LOG_ERR("Wintun initialization failed (is wintun.dll present next to the executable?)");
            return 1;
        }

        NET_LUID luid = tun.get_interface_luid();
        AdapterConfig adapter(luid);
        if (!adapter.set_IPv4_address(cfg.VirtualIP, static_cast<uint8_t>(cfg.VirtualPrefix)))
        {
            LOG_ERR("Failed to set TUN IP address");
            return 1;
        }
        if (!adapter.set_MTU(cfg.MTU))
        {
            LOG_ERR("[Warn] Failed to set MTU");
        }
        if (!adapter.set_metric(cfg.Metric))
        {
            LOG_ERR("[Warn] Failed to set adapter metric");
        }
        if (!adapter.set_DNS_IPv4(cfg.DNS))
        {
            LOG_ERR("[Warn] Failed to set DNS, continuing without custom DNS");
        }

        RouteManager route(luid);
        g_route = &route;
        if (!route.add_server_bypass_route(to_wstring(remote)))
        {
            LOG_ERR("Failed to add server bypass route");
            return 1;
        }
        if (!route.add_default_route(cfg.Metric))
        {
            LOG_ERR("Failed to add default route");
            return 1;
        }

        ReconnectManager mgr(remote, port, 256);
        mgr.set_identity(ed_priv, server_sig_pub_pem, narrow(cfg.ClientID), narrow(cfg.RegisterToken));
        g_mgr = &mgr;
        mgr.set_state_callback([](ConnState s)
            {
                LOG_KEY("[Reconnect] state -> %s", ReconnectManager::state_name(s));
            });
        mgr.set_connected_callback([&]()
            {
                route.add_server_bypass_route(to_wstring(remote));
                route.add_default_route(cfg.Metric);
                LOG_KEY("[Reconnect] Connected, routes added");
                // 多用户服务端：采用 identity_ok 通告的虚拟 IP 配置网卡（覆盖 config.ini 的 VirtualIP）
                auto cur = mgr.udp();
                if (cur && cur->assigned_ip() != 0)
                {
                    const uint32_t ip = cur->assigned_ip();
                    char ipstr[16] = { 0 };
                    std::snprintf(ipstr, sizeof(ipstr), "%u.%u.%u.%u",
                                  (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                                  (ip >> 8) & 0xFF, ip & 0xFF);
                    const std::wstring wip = to_wstring(std::string(ipstr));
                    const uint8_t prefix = cur->assigned_prefix();
                    if (wip != cfg.VirtualIP)
                    {
                        adapter.remove_IPv4_address(cfg.VirtualIP, static_cast<uint8_t>(cfg.VirtualPrefix));
                        if (adapter.set_IPv4_address(wip, prefix))
                        {
                            cfg.VirtualIP = wip;
                            cfg.VirtualPrefix = prefix;
                            LOG_KEY("[TUN] 已采用服务端分配的虚拟 IP: %s/%u", ipstr, static_cast<unsigned>(prefix));
                        }
                        else
                        {
                            LOG_ERR("[TUN] 设置服务端分配的 IP 失败: %s/%u", ipstr, static_cast<unsigned>(prefix));
                        }
                    }
                }
                // 注册模式连上 = 注册成功：自动清空 config.ini 的 RegisterToken，下次自动走登录
                if (!cfg.RegisterToken.empty())
                {
                    cfg.RegisterToken.clear();
                    mgr.clear_register_token();
                    if (config.SaveClientConfig(cfg))
                    {
                        LOG_KEY("[Config] 注册成功，已自动清空 RegisterToken，下次连接自动为登录模式");
                    }
                }
            });
        // 注册令牌无效/已使用被拒：自动清空 config.ini 的 RegisterToken，切换登录模式重试
        mgr.set_register_token_rejected_callback([&]()
            {
                cfg.RegisterToken.clear();
                if (config.SaveClientConfig(cfg))
                {
                    LOG_KEY("[Config] 注册令牌无效或已使用，已自动清空 RegisterToken，将以登录模式重试");
                }
            });
        if (!mgr.start())
        {
            LOG_ERR("Failed to start reconnect manager");
            return 1;
        }

        /*  TUN <-> UDP  */
        std::thread tun_to_udp([&]()
            {
                while (g_running.load())
                {
                    auto u = mgr.udp();
                    if (!u || !u->is_handshaked())
                    {
                        std::this_thread::sleep_for(std::chrono::milliseconds(10));
                        continue;
                    }
                    DWORD len = 0;
                    uint8_t* pkt = tun.read_packet(&len);
                    if (pkt && len > 0)
                    {
                        LOG_DBG("Wintun RX " << len << " bytes\n");
#ifndef _DEBUG
                        g_tx_pkts.fetch_add(1);
                        g_tx_bytes.fetch_add(len);
#endif
                        packet_buffer buf(pkt, len);
                        tun.release_read_packet(pkt);
                        u->send_ip_packet(std::move(buf));
                    }
                    else
                    {
                        std::this_thread::sleep_for(std::chrono::milliseconds(5));
                    }
                }
            });

        std::thread udp_to_tun([&]()
            {
                while (g_running.load())
                {
                    auto u = mgr.udp();
                    if (!u)
                    {
                        std::this_thread::sleep_for(std::chrono::milliseconds(10));
                        continue;
                    }
                    packet_buffer buf;
                    if (!u->recv_ip_packet(buf))
                    {
                        continue; 
                    }
                    if (!buf.is_empty())
                    {
                        LOG_DBG("UDP -> TUN " << buf.data_size() << " bytes\n");
#ifndef _DEBUG
                        g_rx_pkts.fetch_add(1);
                        g_rx_bytes.fetch_add(buf.data_size());
#endif
                        tun.write_packet(buf.get_data(), static_cast<DWORD>(buf.data_size()));
                    }
                }
            });

        #ifndef _DEBUG
        LOG_KEY("VPN started, Config: %s, TUN IP: %s/%d, Server: %s:%d",
                narrow(configPath).c_str(), narrow(cfg.VirtualIP).c_str(),
                static_cast<int>(cfg.VirtualPrefix), remote.c_str(), static_cast<int>(port));
#else
        std::cout << "VPN started\n"
                  << "Debug build: using local test server 192.168.1.12 (config.ini not required)\n"
                  << "TUN IP: " << narrow(cfg.VirtualIP) << "/" << cfg.VirtualPrefix << "\n"
                  << "Server: " << remote << ":" << port << "\n";
#endif
        std::cout << "Enter 'r' to force reconnect (for testing)\n"
                  << "Type any other input or press Enter to exit. Use Ctrl+C to quit.\n";

#ifndef _DEBUG
        std::thread status_logger([&]()
            {
                int tick = 0;
                while (g_running.load())
                {
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    if (!g_running.load())
                    {
                        break;
                    }
                    if (++tick % 5 != 0)
                    {
                        continue;
                    }
                    LOG_KEY("alive: state=%s, tun->udp=%llu pkts/%s, udp->tun=%llu pkts/%s",
                            ReconnectManager::state_name(mgr.state()),
                            g_tx_pkts.load(), format_bytes(g_tx_bytes.load()).c_str(),
                            g_rx_pkts.load(), format_bytes(g_rx_bytes.load()).c_str());
                }
            });
#endif

        std::string line;
        while (g_running.load() && std::getline(std::cin, line))
        {
                if (line == "r" || line == "R")
                {
                    std::cout << "Forcing reconnect...\n";
                    mgr.force_disconnect_for_test();
                }
            else
            {
                break;
            }
        }

        request_shutdown();
#ifndef _DEBUG
        if (status_logger.joinable())
        {
            status_logger.join();
        }
#endif
        if (tun_to_udp.joinable())
        {
            tun_to_udp.join();
        }
        if (udp_to_tun.joinable())
        {
            udp_to_tun.join();
        }
        LOG_KEY("VPN stopped");
    }
    catch (const std::exception& e)
    {
        LOG_ERR("Error: %s", e.what());
        request_shutdown();
        return 1;
    }

    Logger::Shutdown();
    return 0;
}
