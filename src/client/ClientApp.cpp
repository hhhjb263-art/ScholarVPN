#include "ClientApp.h"
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <chrono>
#include "platform/iplist.h"
#include "tun_macro.h"
#include"../src/util/utf.h"
#if !defined(_WIN32)
#include <poll.h>
#include <unistd.h>
#endif

namespace {

#if defined(_WIN32)
bool dpapi_protect(const std::vector<uint8_t>& plain, std::vector<uint8_t>& out)
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

bool dpapi_unprotect(const std::vector<uint8_t>& enc, std::vector<uint8_t>& plain)
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
#else
bool dpapi_protect(const std::vector<uint8_t>& plain, std::vector<uint8_t>& out)
{
    out = plain;
    return true;
}

bool dpapi_unprotect(const std::vector<uint8_t>& enc, std::vector<uint8_t>& plain)
{
    plain = enc;
    return true;
}
#endif

#ifdef _DEBUG
const std::string kServerSigPubPem = R"(-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEADOVzGrvIQ/LWfUu9aatEdjKotXm2OXcy02/IJ/RqlcI=
-----END PUBLIC KEY-----
)";
#else
const std::string kServerSigPubPem = R"(-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEADOVzGrvIQ/LWfUu9aatEdjKotXm2OXcy02/IJ/RqlcI=
-----END PUBLIC KEY-----
)";
#endif

}

ClientApp::ClientApp() = default;

ClientApp::~ClientApp()
{
    stop();
}

void ClientApp::emit_log(const char* fmt, ...)
{
    char buf[2048]{};
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    LOG_INFO("%s", buf);
    if (m_onLog)
    {
        m_onLog(0, buf);
    }
}

// 分级别版本：写文件时带上正确级别，同时把级别传给 GUI 用于着色与筛选
void ClientApp::emit_warn(const char* fmt, ...)
{
    char buf[2048]{};
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    LOG_WARN("%s", buf);
    if (m_onLog)
    {
        m_onLog(1, buf);
    }
}

void ClientApp::emit_err(const char* fmt, ...)
{
    char buf[2048]{};
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    LOG_ERR("%s", buf);
    if (m_onLog)
    {
        m_onLog(2, buf);
    }
}

void ClientApp::set_state_callback(StateCallback cb)
{
    m_onState = std::move(cb);
}

void ClientApp::set_connected_callback(ConnectedCallback cb)
{
    m_onConnect = std::move(cb);
}

void ClientApp::set_log_callback(LogCallback cb)
{
    m_onLog = std::move(cb);
}

void ClientApp::set_register_token_rejected_callback(TokenRejectedCallback cb)
{
    m_onTokenRejected = std::move(cb);
}

void ClientApp::save_config()
{
    if (m_configPath.empty())
    {
        return;
    }
    Config config(m_configPath, m_configDir);
    config.SaveClientConfig(m_cfg);
}

bool ClientApp::is_elevated()
{
#if defined(_WIN32)
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token))
    {
        return false;
    }
    TOKEN_ELEVATION elev{};
    DWORD ret = 0;
    const BOOL ok = ::GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &ret);
    ::CloseHandle(token);
    return ok != FALSE && elev.TokenIsElevated != 0;
#else
    return ::geteuid() == 0;
#endif
}

// 一次性初始化：日志、套接字运行时、管理员权限校验、配置与密钥
bool ClientApp::init()
{
    Logger::Init();

    sock_runtime_start();

    if (!is_elevated())
    {
        LOG_ERR("[权限] 当前以普通用户运行：创建虚拟网卡 / 修改路由 / 修改 DNS 需要管理员权限，"
                "连接功能不可用。请右键程序选择「以管理员身份运行」后重试。");
        return false;
    }

    m_dnsGuard.restore();

    m_configDir = cfg_app_dir();
    m_configPath = cfg_path_join(m_configDir, CS("config.ini"));
    Config::CreateDir(m_configDir);
    const cfgstr keysDirW = cfg_path_join(m_configDir, CS("keys"));
    Config::CreateDir(keysDirW);
    std::string keysDir = cfg_to_utf8(keysDirW);
    if (keysDir.empty() || (keysDir.back() != '/' && keysDir.back() != '\\'))
    {
        keysDir += '/';
    }

    const cfgstr idPubPathW = cfg_path_join(keysDirW, CS("client.id.pub"));
    const cfgstr idEncPathW = cfg_path_join(keysDirW, CS("client.id.enc"));
    if (!Config::FileExists(idPubPathW))
    {
        try
        {
            const std::string tmpPriv = keysDir + "client.id.priv.tmp";
            std::string pubPem;
            if (!generate_ed25519_keypair(tmpPriv, narrow(idPubPathW), pubPem))
            {
                LOG_ERR("Failed to generate Ed25519 identity key pair");
                return false;
            }
            std::ifstream in(tmpPriv, std::ios::binary);
            std::vector<uint8_t> privPem(
                (std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            in.close();
            ::cfg_unlink(cfg_from_utf8(tmpPriv));
            std::vector<uint8_t> blob;
            if (!dpapi_protect(privPem, blob) ||
                !Config::WriteTextFile(idEncPathW, std::string(blob.begin(), blob.end())))
            {
                LOG_ERR("Failed to store identity private key");
                return false;
            }
            if (!cfg_restrict_file(idEncPathW))
            {
                LOG_ERR("[Identity] 无法把 %s 权限设为 0600，私钥可能被其他用户读取",
                        cfg_to_utf8(idEncPathW).c_str());
                return false;
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
            return false;
        }
    }
    try
    {
        const std::string encData = Config::ReadTextFile(idEncPathW);
        std::vector<uint8_t> blob(encData.begin(), encData.end());
        std::vector<uint8_t> privPem;
        if (!dpapi_unprotect(blob, privPem))
        {
            LOG_ERR("Failed to decrypt identity private key (DPAPI). "
                    "client.id.enc is bound to this Windows user account.");
            return false;
        }
        m_ed25519Priv.reset(
            load_ed25519_private_key_pem(std::string(privPem.begin(), privPem.end())),
            EVP_PKEY_free);
        LOG_KEY("[Identity] SIG_CLI_PUB loaded");
    }
    catch (const std::exception& e)
    {
        LOG_ERR("Error loading identity keys: %s", e.what());
        return false;
    }

    m_serverSigPubPem = kServerSigPubPem;
    if (m_serverSigPubPem.find("-----BEGIN PUBLIC KEY-----") == std::string::npos)
    {
        const std::string exe_dir = get_exe_dir();
        const std::string pub_path = find_key_file(keysDir, exe_dir, "server.pub");
        std::ifstream in(pub_path, std::ios::binary);
        if (!in)
        {
            LOG_ERR("No server identity public key: neither kServerSigPubPem in source "
                    "nor %s exists. Embed the server's server_sig.pub into the client.",
                    pub_path.c_str());
            return false;
        }
        m_serverSigPubPem.assign(
            std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
        LOG_KEY("[Identity] No hardcoded SIG_SRV_PUB, falling back to %s "
                "(consider embedding it into kServerSigPubPem)", pub_path.c_str());
    }

#ifndef _DEBUG
    if (!Config::FileExists(m_configPath))
    {
        if (!Config(m_configPath, m_configDir).SaveClientConfig(m_cfg))
        {
            LOG_ERR("Failed to create config.ini at %s", narrow(m_configPath).c_str());
            return false;
        }
        LOG_KEY("First run: config.ini created at %s\n"
                "Client keys are stored at %s\n"
                "Please fill in ServerIP in config.ini, then run the client again.",
                narrow(m_configPath).c_str(), keysDir.c_str());
        return false;
    }
#endif
    if (Config::FileExists(m_configPath))
    {
        Config config(m_configPath, m_configDir);
        if (!config.LoadClientConfig(m_cfg))
        {
            LOG_ERR("Failed to read config.ini: %s", narrow(m_configPath).c_str());
            return false;
        }
        LOG_KEY("[Config] config.ini loaded: ClientID=%s, RegisterToken=%s, DebugServerIP=%s",
                cfg_to_utf8(m_cfg.ClientID).c_str(),
                m_cfg.RegisterToken.empty() ? "(empty -> login mode)" : "(set -> register mode)",
                cfg_to_utf8(m_cfg.DebugServerIP).c_str());
    }
    else
    {
        LOG_KEY("[Config] config.ini not found (%s), using defaults", narrow(m_configPath).c_str());
    }

    m_builtinServerSigPubPem = m_serverSigPubPem;
    if (!m_cfg.ServerPubKey.empty())
    {
        m_serverSigPubPem = "-----BEGIN PUBLIC KEY-----\n"
                          + narrow(m_cfg.ServerPubKey)
                          + "\n-----END PUBLIC KEY-----\n";
        LOG_KEY("[Identity] 已应用服务器 %s 配置的 ServerPubKey 验签", cfg_to_utf8(m_cfg.ServerIP).c_str());
    }

    if (!m_cfg.servers.empty())
    {
        m_transport = m_cfg.servers[0].transport ? Transport::TCP : Transport::UDP;
    }
    else
    {
        m_transport = Transport::UDP;
    }
    LOG_KEY("[Config] 传输方式: %s（[Server1] Transport=%d）",
            (m_transport == Transport::TCP) ? "TCP" : "UDP",
            static_cast<int>(m_transport));

#ifndef _DEBUG
    m_serverHost = narrow(m_cfg.ServerIP);
    m_remote = m_serverHost;
    if (!m_remote.empty() && !is_valid_host(m_remote))
    {
        LOG_ERR("Invalid ServerIP in config.ini (既不是 IPv4 也不是域名): %s", m_remote.c_str());
        return false;
    }
    if (m_cfg.ServerPort < 1 || m_cfg.ServerPort > 65535)
    {
        LOG_ERR("Invalid ServerPort in config.ini: %d", static_cast<int>(m_cfg.ServerPort));
        return false;
    }
    m_port = static_cast<uint16_t>(m_cfg.ServerPort);
#else
    m_remote = "192.168.1.12";
    m_serverHost = m_remote;
    m_port = 51820;
    if (Config::FileExists(m_configPath))
    {
        if (m_cfg.ServerPort >= 1 && m_cfg.ServerPort <= 65535)
            m_port = static_cast<uint16_t>(m_cfg.ServerPort);
        const std::string d = narrow(m_cfg.DebugServerIP);
        if (is_valid_host(d))
        {
            m_serverHost = d;
            m_remote = d;
        }
        else
        {
            const std::string r = narrow(m_cfg.ServerIP);
            if (is_valid_host(r))
            {
                m_serverHost = r;
                m_remote = r;
            }
        }
    }
#endif
    m_tun = create_tun_device();
#if defined(_WIN32)
    const char* kTunName = "MyTunAdapter";
#else
    const char* kTunName = "vpn0";
#endif
    if (!m_tun->init_tun(kTunName, "MyTunnel"))
    {
#if defined(_WIN32)
        LOG_ERR("Wintun initialization failed (is wintun.dll present next to the executable?)");
#else
        LOG_ERR("TUN 初始化失败（需要 root 或 CAP_NET_ADMIN；容器内需 --device /dev/net/tun）");
#endif
        return false;
    }
    m_adapter = std::make_unique<AdapterConfig>(m_tun->get_interface_id());
    if (!m_cfg.VirtualIP.empty())
    {
        if (!m_adapter->set_IPv4_address(m_cfg.VirtualIP, static_cast<uint8_t>(m_cfg.VirtualPrefix)))
        {
            LOG_ERR("Failed to set TUN IP address");
            return false;
        }
    }
    if (!m_adapter->set_MTU(m_cfg.MTU))
    {
        LOG_ERR("[Warn] Failed to set MTU");
    }
    if (!m_adapter->set_metric(m_cfg.Metric))
    {
        LOG_ERR("[Warn] Failed to set adapter metric");
    }
    if (!m_adapter->set_DNS_IPv4(effective_dns()))
    {
        LOG_ERR("[Warn] Failed to set DNS, continuing without custom DNS");
    }
    m_route = std::make_unique<RouteManager>(m_tun->get_interface_id());
    if (!m_remote.empty())
    {
        if (!m_route->add_server_bypass_route(cfg_from_utf8(m_remote)))
        {
            LOG_ERR("Failed to add server bypass route");
            return false;
        }
    }

    emit_log("ClientApp initialized, server=%s:%u", m_remote.c_str(), static_cast<int>(m_port));
    return true;
}

// 建连入口：装配 ReconnectManager 与状态回调，起上下行两个数据面线程
bool ClientApp::start()
{
    if (m_running.exchange(true))
    {
        return false;
    }

    if (m_updateBlocked.load())
    {
        LOG_ERR("[Update] 当前版本被要求强制更新，拒绝连接");
        emit_warn("当前版本已被要求强制更新，请先更新后再连接");
        m_running.store(false);
        return false;
    }
    if (m_serviceBlocked.load())
    {
        LOG_ERR("[Service] 当前设备服务状态不允许使用，拒绝连接");
        emit_warn("服务状态不允许连接（试用期结束或额度用完，等待服务方确认授权）");
        m_running.store(false);
        return false;
    }

    if (!m_serverHost.empty())
    {
        std::string ip;
        if (!resolve_host(m_serverHost, ip))
        {
            LOG_ERR("[DNS] 解析服务器地址失败: %s", m_serverHost.c_str());
            emit_err("无法解析服务器地址 %s（检查域名拼写 / 本机 DNS）", m_serverHost.c_str());
            m_running.store(false);
            return false;
        }
        if (ip != m_serverHost)
        {
            LOG_KEY("[DNS] %s -> %s", m_serverHost.c_str(), ip.c_str());
            emit_log("[DNS] %s -> %s", m_serverHost.c_str(), ip.c_str());
        }
        m_remote = ip;
    }

    if (m_route && !m_remote.empty() &&
        !m_route->add_server_bypass_route(cfg_from_utf8(m_remote)))
    {
        LOG_ERR("Failed to add server bypass route");
        m_running.store(false);
        return false;
    }

    m_mgr = std::make_unique<ReconnectManager>(m_remote, m_port, 4096);
    m_mgr->set_transport(m_transport);
    m_mgr->set_identity(m_ed25519Priv, m_serverSigPubPem,
                        narrow(m_cfg.ClientID), narrow(m_cfg.RegisterToken));

    m_tunIpReady.store(false);

    m_mgr->set_state_callback([this](ConnState s)
        {
            try
            {
                m_state.store(s);
                emit_log("[Reconnect] state -> %s", ReconnectManager::state_name(s));
                if (s == ConnState::Reconnecting)
                {
                    m_tunIpReady.store(false);
                    if (m_route)
                    {
                        m_route->remove_default_route();
                    }
                    m_dnsProxy.stop();
                    m_dnsGuard.restore();
                }
                if (s == ConnState::Stopped || s == ConnState::Error)
                {
                    m_tunIpReady.store(false);
                }
                if (m_onState)
                {
                    m_onState(s);
                }
            }
            catch (const std::exception& e)
            {
                LOG_ERR("[ClientApp] state callback exception: %s", e.what());
            }
            catch (...)
            {
                LOG_ERR("[ClientApp] state callback unknown exception");
            }
        });

    m_mgr->set_connected_callback([this]()
        {
            try
            {
            if (m_route)
            {
                // 顺序不能换：先 bypass 服务器，再加默认路由，否则握手包会进 TUN 黑洞
                m_route->add_server_bypass_route(cfg_from_utf8(m_remote));
                if (intranet_active())
                {
                    // 内网模式：只把指定网段指向隧道，默认路由留给物理网卡
                    apply_intranet_routing();
                }
                else
                {
                    if (routing_intranet() && m_serverManaged)
                    {
                        emit_warn("[Intranet] 受管服务器不支持内网访问，本次按全局模式连接");
                    }
                    apply_split_routing();
                    m_route->add_default_route(m_cfg.Metric);
                }
            }
            if (!intranet_active())
            {
                // 内网模式下不改系统 DNS：公网解析仍由物理网卡完成
                m_dnsGuard.protect(m_tun->get_interface_id(), effective_dns());
            }
            if (routing_split())
            {
                const cfgstr listFile = cfg_path_join(cfg_from_utf8(get_exe_dir()), CS("chn-domains.txt"));
                std::string foreign = narrow(m_cfg.DNS);
                const std::size_t comma = foreign.find(',');
                if (comma != std::string::npos)
                    foreign = foreign.substr(0, comma);
                while (!foreign.empty() && foreign.back() == ' ')
                    foreign.pop_back();
                if (m_dnsProxy.start(listFile, "223.5.5.5",
                                     foreign.empty() ? "8.8.8.8" : foreign)) {
                    m_adapter->set_DNS_IPv4(CS("127.0.0.1"));
                    emit_log("[DnsProxy] DNS 分流已启用（国内直连解析 / 国外走隧道）");
                }
            }
            else if (intranet_active())
            {
                // 内网模式不动系统 DNS：公网解析继续走物理网卡
                m_dnsProxy.stop();
            }
            else
            {
                m_dnsProxy.stop();
                m_adapter->set_DNS_IPv4(effective_dns());
            }
            emit_log("[Reconnect] Connected, routes + DNS guard active");

            auto u = m_mgr->udp();
            m_tunIpReady.store(u == nullptr || u->assigned_ip() == 0);
            if (u && u->assigned_ip() != 0 && m_adapter)
            {
                const uint32_t ip = u->assigned_ip();
                char ipstr[16] = { 0 };
                std::snprintf(ipstr, sizeof(ipstr), "%u.%u.%u.%u",
                              (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                              (ip >> 8) & 0xFF, ip & 0xFF);
                const cfgstr wip = cfg_from_utf8(ipstr);
                const uint8_t prefix = u->assigned_prefix();
                const int cleared = m_adapter->clear_IPv4_addresses(wip);
                if (cleared > 0)
                {
                    emit_log("[TUN] 已清理网卡上 %d 个遗留 IPv4 地址（防源地址不匹配）", cleared);
                }
                if (m_adapter->set_IPv4_address(wip, prefix))
                {
                    // 只配到网卡上，不回写 config：VirtualIP 是"用户指定"语义，
                    // 把服务端临时分配的地址写回去，下次启动就变成了固定请求，容易和别的设备撞车
                    emit_log("[TUN] 已采用服务端分配的虚拟 IP: %s/%u", ipstr, static_cast<unsigned>(prefix));
                }
                else
                {
                    LOG_ERR("[TUN] 设置服务端分配的 IP 失败: %s/%u —— 上行数据可能被服务端"
                            "源地址校验丢弃；请重连（或检查 Wintun 网卡地址是否被占用）",
                            ipstr, static_cast<unsigned>(prefix));
                }
                m_tunIpReady.store(true);
            }
            if (!m_cfg.RegisterToken.empty())
            {
                m_cfg.RegisterToken.clear();
                m_mgr->clear_register_token();
                save_config();
                emit_log("[Config] 注册成功，已自动清空 RegisterToken，下次连接自动为登录模式");
            }
            if (m_onConnect)
            {
                m_onConnect(assigned_ip());
            }
            }
            catch (const std::exception& e)
            {
                LOG_ERR("[ClientApp] connected callback exception: %s", e.what());
            }
            catch (...)
            {
                LOG_ERR("[ClientApp] connected callback unknown exception");
            }
        });

    m_mgr->set_register_token_rejected_callback([this]()
        {
            try
            {
                m_cfg.RegisterToken.clear();
                save_config();
                emit_log("[Config] 注册令牌无效或已使用，已自动清空 RegisterToken，将以登录模式重试");
                if (m_onTokenRejected)
                {
                    m_onTokenRejected();
                }
            }
            catch (const std::exception& e)
            {
                LOG_ERR("[ClientApp] token rejected callback exception: %s", e.what());
            }
            catch (...)
            {
                LOG_ERR("[ClientApp] token rejected callback unknown exception");
            }
        });

    if (!m_mgr->start())
    {
        LOG_ERR("Failed to start reconnect manager");
        m_running.store(false);
        return false;
    }

    m_threadTunToUdp = std::thread([this]() { tun_to_udp_loop(); });
    m_threadUdpToTun = std::thread([this]() { udp_to_tun_loop(); });

    emit_log("VPN started, connecting to %s:%d (%s)", m_remote.c_str(), static_cast<int>(m_port),
             (m_transport == Transport::TCP) ? "TCP" : "UDP");
    return true;
}

// 上行：虚拟网卡读 IP 包，握手完成且虚拟 IP 就绪后封装发往服务端
void ClientApp::tun_to_udp_loop()
{
    while (m_running.load())
    {
        try
        {
            auto u = m_mgr ? m_mgr->udp() : nullptr;
            if (!u || !u->is_handshaked())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }
            const uint32_t assigned = u->assigned_ip();
            if (assigned != 0 && !m_tunIpReady.load())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
                continue;
            }
            tun_len_t len = 0;
            uint8_t* pkt = m_tun->read_packet(&len);
            if (pkt && len > 0)
            {
                if (len < 20 || (pkt[0] >> 4) != 4)
                {
                    m_tun->release_read_packet(pkt);
                    const uint32_t n = m_nonIpv4Dropped.fetch_add(1);
                    if (n < 3)
                    {
                        LOG_INFO("[TUN] 丢弃非 IPv4 报文（%u 字节，本隧道只承载 IPv4）%s",
                                 static_cast<unsigned>(len),
                                 (n == 2) ? "（同类日志已抑制）" : "");
                    }
                    continue;
                }
                if (assigned != 0)
                {
                    uint32_t src = 0;
                    memcpy(&src, pkt + 12, 4);
                    if (src != htonl(assigned))
                    {
                        m_tun->release_read_packet(pkt);
                        const uint32_t n = m_srcMismatchDropped.fetch_add(1);
                        if (n < 3)
                        {
                            LOG_ERR("[TUN] 丢弃源地址不匹配的上行报文（包内源地址非本会话虚拟 IP），"
                                    "累计 %u 个%s", n + 1,
                                    (n == 2) ? "（同类日志已抑制，请检查网卡是否残留旧地址）" : "");
                        }
                        continue;
                    }
                }
                m_txPkts.fetch_add(1);
                m_txBytes.fetch_add(len);
                packet_buffer buf(pkt, len);
                m_tun->release_read_packet(pkt);
                u->send_ip_packet(std::move(buf));
            }
            else
            {
                const tun_event_t ev = m_tun->read_wait_event();
#if defined(_WIN32)
                if (ev != nullptr)
                {
                    ::WaitForSingleObject(ev, 200);
                }
                else
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }
#else
                if (ev >= 0)
                {
                    struct pollfd pfd{};
                    pfd.fd = ev;
                    pfd.events = POLLIN;
                    ::poll(&pfd, 1, 200);
                }
                else
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }
#endif
            }
        }
        catch (const std::exception& e)
        {
            LOG_ERR("[Bridge] tun->udp 异常（已忽略继续）: %s", e.what());
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        catch (...)
        {
            LOG_ERR("[Bridge] tun->udp 未知异常（已忽略继续）");
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
}

// 下行：从服务端收 IP 包，写回虚拟网卡
void ClientApp::udp_to_tun_loop()
{
    while (m_running.load())
    {
        try
        {
            auto u = m_mgr ? m_mgr->udp() : nullptr;
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
                m_rxPkts.fetch_add(1);
                m_rxBytes.fetch_add(buf.data_size());
                m_tun->write_packet(buf.get_data(), static_cast<tun_len_t>(buf.data_size()));
            }
        }
        catch (const std::exception& e)
        {
            LOG_ERR("[Bridge] udp->tun 异常（已忽略继续）: %s", e.what());
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        catch (...)
        {
            LOG_ERR("[Bridge] udp->tun 未知异常（已忽略继续）");
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
}

namespace {

bool equals_ci(const std::string& a, const char* b)
{
    const std::size_t n = std::strlen(b);
    if (a.size() != n)
    {
        return false;
    }
    for (std::size_t i = 0; i < n; ++i)
    {
        const unsigned char c = static_cast<unsigned char>(a[i]);
        const char lower = (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a')
                                                  : static_cast<char>(c);
        if (lower != b[i])
        {
            return false;
        }
    }
    return true;
}

bool load_china_ip_list(const std::string& exeDirUtf8, std::vector<cidr::Cidr>& out)
{
    const cfgstr path = cfg_path_join(cfg_from_utf8(exeDirUtf8), CS("chnroute.txt"));
    iplist::Stats st;
    if (!iplist::load_file(path, out, &st))
    {
        LOG_WARN("[Split] 找不到国内网段文件：%s", cfg_to_utf8(path).c_str());
        return false;
    }
    LOG_INFO("[Split] 加载国内网段 %zu 条（坏行 %zu）", st.valid, st.malformed);
    return !out.empty();
}

}

bool ClientApp::routing_split() const
{
    return equals_ci(cfg_to_utf8(m_cfg.RoutingMode), "split");
}

void ClientApp::set_routing_split(bool split)
{
    m_cfg.RoutingMode = split ? CS("split") : CS("full");
}

bool ClientApp::routing_intranet() const
{
    return equals_ci(cfg_to_utf8(m_cfg.RoutingMode), "intranet");
}

// 内网访问只对自建卡片开放；受管服务器即使配置了也按 full 处理

cfgstr ClientApp::routing_mode() const
{
    return m_cfg.RoutingMode;
}

void ClientApp::set_routing_mode(const cfgstr& mode)
{
    m_cfg.RoutingMode = mode;
    m_intranetApplied.store(false);
}

static cfgstr ipv4_text(uint32_t v)
{
    char buf[16] = {0};
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                  (v >> 24) & 0xFFu, (v >> 16) & 0xFFu,
                  (v >> 8) & 0xFFu, v & 0xFFu);
    return cfg_from_utf8(buf);
}

// 内网访问：只把配置的网段指向隧道，系统默认路由保持物理网卡
void ClientApp::apply_intranet_routing()
{
    if (!m_route || m_intranetApplied.load())
    {
        return;
    }
    if (m_serverManaged)
    {
        LOG_ERR("[Intranet] 受管服务器（由服务方下发）不支持内网访问，已忽略 IntranetSubnets");
        return;
    }

    std::vector<cidr::Cidr> list;
    const std::string raw = cfg_to_utf8(m_cfg.IntranetSubnets);
    std::string item;
    for (std::size_t i = 0; i <= raw.size(); ++i)
    {
        const char c = (i < raw.size()) ? raw[i] : ',';
        if (c != ',' && c != ';' && c != ' ' && c != '\t')
        {
            item.push_back(c);
            continue;
        }
        if (item.empty())
        {
            continue;
        }
        cidr::Cidr one{};
        if (cidr::parse(item, one))
        {
            list.push_back(one);
        }
        else
        {
            LOG_WARN("[Intranet] 忽略无法解析的网段: %s", item.c_str());
        }
        item.clear();
    }

    if (list.empty())
    {
        LOG_ERR("[Intranet] IntranetSubnets 为空或全部无效，未注入任何路由："
                "除隧道本身外所有流量仍走物理网络");
        return;
    }

    int ok = 0;
    for (const auto& n : list)
    {
        if (m_route->add_tunnel_route(ipv4_text(n.addr), n.prefix, m_cfg.Metric))
        {
            ++ok;
        }
    }
    if (ok == 0)
    {
        LOG_ERR("[Intranet] %zu 条内网路由全部注入失败（需管理员权限）", list.size());
        return;
    }
    m_intranetApplied.store(true);
    LOG_INFO("[Intranet] 注入 %d/%zu 条内网路由，默认路由保持物理网卡",
             ok, list.size());
}

cfgstr ClientApp::effective_dns() const
{
    if (!routing_split())
    {
        return m_cfg.DNS;
    }
    return CS("223.5.5.5,119.29.29.29");
}

// 分流：把国内 CIDR 指向物理网关，前缀比隧道默认路由更具体因而优先生效
void ClientApp::apply_split_routing()
{
    if (!equals_ci(cfg_to_utf8(m_cfg.RoutingMode), "split"))
    {
        LOG_INFO("[Split] Mode=full：全流量走隧道");
        return;
    }
    if (m_route->split_route_count() > 0)
    {
        LOG_INFO("[Split] 已注入 %zu 条，跳过重复注入", m_route->split_route_count());
        return;
    }

    std::vector<cidr::Cidr> list;
    if (!load_china_ip_list(get_exe_dir(), list))
    {
        LOG_WARN("[Split] 无可用列表，降级为 full（全流量走隧道）");
        return;
    }

    const cfgstr probe = m_cfg.ProbeIP.empty() ? CS("8.8.8.8") : m_cfg.ProbeIP;
    const auto t0 = std::chrono::steady_clock::now();
    const int ok = m_route->add_bypass_routes(list, probe);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - t0).count();

    const std::size_t total = list.size();
    if (ok == 0)
    {
        LOG_WARN("[Split] 一条都未注入成功，降级为 full");
        return;
    }
    if (static_cast<std::size_t>(ok) * 10 < total)
    {
        LOG_WARN("[Split] 仅成功 %d/%zu（不足 10%%），回滚避免半个分流", ok, total);
        m_route->remove_split_routes();
        return;
    }
    LOG_INFO("[Split] 注入 %d/%zu 条国内网段，耗时 %lld ms", ok, total,
             static_cast<long long>(ms));

    const int actual = m_route->count_active_split_routes();
    if (actual >= 0)
    {
        if (actual < ok)
        {
            LOG_WARN("[Split] 自校验不通过：API 返回 %d 条，路由表里只有 %d 条"
                     "（注入未真正生效，检查是否以管理员运行）", ok, actual);
        }
        else
        {
            LOG_INFO("[Split] 自校验通过：路由表内确认 %d 条分流路由", actual);
        }
    }
}

void ClientApp::stop()
{
    const bool wasRunning = m_running.exchange(false);
    m_tunIpReady.store(false);
    if (m_mgr)
    {
        m_mgr->stop();
    }
    if (m_route)
    {
        m_route->clear_routes();
    }
    m_intranetApplied.store(false);
    if (m_threadTunToUdp.joinable())
    {
        m_threadTunToUdp.join();
    }
    if (m_threadUdpToTun.joinable())
    {
        m_threadUdpToTun.join();
    }
    m_mgr.reset();
    m_dnsProxy.stop();
    m_dnsGuard.restore();
    m_state.store(ConnState::Stopped);
    if (wasRunning)
    {
        emit_log("VPN stopped");
    }
}

ConnState ClientApp::state() const
{
    return m_state.load();
}

std::string ClientApp::assigned_ip() const
{
    auto u = m_mgr ? m_mgr->udp() : nullptr;
    if (!u)
    {
        return {};
    }
    const uint32_t ip = u->assigned_ip();
    if (ip == 0)
    {
        return {};
    }
    char buf[16]{};
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                  (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
    return buf;
}

std::string ClientApp::client_id() const
{
    return narrow(m_cfg.ClientID);
}

void ClientApp::set_server(const ServerEntry& entry)
{
    m_serverManaged = entry.managed;
    m_serverHost = narrow(entry.ServerIP);
    m_remote = m_serverHost;
    m_port = static_cast<uint16_t>(entry.ServerPort);
    m_transport = entry.transport ? Transport::TCP : Transport::UDP;
    m_cfg.ClientID = entry.ClientID;
    m_cfg.RegisterToken = entry.RegisterToken;
    bool synced = false;
    for (auto& s : m_cfg.servers)
    {
        if (s.ServerIP == entry.ServerIP && s.ServerPort == entry.ServerPort)
        {
            s.transport = entry.transport;
            s.ClientID = entry.ClientID;
            s.RegisterToken = entry.RegisterToken;
            s.ServerPubKey = entry.ServerPubKey;
            synced = true;
            break;
        }
    }
    if (!synced)
    {
        m_cfg.servers.push_back(entry);
    }
    if (!entry.ServerPubKey.empty())
    {
        m_serverSigPubPem = "-----BEGIN PUBLIC KEY-----\n"
                          + narrow(entry.ServerPubKey)
                          + "\n-----END PUBLIC KEY-----\n";
        emit_log("已应用服务器条目 %s 配置的 ServerPubKey 验签", cfg_to_utf8(m_cfg.ServerIP).c_str());
    }
    else
    {
        m_serverSigPubPem = m_builtinServerSigPubPem;
        emit_log("服务器条目未配置 ServerPubKey，使用内置固定公钥验签"
                 "（若与服务器身份不符会在握手时验签失败）");
    }
    emit_log("已选择服务器: %s:%u, 传输=%s, ClientID=%s", m_remote.c_str(), static_cast<int>(m_port),
             (m_transport == Transport::TCP) ? "TCP" : "UDP",
             narrow(m_cfg.ClientID).c_str());
}
