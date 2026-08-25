
#include "ClientApp.h"
#include <cstdarg>
#include"../src/util/utf.h"   // narrow/to_wstring/is_valid_ipv4/get_exe_dir/find_key_file 统一由 utf.h 提供
namespace {

//客户端身份私钥本地加密存储
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

// 服务器身份公钥 SIG_SRV_PUB（硬编码编译进客户端）
// 按构建配置区分：Debug 用本地测试服务器公钥；Release 用正式服务器公钥。
#ifdef _DEBUG
const std::string kServerSigPubPem = R"(-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA+A73aBlJFR3H7ozQ0os5SduqQIga6zIpfI5VSFlGE0A=
-----END PUBLIC KEY-----
)";
#else
const std::string kServerSigPubPem = R"(-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAE9IPOxEDucOHUEhHJ2oZKUhH4wGqV6tgVxdJzhHqQS4=
-----END PUBLIC KEY-----
)";
#endif

} // namespace

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
    if (m_onLog)
    {
        m_onLog(buf);
    }
}

// Callback setters
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

bool ClientApp::init()
{
    Logger::Init();

    m_configDir = Config::GetAppDataRoaming() + L"\\ScholarVPN";
    m_configPath = m_configDir + L"\\config.ini";
    Config::CreateDir(m_configDir);
    const std::wstring keysDirW = m_configDir + L"\\keys";
    Config::CreateDir(keysDirW);
    const std::string keysDir = narrow(keysDirW) + "\\";

    // ---- Ed25519 身份密钥（SIG_CLI_PRI 本地加密存储 / SIG_CLI_PUB）----
    // 私钥经 Windows DPAPI 加密存为 client.id.enc；公钥明文存为 client.id.pub。
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
                return false;
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

    // ---- 服务器身份公钥 SIG_SRV_PUB：优先硬编码，否则回退 keys\server.pub ----
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
        return false;   // 首次运行：生成配置文件后等待用户填写
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
        LOG_KEY("[Config] config.ini loaded: ClientID=%ls, RegisterToken=%s, DebugServerIP=%ls",
                m_cfg.ClientID.c_str(),
                m_cfg.RegisterToken.empty() ? "(empty -> login mode)" : "(set -> register mode)",
                m_cfg.DebugServerIP.c_str());
    }
    else
    {
        LOG_KEY("[Config] config.ini not found (%s), using defaults", narrow(m_configPath).c_str());
    }

#ifndef _DEBUG
    m_remote = narrow(m_cfg.ServerIP);
    // 空 = 多服务器模式：init 只建网卡/路由，目标服务器稍后由 set_server() 指定
    if (!m_remote.empty() && !is_valid_ipv4(m_remote))
    {
        LOG_ERR("Invalid ServerIP in config.ini: %s", m_remote.c_str());
        return false;
    }
    if (m_cfg.ServerPort < 1 || m_cfg.ServerPort > 65535)
    {
        LOG_ERR("Invalid ServerPort in config.ini: %d", static_cast<int>(m_cfg.ServerPort));
        return false;
    }
    m_port = static_cast<uint16_t>(m_cfg.ServerPort);
#else
    // Debug：默认192.168.1.12
    m_remote = "192.168.1.12";
    m_port = 51820;
    if (Config::FileExists(m_configPath))
    {
        if (m_cfg.ServerPort >= 1 && m_cfg.ServerPort <= 65535)
            m_port = static_cast<uint16_t>(m_cfg.ServerPort);
        const std::string d = narrow(m_cfg.DebugServerIP);
        if (is_valid_ipv4(d))
            m_remote = d;
        else
        {
            const std::string r = narrow(m_cfg.ServerIP);
            if (is_valid_ipv4(r))
                m_remote = r;
        }
    }
#endif
    m_tun = std::make_unique<WintunTun>();
    if (!m_tun->init_tun("MyTunAdapter", "MyTunnel"))
    {
        LOG_ERR("Wintun initialization failed (is wintun.dll present next to the executable?)");
        return false;
    }
    m_adapter = std::make_unique<AdapterConfig>(m_tun->get_interface_luid());
    // VirtualIP 可留空
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
    if (!m_adapter->set_DNS_IPv4(m_cfg.DNS))
    {
        LOG_ERR("[Warn] Failed to set DNS, continuing without custom DNS");
    }
    m_route = std::make_unique<RouteManager>(m_tun->get_interface_luid());
    // 只加服务器 bypass 路由：保证握手包能走物理网卡到达服务器。
    // 注意：不能在 init 里切默认路由 / 做 DNS 防护——握手可能失败，
    // 隧道未建立时默认路由指向 TUN 就是"黑洞"，全部流量进 TUN 被丢，
    // 物理网卡 DNS 被清空则 DNS 解析全挂（表现为浏览器没网）。
    // 默认路由 + DNS 防护必须等握手成功（Connected 回调）才激活。
    if (!m_route->add_server_bypass_route(to_wstring(m_remote)))
    {
        LOG_ERR("Failed to add server bypass route");
        return false;
    }

    emit_log("ClientApp initialized, server=%s:%u", m_remote.c_str(), static_cast<int>(m_port));
    return true;
}

bool ClientApp::start()
{
    // 注意：此处不能再调 init()！init() 会用 config 重新解析 m_remote，
    // 会覆盖 set_server() 设置的"当前卡片服务器 IP"。
    // init() 由 AppBridge::connect_to_server / start 在调用 start() 之前完成。
    if (m_running.exchange(true))
    {
        return false;
    }

    // 启动兜底清扫：上次进程异常退出（崩溃/被杀/断电）时，黑洞 DNS 与静态路由可能残留，
    // restore() 会把所有残留的 0.0.0.0 黑洞 DNS 清回 DHCP 自动并恢复注册表策略，
    // 保证"电脑断网"不会跨进程残留——下次启动自动恢复，不需要手动改网卡。
    m_dnsGuard.restore();

    m_mgr = std::make_unique<ReconnectManager>(m_remote, m_port, 256);
    m_mgr->set_identity(m_ed25519Priv, m_serverSigPubPem,
                        narrow(m_cfg.ClientID), narrow(m_cfg.RegisterToken));

    // 状态回调：断线/重连时撤销\"全流量进 TUN\"的黑洞，让物理网卡恢复上网，
    // 同时恢复物理网卡 DNS（防泄漏守卫反向操作），握手包仍走 bypass 路由。
    m_mgr->set_state_callback([this](ConnState s)
        {
            // 回调运行在 ReconnectManager 的 worker 线程里，任何异常穿过
            // std::thread 边界都会 std::terminate 崩溃（崩溃后 stop() 跑不到，
            // 黑洞路由/DNS 残留，电脑断网）。整体 try/catch 兜底。
            try
            {
                m_state.store(s);
                emit_log("[Reconnect] state -> %s", ReconnectManager::state_name(s));
                if (s == ConnState::Reconnecting || s == ConnState::Connecting)
                {
                    if (m_route)
                    {
                        m_route->remove_default_route();   // 只撤默认路由，保留服务器 bypass
                    }
                    m_dnsGuard.restore();                 // 恢复物理网卡 DNS（断线期间可正常上网）
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

    // 连接成功回调：加默认路由 + 防 DNS 泄漏 + 采用服务端通告的虚拟 IP + 注册成功清 RegisterToken
    // 回调运行在 worker 线程，整体 try/catch 防止异常穿过 std::thread 边界导致崩溃。
    m_mgr->set_connected_callback([this]()
        {
            try
            {
            if (m_route)
            {
                m_route->add_server_bypass_route(to_wstring(m_remote));
                m_route->add_default_route(m_cfg.Metric);
            }
            // 隧道已建立：此时才清物理网卡 DNS / 禁用多宿主解析（防泄漏），
            // 断线时由状态回调恢复，不会出现\"没连上却把系统 DNS/路由切走\"的黑洞。
            m_dnsGuard.protect(m_tun->get_interface_luid());
            emit_log("[Reconnect] Connected, routes + DNS guard active");

            // 多用户服务端：identity_ok 通告的虚拟 IP 覆盖网卡地址
            auto u = m_mgr->udp();
            if (u && u->assigned_ip() != 0 && m_adapter)
            {
                const uint32_t ip = u->assigned_ip();
                char ipstr[16] = { 0 };
                std::snprintf(ipstr, sizeof(ipstr), "%u.%u.%u.%u",
                              (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                              (ip >> 8) & 0xFF, ip & 0xFF);
                const std::wstring wip = to_wstring(std::string(ipstr));
                const uint8_t prefix = u->assigned_prefix();
                if (wip != m_cfg.VirtualIP)
                {
                    if (!m_cfg.VirtualIP.empty())
                    {
                        m_adapter->remove_IPv4_address(m_cfg.VirtualIP,
                                                       static_cast<uint8_t>(m_cfg.VirtualPrefix));
                    }
                    if (m_adapter->set_IPv4_address(wip, prefix))
                    {
                        m_cfg.VirtualIP = wip;
                        m_cfg.VirtualPrefix = prefix;
                        emit_log("[TUN] 已采用服务端分配的虚拟 IP: %s/%u", ipstr, static_cast<unsigned>(prefix));
                    }
                    else
                    {
                        LOG_ERR("[TUN] 设置服务端分配的 IP 失败: %s/%u", ipstr, static_cast<unsigned>(prefix));
                    }
                }
            }
            // 注册模式连上 = 注册成功：清空 RegisterToken，下次自动登录
            if (!m_cfg.RegisterToken.empty())
            {
                m_cfg.RegisterToken.clear();
                m_mgr->clear_register_token();
                save_config();
                emit_log("[Config] 注册成功，已自动清空 RegisterToken，下次连接自动为登录模式");
            }
            if (m_onConnect)
            {
                // ConnectedCallback 携带服务端分配的虚拟 IP（可能为空）
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

    // 注册令牌被拒：清空 RegisterToken，切换登录模式重试
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

    emit_log("VPN started, connecting to %s:%d", m_remote.c_str(), static_cast<int>(m_port));
    return true;
}

void ClientApp::tun_to_udp_loop()
{
    while (m_running.load())
    {
        auto u = m_mgr ? m_mgr->udp() : nullptr;
        if (!u || !u->is_handshaked())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        DWORD len = 0;
        uint8_t* pkt = m_tun->read_packet(&len);
        if (pkt && len > 0)
        {
            m_txPkts.fetch_add(1);
            m_txBytes.fetch_add(len);
            packet_buffer buf(pkt, len);
            m_tun->release_read_packet(pkt);
            u->send_ip_packet(std::move(buf));
        }
        else
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }
}

void ClientApp::udp_to_tun_loop()
{
    while (m_running.load())
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
            m_tun->write_packet(buf.get_data(), static_cast<DWORD>(buf.data_size()));
        }
    }
}

void ClientApp::stop()
{
    const bool wasRunning = m_running.exchange(false);
    if (m_mgr)
    {
        m_mgr->stop();
    }
    if (m_route)
    {
        m_route->clear_routes();
    }
    if (m_threadTunToUdp.joinable())
    {
        m_threadTunToUdp.join();
    }
    if (m_threadUdpToTun.joinable())
    {
        m_threadUdpToTun.join();
    }
    m_mgr.reset();
    // 断线/停止：恢复物理网卡 DNS（防 DNS 泄漏守卫的恢复步骤）
    m_dnsGuard.restore();
    m_state.store(ConnState::Stopped);
    if (wasRunning)
    {
        emit_log("VPN stopped");
    }
}

//void ClientApp::force_reconnect()
//{
//    if (m_mgr)
//    {
//        m_mgr->force_disconnect_for_test();
//    }
//}

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

// 多服务器：切换目标服务器及其各自认证身份（init 之后、start 之前调用）
void ClientApp::set_server(const ServerEntry& entry)
{
    m_remote = narrow(entry.ServerIP);
    m_port = static_cast<uint16_t>(entry.ServerPort);
    m_cfg.ClientID = entry.ClientID;
    m_cfg.RegisterToken = entry.RegisterToken;
    // 服务器身份公钥：该服务器配置了公钥就用它验签（多服务器各自独立），
    // 为空则保留内置硬编码公钥
    if (!entry.ServerPubKey.empty())
    {
        m_serverSigPubPem = "-----BEGIN PUBLIC KEY-----\n"
                          + narrow(entry.ServerPubKey)
                          + "\n-----END PUBLIC KEY-----\n";
        emit_log("已加载服务器公钥（用于验签防中间人）: %s", m_remote.c_str());
    }
    emit_log("已选择服务器: %s:%u, ClientID=%s", m_remote.c_str(), static_cast<int>(m_port),
             narrow(m_cfg.ClientID).c_str());
}

