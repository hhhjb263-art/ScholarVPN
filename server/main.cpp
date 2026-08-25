#include "VpnCore.h"
#include "core/log.h"

#include <csignal>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <system_error>
#include <unistd.h>   // pause()

// 全局：信号处理只置位标志，主线程负责优雅停止
static volatile std::sig_atomic_t g_stop = 0;

static void handle_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void print_usage(const char *prog)
{
    printf("用法: %s [选项]\n", prog);
    printf("  服务端 VPN：创建 TUN 虚拟网卡并通过 UDP 隧道转发流量\n");
    printf("选项:\n");
    printf("  -l, --listen <ip>     监听 IP (默认 0.0.0.0)\n");
    printf("  -p, --port <port>     监听端口 (默认 51820)\n");
    printf("  -n, --name <name>     TUN 网卡名 (默认 vpn0)\n");
    printf("  -a, --addr <ip>       TUN 内网 IP (默认 10.8.0.1)\n");
    printf("      --prefix <n>      隧道网段前缀 (默认 24)\n");
    printf("      --mtu <n>         TUN MTU (默认 1400)\n");
    printf("      --default-route   把默认路由指向 TUN\n");
    printf("  -k, --key <path>      服务器 Ed25519 身份私钥 (默认 keys/server_sig.key)\n");
    printf("      --max-clients <n> 最大并发客户端数，自动分配虚拟 IP (默认 64)\n");
    printf("  -g, --gen-token [n]   生成 n 个一次性注册令牌(默认1)追加到 keys/register_tokens.txt 后退出\n");
    printf("      --quiet           关闭数据包级日志，只输出重点日志（公网服务器推荐）\n");
    printf("  -h, --help            显示本帮助\n");
}

static bool parse_args(int argc, char *argv[], VpnCore::Config &cfg)
{
    for(int i = 1; i < argc; ++i){
        const std::string arg = argv[i];
        auto next = [&](const char *what) -> const char * {
            if(i + 1 >= argc){
                fprintf(stderr, "缺少参数: %s %s\n", arg.c_str(), what);
                return nullptr;
            }
            return argv[++i];
        };

        if(arg == "-h" || arg == "--help"){
            print_usage(argv[0]);
            exit(0);
        }else if(arg == "-l" || arg == "--listen"){
            const char *v = next("IP");
            if(!v) return false;
            cfg.listen_ip = v;
        }else if(arg == "-p" || arg == "--port"){
            const char *v = next("端口");
            if(!v) return false;
            cfg.listen_port = static_cast<uint16_t>(std::atoi(v));
        }else if(arg == "-n" || arg == "--name"){
            const char *v = next("网卡名");
            if(!v) return false;
            cfg.tun_name = v;
        }else if(arg == "-a" || arg == "--addr"){
            const char *v = next("IP");
            if(!v) return false;
            cfg.tun_ip = v;
        }else if(arg == "--prefix"){
            const char *v = next("前缀");
            if(!v) return false;
            cfg.tun_prefix = std::atoi(v);
        }else if(arg == "--mtu"){
            const char *v = next("MTU");
            if(!v) return false;
            cfg.tun_mtu = std::atoi(v);
        }else if(arg == "--default-route"){
            cfg.add_default_route = true;
        }else if(arg == "-k" || arg == "--key"){
            const char *v = next("路径");
            if(!v) return false;
            cfg.key_sig_path = v;
        }else if(arg == "--max-clients"){
            const char *v = next("数量");
            if(!v) return false;
            const long n = std::strtol(v, nullptr, 10);
            if(n > 0 && n <= 10000){
                cfg.max_clients = static_cast<size_t>(n);
            }else{
                fprintf(stderr, "参数错误: --max-clients 必须是 1-10000\n");
                return false;
            }
        }else if(arg == "-g" || arg == "--gen-token"){
            int count = 1;
            if(i + 1 < argc){
                char* end = nullptr;
                const long v = std::strtol(argv[i + 1], &end, 10);
                if(end != argv[i + 1] && v > 0 && v <= 1000){
                    count = static_cast<int>(v);
                    ++i;
                }
            }
            cfg.gen_tokens = count;
        }else if(arg == "--quiet"){
            g_packet_log = false;
        }else{
            fprintf(stderr, "未知选项: %s\n", arg.c_str());
            print_usage(argv[0]);
            return false;
        }
    }
    return true;
}

int main(int argc, char *argv[])
{
    VpnCore::Config cfg;
    if(!parse_args(argc, argv, cfg)){
        return 1;
    }

    // 管理员操作：生成一次性注册令牌（vpn_server --gen-token [n]）
    if(cfg.gen_tokens > 0){
        // 令牌目录必须与运行时 UDP::m_keys_dir 一致：
        // 运行时 m_keys_dir = parent(key_sig_path)（VpnCore.cpp），
        // 所以这里也写到 parent(key_sig_path)，而不是硬编码相对路径 "keys/"——
        // 否则 systemd/start.sh 部署（cwd 不是脚本目录）或 -k 自定义路径时，
        // 令牌写到别处，服务端验证永远找不到 → 客户端"注册令牌无效"死循环。
        std::error_code ec;
        std::filesystem::path keys_dir = std::filesystem::path(cfg.key_sig_path).parent_path();
        if(keys_dir.empty()){
            keys_dir = ".";
        }
        std::filesystem::create_directories(keys_dir, ec);
        const std::string tokens_path = (keys_dir / "register_tokens.txt").string();
        FILE *f = std::fopen(tokens_path.c_str(), "a");
        if(f == nullptr){
            fprintf(stderr, "[main] 无法写入 %s\n", tokens_path.c_str());
            return 1;
        }
        for(int i = 0; i < cfg.gen_tokens; ++i){
            const std::string tok = generate_register_token();
            std::fprintf(f, "%s\n", tok.c_str());
            std::printf("register_token: %s\n", tok.c_str());
        }
        std::fclose(f);
        std::printf("[main] 已生成 %d 个注册令牌并追加到 %s\n",
                    cfg.gen_tokens, tokens_path.c_str());
        return 0;
    }

    VpnCore core;
    if(!core.init(cfg)){
        fprintf(stderr, "[main] 初始化失败（创建 TUN 需要 root 权限）\n");
        return 1;
    }
    if(!core.start()){
        fprintf(stderr, "[main] 启动转发层失败\n");
        core.stop();
        return 1;
    }

    printf("[main] VPN 服务端已启动: listen=%s:%u tun=%s(%s/%d mtu=%d)\n",
           cfg.listen_ip.c_str(), cfg.listen_port,
           cfg.tun_name.c_str(), cfg.tun_ip.c_str(),
           cfg.tun_prefix, cfg.tun_mtu);
    printf("[main] 日志模式: %s\n",
           g_packet_log ? "完整（含数据包级日志）" : "精简（仅重点日志）");
    printf("[main] 按 Ctrl+C 优雅退出\n");

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // 阻塞等待信号
    while(!g_stop){
        pause();
    }

    core.stop();
    printf("[main] VPN 服务端已退出\n");
    return 0;
}
