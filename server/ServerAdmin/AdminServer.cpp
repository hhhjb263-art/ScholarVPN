// AdminServer.cpp —— 后台管理服务（按 docs/后台管理服务计划书.md 实现，下称 spec）
// 框架层：epoll + HTTP 解析 + 8KB 上限 + 读写超时 + 限速拉黑 + Connection: close（spec 3.2/7）
// 业务层：onRequest 路由四个 API（spec 第 4 节）；GET / 返回内置管理页（spec 4.5/8.1）
#include "AdminServer.h"
#include "../Crypt/crypt.h"   // generate_register_token / load_ed25519_public_key：复用现成符号（spec 6.2）
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <cstdlib>            // getenv / strtol
#include <cstdio>             // 令牌文件 fopen/fprintf
#include <cctype>             // isdigit
#include <cerrno>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <system_error>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <poll.h>             // sendAll 写缓冲满时的单点救急
#include <sys/file.h>         // flock
#include <sys/stat.h>         // chmod
#include <openssl/crypto.h>   // CRYPTO_memcmp：常量时间比较

// spec 4 的请求结构：头文件只前置声明，完整定义按约定放在这里
// （业务子类与 main 同在本文件，能看到完整类型）
struct HttpRequest {
    std::string method;
    std::string path;
    std::string version;
    std::string body;
    std::unordered_map<std::string, std::string> headers;   // key 统一小写（HTTP 头大小写不敏感）
};

namespace {
constexpr int    kMaxEvents       = 16;     // 一次 epoll_wait 最多取回的事件数
constexpr int    kListenBacklog   = 10;     // 连接队列长度（管理流量极低，够用）
constexpr size_t kMaxRequest      = 8192;   // 请求头+body 总上限 8KB（spec 7）
constexpr int    kTimeoutMs       = 5000;   // epoll_wait 节拍 = 读写超时 = 清扫周期（spec 7）
constexpr int    kAuthFailLimit   = 5;      // 限速窗口内允许的鉴权失败次数（spec 7：5 次/分钟）
constexpr int    kAuthWindowSec   = 60;
constexpr size_t kBearerPrefixLen = 7;      // "Bearer " 的长度

// PEM 里有真实换行，拼进 JSON 字符串必须转义，否则就是非法 JSON
std::string jsonEscape(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;      break;
        }
    }
    return out;
}

// 返回：0 = 还没收全继续等；1 = 解析成功；2 = 格式错误（回 400）；3 = 超过 8KB（回 413）
int parseRequest(const std::string& raw, HttpRequest& req)
{
    const size_t header_end = raw.find("\r\n\r\n");     // 空行 = 头结束
    if (header_end == std::string::npos) return 0;

    const size_t line1_end = raw.find("\r\n");
    if (line1_end == std::string::npos) return 2;
    const std::string line1 = raw.substr(0, line1_end);
    const size_t sp1 = line1.find(' ');                 // "GET /api/info HTTP/1.1" 按空格切三段
    const size_t sp2 = line1.find(' ', sp1 + 1);
    if (sp1 == std::string::npos || sp2 == std::string::npos) return 2;
    req.method  = line1.substr(0, sp1);
    req.path    = line1.substr(sp1 + 1, sp2 - sp1 - 1);
    req.version = line1.substr(sp2 + 1);
    if (req.version.rfind("HTTP/", 0) != 0) return 2;
    if (req.method != "GET" && req.method != "POST" && req.method != "DELETE")
        return 2;                                       // spec 9：仅支持这三种方法，其余一律 400

    size_t pos = line1_end + 2;                         // 逐行切 headers，key 转小写
    while (pos < header_end) {
        const size_t line_end = raw.find("\r\n", pos);
        if (line_end == std::string::npos) break;
        const std::string hline = raw.substr(pos, line_end - pos);
        const size_t colon = hline.find(':');
        if (colon != std::string::npos && colon > 0) {
            std::string key = hline.substr(0, colon);
            for (char& c : key)
                if (c >= 'A' && c <= 'Z') c = char(c + 32);
            size_t v = colon + 1;
            while (v < hline.size() && hline[v] == ' ') v++;    // 跳过冒号后的空格
            req.headers[key] = hline.substr(v);
        }
        pos = line_end + 2;
    }

    long long cl = 0;                                   // 客户端约定：GET/DELETE 也发 Content-Length: 0
    if (auto it = req.headers.find("content-length"); it != req.headers.end())
        cl = atoll(it->second.c_str());
    if (cl < 0) return 2;                               // 负数长度是格式错误
    if (static_cast<size_t>(cl) > kMaxRequest) return 3; // 声明就超限：不必等 body 到齐再拒
    const size_t total = header_end + 4 + static_cast<size_t>(cl);
    if (raw.size() < total) return 0;                   // body 还没收全
    req.body = raw.substr(header_end + 4, static_cast<size_t>(cl));
    return 1;
}

const char* reasonPhrase(int status)
{
    switch (status) {
        case 200: return "OK";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 413: return "Payload Too Large";
        case 429: return "Too Many Requests";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        default:  return "Unknown";
    }
}

std::string makeResponse(int status, const std::string& body,
                         const char* content_type = "application/json")
{
    std::string res;
    res.reserve(body.size() + 160);
    res += "HTTP/1.1 " + std::to_string(status) + " " + reasonPhrase(status) + "\r\n";
    res += "Content-Type: ";
    res += content_type;
    res += "\r\n";
    res += "Content-Length: " + std::to_string(body.size()) + "\r\n";  // 字节数，不是字符数
    res += "Connection: close\r\n";                     // 回完就关——客户端 recv==0 靠它收尾（spec 3.2）
    res += "\r\n";
    res += body;
    return res;
}

bool sendAll(int fd, const std::string& data)
{
    size_t off = 0;
    while (off < data.size()) {
        // MSG_NOSIGNAL：对端已关时不让 SIGPIPE 杀死整个进程
        const ssize_t ns = send(fd, data.data() + off, data.size() - off, MSG_NOSIGNAL);
        if (ns > 0) { off += static_cast<size_t>(ns); continue; }
        if (ns < 0 && errno == EINTR) continue;
        if (ns < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            pollfd p{};                                 // 写缓冲满：只为这一处等 POLLOUT，不污染主 epoll
            p.fd = fd;
            p.events = POLLOUT;
            if (poll(&p, 1, kTimeoutMs) <= 0) return false;
            continue;
        }
        return false;                                   // 对端已关或其他真错误
    }
    return true;
}

// ============ 令牌文件操作（spec 第 6 节：flock 是硬约束） ============
// CLI --gen-token、运行中的 vpn_server（消费删行）、本服务三方共用 <tokens>.lock 一把锁，
// 谁都不许裸读写 register_tokens.txt
class FileLock {                                        // RAII：构造加锁，析构解锁，异常也不漏
public:
    FileLock(const std::string& lock_path, int op) {
        fd_ = ::open(lock_path.c_str(), O_CREAT | O_RDWR, 0600);
        if (fd_ >= 0 && ::flock(fd_, op) != 0) { ::close(fd_); fd_ = -1; }
    }
    ~FileLock() {
        if (fd_ >= 0) { ::flock(fd_, LOCK_UN); ::close(fd_); }
    }
    bool ok() const { return fd_ >= 0; }
    FileLock(const FileLock&) = delete;                 // 锁的所有权不许拷贝
    FileLock& operator=(const FileLock&) = delete;
private:
    int fd_ = -1;
};

std::vector<std::string> listTokens(const std::string& tokens_path, bool& ok)
{
    ok = false;
    FileLock lock(tokens_path + ".lock", LOCK_SH);      // 读锁：与追加/替换互斥（spec 6.3）
    if (!lock.ok()) return {};
    std::ifstream fin(tokens_path);
    ok = true;                                          // 文件不存在 = 还没有令牌，空列表不算错
    std::vector<std::string> out;
    std::string line;
    while (std::getline(fin, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        if (!line.empty()) out.push_back(line);
    }
    return out;
}

bool appendTokens(const std::string& tokens_path, int count, std::vector<std::string>& out)
{
    FileLock lock(tokens_path + ".lock", LOCK_EX);      // spec 6.2：复制 main.cpp 块时唯一不可省略的就是这把锁
    if (!lock.ok()) return false;
    FILE* f = std::fopen(tokens_path.c_str(), "a");     // 追加模式，与 main.cpp --gen-token 同款
    if (f == nullptr) return false;
    for (int i = 0; i < count; ++i) {
        const std::string tok = generate_register_token();   // 复用 Crypt 现成符号，不重写算法（spec 6.1）
        std::fprintf(f, "%s\n", tok.c_str());
        out.push_back(tok);
    }
    std::fclose(f);
    return true;
}

// spec 4.4/6.3：flock 持有期间 读全表 → 过滤 → 临时文件 → rename 原子替换，
// 与 UDP::file_remove_line 同款语义（含 fflush/fsync）
// 返回：1 = 删了，0 = 没找到，-1 = IO 失败
int removeToken(const std::string& tokens_path, const std::string& token)
{
    FileLock lock(tokens_path + ".lock", LOCK_EX);
    if (!lock.ok()) return -1;
    FILE* src = std::fopen(tokens_path.c_str(), "r");
    if (src == nullptr) return 0;                       // 文件不存在 = 还没有令牌
    std::vector<std::string> keep;
    bool found = false;
    char buf[512] = {0};
    while (std::fgets(buf, sizeof(buf), src) != nullptr) {
        std::string s(buf);
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
        if (!found && s == token) { found = true; continue; }   // 跳过要删的行
        keep.push_back(s);
    }
    std::fclose(src);
    if (!found) return 0;
    const std::string tmp = tokens_path + ".tmp." + std::to_string(::getpid());
    FILE* dst = std::fopen(tmp.c_str(), "w");
    if (dst == nullptr) return -1;
    bool ok = true;
    for (const auto& s : keep) {
        if (std::fprintf(dst, "%s\n", s.c_str()) < 0) { ok = false; break; }
    }
    if (std::fflush(dst) != 0) ok = false;
    if (ok && ::fsync(fileno(dst)) != 0) ok = false;
    std::fclose(dst);
    if (!ok) { ::unlink(tmp.c_str()); return -1; }
    if (::rename(tmp.c_str(), tokens_path.c_str()) != 0) {
        ::unlink(tmp.c_str());
        return -1;
    }
    return 1;
}

// ============ 公钥：PEM 原文 + 原始公钥转 64 hex（spec 9） ============
bool readPubkey(const std::string& pem_path, std::string& pem_out, std::string& hex_out)
{
    std::ifstream fin(pem_path, std::ios::binary);
    if (!fin) return false;                             // 文件不存在：调用方回 null 字段（spec 4.1）
    std::ostringstream ss;
    ss << fin.rdbuf();
    pem_out = ss.str();

    EVP_PKEY* pkey = nullptr;
    try {
        pkey = load_ed25519_public_key(pem_path);       // Crypt 现成的加载函数
    } catch (const std::exception& e) {                 // 注意：它失败时是抛异常，不是返回 nullptr！
        std::cerr << "[admin] load pubkey failed: " << e.what() << std::endl;
        return false;
    }
    unsigned char raw[64];
    size_t raw_len = sizeof(raw);                       // 入/出双用参数：传入必须是缓冲区大小！
    const bool ok = EVP_PKEY_get_raw_public_key(pkey, raw, &raw_len) == 1;
    EVP_PKEY_free(pkey);                                // load 出来的必须自己还
    if (!ok) return false;
    static const char* hexd = "0123456789abcdef";
    for (size_t i = 0; i < raw_len; ++i) {
        hex_out += hexd[raw[i] >> 4];
        hex_out += hexd[raw[i] & 0xF];
    }
    return true;
}

// ============ 管理令牌：env ADMIN_TOKEN > 文件 > 自动生成落盘 0600（spec 7） ============
// 日志只记来源，令牌值绝不进日志/终端——它等于发准入资格的权限
std::string loadOrCreateAdminToken(const std::string& keys_dir)
{
    if (const char* env = std::getenv("ADMIN_TOKEN")) {
        std::cout << "AdminServer: 管理令牌来自 ADMIN_TOKEN 环境变量" << std::endl;
        return env;
    }
    const std::string path = keys_dir + "/admin_token.txt";
    if (std::ifstream fin{path}) {                      // 条件里声明只能用 {} 初始化，圆括号会被当函数声明
        std::string t;
        std::getline(fin, t);
        while (!t.empty() && (t.back() == '\r' || t.back() == '\n')) t.pop_back();
        if (!t.empty()) {
            std::cout << "AdminServer: 管理令牌来自 " << path << std::endl;
            return t;
        }
    }
    const std::string t = generate_register_token();    // 64 hex，与注册令牌同源（spec 6.1）
    if (FILE* f = std::fopen(path.c_str(), "w")) {
        std::fprintf(f, "%s\n", t.c_str());
        std::fclose(f);
        ::chmod(path.c_str(), 0600);                    // spec 7：落盘必须 0600
        std::cout << "AdminServer: 已生成管理令牌写入 " << path << "（0600）" << std::endl;
    } else {
        std::cerr << "AdminServer: 管理令牌写盘失败（" << strerror(errno)
                  << "），仅本次进程内有效" << std::endl;
    }
    return t;
}

// 审计日志（spec 7 五件套之一）：申请（数量）/删除（指纹前 8 位）/鉴权失败 都留痕
// 一期与 vpn-server 日志同放 logs/；单线程事件循环里写，无并发问题
void appendAudit(const std::string& ip, const std::string& action)
{
    char ts[32] = {0};
    const std::time_t now = std::time(nullptr);
    std::strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    std::ofstream f("logs/admin_audit.log", std::ios::app);
    if (f)
        f << ts << '\t' << ip << '\t' << action << '\n';
    else
        std::cerr << "[audit] 写入 logs/admin_audit.log 失败" << std::endl;
}

// ============ 内置管理页（spec 4.5/5.1）：单页 HTML+JS，零外部依赖 ============
// 页面公开访问，令牌存 localStorage，每个 API 请求带 Bearer，401 时重新弹出
constexpr const char* kAdminPage = R"HTML(<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ScholarVPN 服务器管理</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;max-width:640px;margin:24px auto;padding:0 12px;color:#1a1a1a;background:#fafafa}
h1{font-size:20px}
fieldset{border:1px solid #ddd;border-radius:8px;margin:0 0 16px;padding:12px;background:#fff}
legend{font-weight:600;padding:0 6px}
.row{display:flex;gap:8px;align-items:center;margin:6px 0;flex-wrap:wrap}
.mono{font-family:ui-monospace,Menlo,monospace;font-size:13px;word-break:break-all}
button{cursor:pointer;padding:2px 10px}
input[type=number]{width:64px;padding:2px 4px}
.tok{display:flex;justify-content:space-between;gap:8px;align-items:center;padding:4px 6px;border-bottom:1px solid #eee}
.tok:last-child{border-bottom:none}
.fresh{background:#fff3c4}
.err{color:#b00;font-size:13px;min-height:16px;margin-left:8px}
pre{white-space:pre-wrap;margin:6px 0}
</style>
</head>
<body>
<h1>ScholarVPN 服务器管理</h1>
<fieldset><legend>服务器信息</legend>
<div class="row"><span>公钥</span><span id="pubhex" class="mono">加载中…</span><button data-copy="pubhex">复制</button></div>
<details><summary>PEM</summary><pre id="pubpem" class="mono"></pre><button data-copy="pubpem">复制 PEM</button></details>
<div class="row"><span>IP</span><span id="ip" class="mono">-</span><span>端口</span><span id="port" class="mono">-</span></div>
</fieldset>
<fieldset><legend>注册令牌</legend>
<div class="row">数量 <input id="count" type="number" min="1" max="1000" value="5"><button id="gen">申请</button><span id="msg" class="err"></span></div>
<div id="tokens">加载中…</div>
</fieldset>
<script>
const TKEY='admin_token';
function getToken(){
  let t=localStorage.getItem(TKEY);
  if(!t){t=prompt('请输入管理令牌');if(t)t=t.trim();}
  if(t)localStorage.setItem(TKEY,t);
  return t;
}
function msg(s){document.getElementById('msg').textContent=s||'';}
async function api(method,path,body){
  const t=getToken();
  if(!t)throw new Error('需要管理令牌');
  const opt={method,headers:{'Authorization':'Bearer '+t}};
  if(body!==undefined)opt.body=JSON.stringify(body);
  const r=await fetch(path,opt);
  if(r.status===401){
    localStorage.removeItem(TKEY);
    if(confirm('管理令牌无效，重新输入？'))return api(method,path,body);
    throw new Error('未授权');
  }
  const j=await r.json().catch(()=>({}));
  if(!r.ok)throw new Error(j.error||('HTTP '+r.status));
  return j;
}
async function loadInfo(){
  try{
    const r=await fetch('/api/info');
    const j=await r.json();
    document.getElementById('pubhex').textContent=j.pubkey_hex||'未找到公钥文件';
    document.getElementById('pubpem').textContent=j.pubkey_pem||'';
    document.getElementById('ip').textContent=j.ip??'-';
    document.getElementById('port').textContent=j.port??'-';
  }catch(e){document.getElementById('pubhex').textContent='加载失败';}
}
let fresh=new Set();
async function loadTokens(){
  const box=document.getElementById('tokens');
  box.textContent='加载中…';
  try{
    const j=await api('GET','/api/tokens');
    box.textContent='';
    if(!j.tokens||!j.tokens.length){box.textContent='（暂无未消费令牌）';return;}
    for(const t of j.tokens){
      const row=document.createElement('div');
      row.className='tok'+(fresh.has(t)?' fresh':'');
      const span=document.createElement('span');span.className='mono';span.textContent=t;
      const btn=document.createElement('button');btn.textContent='删除';
      btn.onclick=async()=>{try{await api('DELETE','/api/tokens/'+t);fresh.delete(t);await loadTokens();}catch(e){msg(e.message);}};
      row.append(span,btn);box.append(row);
    }
  }catch(e){box.textContent='';msg(e.message);}
}
document.getElementById('gen').onclick=async()=>{
  msg('');
  const n=parseInt(document.getElementById('count').value,10);
  try{
    const j=await api('POST','/api/tokens',{count:n});
    fresh=new Set(j.tokens||[]);
    await loadTokens();
    msg('已生成 '+fresh.size+' 个');
  }catch(e){msg(e.message);}
};
document.querySelectorAll('[data-copy]').forEach(b=>b.onclick=()=>{
  navigator.clipboard.writeText(document.getElementById(b.dataset.copy).textContent);
});
loadInfo();loadTokens();
</script>
</body>
</html>
)HTML";
}  // namespace

void AdminServer::closeConn(int fd)
{
    auto it = conns.find(fd);
    if(it == conns.end()){
        close(fd);                        // 不在连接表里（残留事件）：fd 只能在这里还
        return;
    }
    epoll_ctl(m_epfd, EPOLL_CTL_DEL, fd, nullptr);   // 先摘 epoll，再让 Session 析构去 close
    conns.erase(it);
}

// 节拍清扫（5s 一拍）：读超时连接 + 过期的限速窗口（spec 7：读写超时 5s）
void AdminServer::sweep()
{
    const time_t now = time(nullptr);
    std::vector<int> idle;
    for (const auto& kv : conns)
        if (now - kv.second->last_active >= kTimeoutMs / 1000)   // 一直不发数据的连接：读超时
            idle.push_back(kv.first);
    for (int fd : idle)                   // 先收集再关，避免边遍历边 erase
        closeConn(fd);
    for (auto it = auth_fails.begin(); it != auth_fails.end(); ) {
        if (now - it->second.first >= kAuthWindowSec)
            it = auth_fails.erase(it);    // 限速窗口过了：整条记录清掉
        else
            ++it;
    }
}

AdminServer::AdminServer()
{
}

AdminServer::~AdminServer()
{
    if(m_fd >= 0){
        close(m_fd);
        m_fd = -1;
    }
    if(m_epfd >= 0){
        close(m_epfd);
        m_epfd = -1;
    }
    // conns 是 unique_ptr 表：随对象销毁自动逐个 Session 析构 → close，无 fd 泄漏
}

bool AdminServer::start(std::string ip, int port)
{
    if(m_fd >= 0){
        std::cerr << "AdminServer 已启动，不能重复 start" << std::endl;
        return false;
    }
    m_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if(m_fd < 0){
        std::cerr << "socket failed: " << strerror(errno) << std::endl;
        return false;
    }
    m_ip = ip;
    m_port = port;
    const int flags = fcntl(m_fd, F_GETFL, 0);
    if(flags < 0 || fcntl(m_fd, F_SETFL, flags | O_NONBLOCK) < 0){
        // 失败必须中止：fd 若保持阻塞，runloop 的 accept 循环会卡死在第二次 accept
        std::cerr << "fcntl failed: " << strerror(errno) << std::endl;
        close(m_fd);
        m_fd = -1;
        return false;
    }
    int opt = 1;
    if(setsockopt(m_fd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt)) < 0){
        // 只少了个"重启免等 TIME_WAIT"的便利，不值得为它中止启动
        std::cerr << "setsockopt SO_REUSEADDR failed: " << strerror(errno) << std::endl;
    }
    memset(&serv,0,sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_port = htons(static_cast<uint16_t>(port));
    if(ip == "0.0.0.0"){
        serv.sin_addr.s_addr = INADDR_ANY;
    }else{
        // inet_pton 第一个参数是地址族 AF_INET，不是 fd；失败返回 <= 0 且不动 sin_addr
        if(inet_pton(AF_INET,ip.c_str(),&serv.sin_addr) <= 0){
            std::cerr << "IP地址格式错误: " << ip << std::endl;
            close(m_fd);
            m_fd = -1;
            return false;
        }
    }
    if(bind(m_fd,(sockaddr*)&serv,sizeof(serv)) < 0){
        std::cerr << "bind failed: " << strerror(errno) << "（端口被占用？）" << std::endl;
        close(m_fd);
        m_fd = -1;
        return false;
    }
    if(listen(m_fd,kListenBacklog) < 0){
        std::cerr << "listen failed: " << strerror(errno) << std::endl;
        close(m_fd);
        m_fd = -1;
        return false;
    }
    m_epfd = epoll_create1(EPOLL_CLOEXEC);
    if(m_epfd < 0){
        std::cerr << "create epoll failed: " << strerror(errno) << std::endl;
        close(m_fd);
        m_fd = -1;
        return false;
    }
    // listen fd 也要进 epoll：它"可读"的含义不是来了数据，是有新连接
    struct epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = m_fd;
    if(epoll_ctl(m_epfd,EPOLL_CTL_ADD,m_fd,&ev) < 0){
        std::cerr << "epoll add failed: " << strerror(errno) << std::endl;
        close(m_epfd);                    // 这条失败路径上 epfd 已经开了，要一起还
        m_epfd = -1;
        close(m_fd);
        m_fd = -1;
        return false;
    }

    // spec 7：一期是明文 HTTP，只允许环回/SSH 隧道；绑非环回必须横幅告警
    if(ip != "127.0.0.1" && ip != "::1"){
        std::cerr << "警告：管理端口绑定在非环回地址 " << ip
                  << "，明文 HTTP 有泄露风险，务必置于 SSH 隧道/防火墙之后" << std::endl;
    }
    tokens_path = keys_dir + "/register_tokens.txt";    // 路径统一按 keys_dir 推导（spec 第 6 节）
    pubkey_path = keys_dir + "/server_sig.pub";
    admin_token = loadOrCreateAdminToken(keys_dir);     // env > 文件 > 自动生成落盘 0600（spec 7）
    if(admin_token.empty()){                            // 没有令牌 = 鉴权全拒，不能带病运行
        std::cerr << "AdminServer: 管理令牌不可用，启动中止" << std::endl;
        close(m_epfd);
        m_epfd = -1;
        close(m_fd);
        m_fd = -1;
        return false;
    }

    m_isrunning = true;
    std::cout << "Server start, ip:" << ip << " port:" << port << std::endl;
    return true;
}

void AdminServer::runloop()
{
    struct epoll_event events[kMaxEvents];

    // ---- 服务一条已有连接：recv 累积 → 收齐 → 限速/路由 → 回包 → 关（Connection: close）----
    // （EPOLLERR/EPOLLHUP 在外层已处理，进到这里的一定是 EPOLLIN）
    auto handleConn = [this](int fd, Session& conn) {
        conn.last_active = time(nullptr);       // 有动静就续命；读超时由 sweep 判
        bool close_it = false;
        bool peer_closed = false;               // 对端发了 FIN：请求可能已经发完了才半关

        char tmp[4096];
        while (!close_it) {                     // 非阻塞：一轮读到 EAGAIN，不让一条连接霸占循环
            const ssize_t nr = recv(fd, tmp, sizeof(tmp), 0);
            if (nr > 0) {
                conn.s_recvbuf.append(tmp, static_cast<size_t>(nr));
                if (conn.s_recvbuf.size() > kMaxRequest) {         // 8KB 上限：头没收齐也挡得住
                    sendAll(fd, makeResponse(413, "{\"error\":\"request too large\"}"));
                    close_it = true;
                }
                continue;
            }
            if (nr == 0) { peer_closed = true; break; }            // 对端关闭：缓冲里可能已有完整请求
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;    // 这轮数据读干净了
            if (errno == EINTR) continue;
            close_it = true;                                       // ECONNRESET 等真错误
            break;
        }

        if (!close_it) {
            HttpRequest req;
            const int r = parseRequest(conn.s_recvbuf, req);
            if (r == 0) {
                // 没收全：对端还在就继续等（读超时由 sweep 兜底）；对端已走就只能放弃
                close_it = peer_closed;
            } else if (r == 2) {                    // 格式错误 / 不支持的方法：400（spec 9）
                sendAll(fd, makeResponse(400, "{\"error\":\"bad request\"}"));
                close_it = true;
            } else if (r == 3) {                    // Content-Length 声明超限：413
                sendAll(fd, makeResponse(413, "{\"error\":\"request too large\"}"));
                close_it = true;
            } else if (authBlocked(conn.ip)) {      // 限速拉黑：进业务前静默丢弃（spec 7）
                close_it = true;
            } else if (req.method == "GET" && req.path == "/") {
                // 内置管理页（spec 4.5/8.1）：公开访问，页面内再鉴权
                sendAll(fd, makeResponse(200, kAdminPage, "text/html; charset=utf-8"));
                close_it = true;
            } else {
                const HttpReply rep = onRequest(req, conn.ip);     // 业务插口：四个 API（spec 第 4 节）
                sendAll(fd, makeResponse(rep.status, rep.body));
                close_it = true;                    // Connection: close：回完就关，客户端 recv==0 靠它收尾
            }
        }

        if (close_it) closeConn(fd);                // 先摘 epoll 再销毁 Session（析构负责 close fd）
    };

    while(m_isrunning){
        sweep();                                // 每拍先清扫：读超时连接、过期的限速窗口

        int n = epoll_wait(m_epfd,events,kMaxEvents,kTimeoutMs);
        if(n == 0){
            continue;                     // 超时没人来：回去看一眼 m_isrunning 再睡
        }
        if(n < 0){
            if(errno == EINTR) continue;  // 被信号打断不算失败
            std::cerr << "epoll_wait failed: " << strerror(errno) << std::endl;
            break;
        }
        for(int i = 0; i < n;i++){
            int fd = events[i].data.fd;
            uint32_t revents = events[i].events;
            if(revents & (EPOLLERR | EPOLLHUP)){
                closeConn(fd);            // 用 closeConn 而不是裸 close：连接表里的 Session 要同步销毁，
                continue;                 // 否则留下悬挂 unique_ptr，之后 closeConn 会对同一 fd close 两次
            }
            if(fd == m_fd && (revents & EPOLLIN)){
                while(true){              // 一次可能积压多个连接：accept 到 EAGAIN 为止
                    sockaddr_in clt{};
                    socklen_t clt_len = sizeof(clt);
                    // accept 出来的 fd 不继承监听 fd 的 O_NONBLOCK，必须自己设——
                    // accept4 一步顶 accept+fcntl：SOCK_NONBLOCK 非阻塞 + SOCK_CLOEXEC 防 exec 带走
                    int client_id = accept4(m_fd,(sockaddr*)&clt,&clt_len,SOCK_NONBLOCK | SOCK_CLOEXEC);
                    if(client_id < 0){
                        if(errno == EAGAIN || errno == EWOULDBLOCK) break;    // 都接完了
                        if(errno == EINTR || errno == ECONNABORTED) continue; // 信号打断/对端提前掉线 不算事故
                        // 注：fd 耗尽（EMFILE/ENFILE）时 level-trigger 每轮都会再叫醒这里，之后要防忙转
                        std::cerr << "accept failed: " << strerror(errno) << std::endl;
                        break;
                    }
                    char ipbuf[INET_ADDRSTRLEN]{};
                    // inet_ntop 可重入；inet_ntoa 返回的是静态缓冲，多连接会互相覆盖
                    const char* ipstr = inet_ntop(AF_INET,&clt.sin_addr,ipbuf,sizeof(ipbuf));
                    const uint16_t cport = ntohs(clt.sin_port);
                    auto conn = std::make_unique<Session>();
                    conn->fd = client_id;
                    conn->ip = ipstr ? ipstr : "unknown";
                    conn->port = cport;
                    conn->is_running = true;
                    conn->last_active = time(nullptr);

                    struct epoll_event ev{};
                    ev.data.fd = client_id;
                    ev.events = EPOLLIN;
                    if(epoll_ctl(m_epfd,EPOLL_CTL_ADD,client_id,&ev) < 0){
                        std::cerr << "epoll add client failed: " << strerror(errno) << std::endl;
                        continue;         // 不手动 close：conns 没接手，conn 离开作用域时
                                          // Session 析构会关 fd——手动关 + 析构关就是 double close
                    }
                    conns[client_id] = std::move(conn);
                    std::cout << "new client: " << (ipstr ? ipstr : "unknown") << std::endl;
                }
            }
            else if (revents & EPOLLIN)
            {
                auto it = conns.find(fd);
                if(it == conns.end()) continue;   // 本批次早前已关掉的连接：残留事件直接跳过
                handleConn(fd, *it->second);
            }
        }
    }
}

// Bearer 鉴权：CRYPTO_memcmp 常量时间比较，防时序侧信道（spec 7）
bool AdminServer::checkAuth(const HttpRequest& req)
{
    if (admin_token.empty()) return false;      // 没配令牌 = 全部拒绝，绝不放空令牌进来
    auto it = req.headers.find("authorization");
    if (it == req.headers.end()) return false;
    const std::string& v = it->second;
    if (v.rfind("Bearer ", 0) != 0) return false;
    const std::string given = v.substr(kBearerPrefixLen);
    if (given.size() != admin_token.size()) return false;   // CRYPTO_memcmp 只收等长；长度不同直接否
    return CRYPTO_memcmp(given.data(), admin_token.data(), admin_token.size()) == 0;
}

void AdminServer::noteAuthFail(const std::string& ip)
{
    const time_t now = time(nullptr);
    auto& slot = auth_fails[ip];                // 不存在就建：{窗口起点, 失败次数}
    if (now - slot.first >= kAuthWindowSec) {   // 旧窗口已过期：开新窗口重新计数
        slot.first = now;
        slot.second = 1;
    } else {
        ++slot.second;
    }
}

bool AdminServer::authBlocked(const std::string& ip)
{
    auto it = auth_fails.find(ip);
    if (it == auth_fails.end()) return false;
    const time_t now = time(nullptr);
    return it->second.second >= kAuthFailLimit &&        // 窗口内失败满 kAuthFailLimit 次
           now - it->second.first < kAuthWindowSec;      // 且窗口还没过（过了 sweep 会清）
}

// ============ 业务层：四个 API 路由（spec 第 4 节） ============
// spec 8.1：这块将来抽成 Admin/AdminCore（传输无关），本地 HTTP 与二期 agent 通道共用；
// 现在 AdminCore 还没建目录，先以 onRequest 子类形式落在本文件夹
class AdminService final : public AdminServer {
public:
    explicit AdminService(const std::string& keys_dir)
        : tokens_path_(keys_dir + "/register_tokens.txt"),
          pubkey_path_(keys_dir + "/server_sig.pub") {}

    // /api/info 展示的数据面监听信息（spec 4.1）。基类的 vpn_ip/vpn_port 是私有成员
    //（预留给内嵌 vpn_server 形态传 Config），独立运行时业务侧自持一份
    std::string vpn_ip_ = "0.0.0.0";
    int vpn_port_ = 51820;

protected:
    HttpReply onRequest(const HttpRequest& req, const std::string& ip) override {
        // GET /api/info 公开：公钥/监听信息本就是给客户端连的公开信息（spec 4.1）
        if (req.method == "GET" && req.path == "/api/info") return apiInfo();
        // 其余三个接口都要 Bearer；失败喂限速器 + 审计（spec 7）
        if (!checkAuth(req)) {
            noteAuthFail(ip);               // 5 次/分钟，超限后由框架进业务前静默拉黑
            appendAudit(ip, "auth_fail " + req.method + " " + req.path);
            return {401, "{\"error\":\"unauthorized\"}"};
        }
        if (req.method == "GET" && req.path == "/api/tokens") return apiList();
        if (req.method == "POST" && req.path == "/api/tokens") return apiGen(req, ip);
        if (req.method == "DELETE" && req.path.rfind("/api/tokens/", 0) == 0) return apiDel(req, ip);
        if (req.path.rfind("/api/", 0) == 0) {
            // 认识的路径但方法不对 → 405；纯未知路径 → 404（spec 9：路由精确到方法+路径）
            const bool known = req.path == "/api/info" || req.path == "/api/tokens"
                            || req.path.rfind("/api/tokens/", 0) == 0;
            if (known) return {405, "{\"error\":\"method not allowed\"}"};
        }
        return {404, "{\"error\":\"not found\"}"};
    }

private:
    std::string tokens_path_;
    std::string pubkey_path_;

    HttpReply apiInfo() const {
        std::string pem, hex;
        std::string pk = "\"pubkey_pem\":null,\"pubkey_hex\":null";   // 公钥缺失回 null（spec 4.1/9）
        if (readPubkey(pubkey_path_, pem, hex))
            pk = "\"pubkey_pem\":\"" + jsonEscape(pem) + "\",\"pubkey_hex\":\"" + hex + "\"";
        return {200, "{\"version\":\"1.0\"," + pk +
                     ",\"ip\":\"" + jsonEscape(vpn_ip_) +
                     "\",\"port\":" + std::to_string(vpn_port_) + "}"};
    }

    HttpReply apiList() const {
        bool ok = false;
        const std::vector<std::string> toks = listTokens(tokens_path_, ok);
        if (!ok) return {500, "{\"error\":\"read tokens failed\"}"};
        std::string body = "{\"tokens\":[";
        for (size_t i = 0; i < toks.size(); ++i) {
            if (i) body += ",";
            body += "\"" + toks[i] + "\"";      // 令牌是 64 hex，不需要转义
        }
        return {200, body + "]}"};
    }

    HttpReply apiGen(const HttpRequest& req, const std::string& ip) {
        const int count = parseCount(req.body);
        if (count < 0) return {400, "{\"error\":\"count must be 1-1000\"}"};   // spec 4.3：1..1000 与 CLI 一致
        std::vector<std::string> fresh;
        if (!appendTokens(tokens_path_, count, fresh))
            return {500, "{\"error\":\"append tokens failed\"}"};
        appendAudit(ip, "gen count=" + std::to_string(count));  // spec 7：申请留痕
        std::string body = "{\"tokens\":[";
        for (size_t i = 0; i < fresh.size(); ++i) {
            if (i) body += ",";
            body += "\"" + fresh[i] + "\"";
        }
        return {200, body + "]}"};
    }

    HttpReply apiDel(const HttpRequest& req, const std::string& ip) {
        const std::string token = req.path.substr(12);          // 掐掉 "/api/tokens/"
        const int r = removeToken(tokens_path_, token);
        if (r < 0) return {500, "{\"error\":\"remove failed\"}"};
        if (r == 0) return {404, "{\"error\":\"token not found\"}"};   // 可能已被消费（spec 4.4）
        appendAudit(ip, "del token=" + token.substr(0, 8) + "...");    // spec 7：记指纹前 8 位
        return {200, "{\"deleted\":true}"};
    }

    // body 形如 {"count":5}——只提取这一个固定字段，严格校验范围
    static int parseCount(const std::string& body)              // -1 = 非法
    {
        const size_t k = body.find("\"count\"");
        if (k == std::string::npos) return -1;
        const size_t c = body.find(':', k);
        if (c == std::string::npos) return -1;
        size_t i = c + 1;
        while (i < body.size() && (body[i] == ' ' || body[i] == '\t')) i++;
        if (i >= body.size() || !std::isdigit(static_cast<unsigned char>(body[i]))) return -1;
        char* end = nullptr;
        const long v = std::strtol(body.c_str() + i, &end, 10);
        if (end == body.c_str() + i || v < 1 || v > 1000) return -1;
        return static_cast<int>(v);
    }
};

int main()
{
    ::umask(077);   // 与 main.cpp 同款：令牌/审计等敏感文件一律 0600

    // 配置全部可用环境变量覆盖（spec 10 的 start.sh 透传约定），默认值与任务书一致
    std::string bind_ip = "127.0.0.1";
    int port = 18080;
    std::string keys_dir = "keys";
    std::string vpn_ip = "0.0.0.0";
    int vpn_port = 51820;
    if (const char* e = std::getenv("ADMIN_BIND")) bind_ip = e;
    if (const char* e = std::getenv("ADMIN_PORT")) port = std::atoi(e);
    if (const char* e = std::getenv("KEYS_DIR"))   keys_dir = e;
    if (const char* e = std::getenv("VPN_IP"))     vpn_ip = e;
    if (const char* e = std::getenv("VPN_PORT"))   vpn_port = std::atoi(e);
    if (port <= 0 || port > 65535) {
        std::cerr << "ADMIN_PORT 非法，用默认 18080" << std::endl;
        port = 18080;
    }

    // keys 目录不存在就建（与 main.cpp --gen-token 同款）；审计日志目录同理由
    std::error_code ec;
    std::filesystem::create_directories(keys_dir, ec);
    std::filesystem::create_directories("logs", ec);

    AdminService svc(keys_dir);
    svc.vpn_ip_ = vpn_ip;
    svc.vpn_port_ = vpn_port;
    svc.set_keys_dir(keys_dir);
    if (!svc.start(bind_ip, port)) return 1;
    svc.runloop();
    return 0;
}
