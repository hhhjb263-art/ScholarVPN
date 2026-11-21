#include "AdminServer.h"
#include "../Crypt/crypt.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <cstdlib>
#include <cstdio>
#include <cctype>
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
#include <poll.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <openssl/crypto.h>

struct HttpRequest {
    std::string method;
    std::string path;
    std::string version;
    std::string body;
    std::unordered_map<std::string, std::string> headers;
};

namespace {
constexpr int kMaxEvents = 16;
constexpr int kListenBacklog = 10;
constexpr size_t kMaxRequest = 8192;
constexpr int kTimeoutMs = 5000;
constexpr int kAuthFailLimit = 5;
constexpr int    kAuthWindowSec   = 60;
constexpr size_t kBearerPrefixLen = 7;

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

int parseRequest(const std::string& raw, HttpRequest& req)
{
    const size_t header_end = raw.find("\r\n\r\n");
    if (header_end == std::string::npos) return 0;

    const size_t line1_end = raw.find("\r\n");
    if (line1_end == std::string::npos) return 2;
    const std::string line1 = raw.substr(0, line1_end);
    const size_t sp1 = line1.find(' ');
    const size_t sp2 = line1.find(' ', sp1 + 1);
    if (sp1 == std::string::npos || sp2 == std::string::npos) return 2;
    req.method  = line1.substr(0, sp1);
    req.path    = line1.substr(sp1 + 1, sp2 - sp1 - 1);
    req.version = line1.substr(sp2 + 1);
    if (req.version.rfind("HTTP/", 0) != 0) return 2;
    if (req.method != "GET" && req.method != "POST" && req.method != "DELETE")
        return 2;

    size_t pos = line1_end + 2;
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
            while (v < hline.size() && hline[v] == ' ') v++;
            req.headers[key] = hline.substr(v);
        }
        pos = line_end + 2;
    }

    long long cl = 0;
    if (auto it = req.headers.find("content-length"); it != req.headers.end())
        cl = atoll(it->second.c_str());
    if (cl < 0) return 2;
    if (static_cast<size_t>(cl) > kMaxRequest) return 3;
    const size_t total = header_end + 4 + static_cast<size_t>(cl);
    if (raw.size() < total) return 0;
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
    res += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    res += "Connection: close\r\n";
    res += "\r\n";
    res += body;
    return res;
}

bool sendAll(int fd, const std::string& data)
{
    size_t off = 0;
    while (off < data.size()) {
        const ssize_t ns = send(fd, data.data() + off, data.size() - off, MSG_NOSIGNAL);
        if (ns > 0) { off += static_cast<size_t>(ns); continue; }
        if (ns < 0 && errno == EINTR) continue;
        if (ns < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            pollfd p{};
            p.fd = fd;
            p.events = POLLOUT;
            if (poll(&p, 1, kTimeoutMs) <= 0) return false;
            continue;
        }
        return false;
    }
    return true;
}

class FileLock {
public:
    FileLock(const std::string& lock_path, int op) {
        fd_ = ::open(lock_path.c_str(), O_CREAT | O_RDWR, 0600);
        if (fd_ >= 0 && ::flock(fd_, op) != 0) { ::close(fd_); fd_ = -1; }
    }
    ~FileLock() {
        if (fd_ >= 0) { ::flock(fd_, LOCK_UN); ::close(fd_); }
    }
    bool ok() const { return fd_ >= 0; }
    FileLock(const FileLock&) = delete;
    FileLock& operator=(const FileLock&) = delete;
private:
    int fd_ = -1;
};

std::vector<std::string> listTokens(const std::string& tokens_path, bool& ok)
{
    ok = false;
    FileLock lock(tokens_path + ".lock", LOCK_SH);
    if (!lock.ok()) return {};
    std::ifstream fin(tokens_path);
    ok = true;
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
    FileLock lock(tokens_path + ".lock", LOCK_EX);
    if (!lock.ok()) return false;
    FILE* f = std::fopen(tokens_path.c_str(), "a");
    if (f == nullptr) return false;
    for (int i = 0; i < count; ++i) {
        const std::string tok = generate_register_token();
        std::fprintf(f, "%s\n", tok.c_str());
        out.push_back(tok);
    }
    std::fclose(f);
    return true;
}

int removeToken(const std::string& tokens_path, const std::string& token)
{
    FileLock lock(tokens_path + ".lock", LOCK_EX);
    if (!lock.ok()) return -1;
    FILE* src = std::fopen(tokens_path.c_str(), "r");
    if (src == nullptr) return 0;
    std::vector<std::string> keep;
    bool found = false;
    char buf[512] = {0};
    while (std::fgets(buf, sizeof(buf), src) != nullptr) {
        std::string s(buf);
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
        if (!found && s == token) { found = true; continue; }
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

bool readPubkey(const std::string& pem_path, std::string& pem_out, std::string& hex_out)
{
    std::ifstream fin(pem_path, std::ios::binary);
    if (!fin) return false;
    std::ostringstream ss;
    ss << fin.rdbuf();
    pem_out = ss.str();

    EVP_PKEY* pkey = nullptr;
    try {
        pkey = load_ed25519_public_key(pem_path);
    } catch (const std::exception& e) {
        std::cerr << "[admin] load pubkey failed: " << e.what() << std::endl;
        return false;
    }
    unsigned char raw[64];
    size_t raw_len = sizeof(raw);
    const bool ok = EVP_PKEY_get_raw_public_key(pkey, raw, &raw_len) == 1;
    EVP_PKEY_free(pkey);
    if (!ok) return false;
    static const char* hexd = "0123456789abcdef";
    for (size_t i = 0; i < raw_len; ++i) {
        hex_out += hexd[raw[i] >> 4];
        hex_out += hexd[raw[i] & 0xF];
    }
    return true;
}

std::string loadOrCreateAdminToken(const std::string& keys_dir)
{
    if (const char* env = std::getenv("ADMIN_TOKEN")) {
        std::cout << "AdminServer: 管理令牌来自 ADMIN_TOKEN 环境变量" << std::endl;
        return env;
    }
    const std::string path = keys_dir + "/admin_token.txt";
    if (std::ifstream fin{path}) {
        std::string t;
        std::getline(fin, t);
        while (!t.empty() && (t.back() == '\r' || t.back() == '\n')) t.pop_back();
        if (!t.empty()) {
            std::cout << "AdminServer: 管理令牌来自 " << path << std::endl;
            return t;
        }
    }
    const std::string t = generate_register_token();
    if (FILE* f = std::fopen(path.c_str(), "w")) {
        std::fprintf(f, "%s\n", t.c_str());
        std::fclose(f);
        ::chmod(path.c_str(), 0600);
        std::cout << "AdminServer: 已生成管理令牌写入 " << path << "（0600）" << std::endl;
    } else {
        std::cerr << "AdminServer: 管理令牌写盘失败（" << strerror(errno)
                  << "），仅本次进程内有效" << std::endl;
    }
    return t;
}

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
<div class="row" style="margin-top:8px"><button id="export">一键导出（公钥 + 令牌）</button></div>
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
document.getElementById('export').onclick=async()=>{
  try{
    const j=await api('GET','/api/export');
    const blob=new Blob([JSON.stringify(j,null,2)],{type:'application/json'});
    const a=document.createElement('a');
    a.href=URL.createObjectURL(blob);
    a.download='scholarvpn-export.json';
    document.body.appendChild(a);a.click();a.remove();
    URL.revokeObjectURL(a.href);
  }catch(e){msg(e.message);}
};
loadInfo();loadTokens();
</script>
</body>
</html>
)HTML";
}

void AdminServer::closeConn(int fd)
{
    auto it = conns.find(fd);
    if(it == conns.end()){
        close(fd);
        return;
    }
    epoll_ctl(m_epfd, EPOLL_CTL_DEL, fd, nullptr);
    conns.erase(it);
}

void AdminServer::sweep()
{
    const time_t now = time(nullptr);
    std::vector<int> idle;
    for (const auto& kv : conns)
        if (now - kv.second->last_active >= kTimeoutMs / 1000)
            idle.push_back(kv.first);
    for (int fd : idle)
        closeConn(fd);
    for (auto it = auth_fails.begin(); it != auth_fails.end(); ) {
        if (now - it->second.first >= kAuthWindowSec)
            it = auth_fails.erase(it);
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
        std::cerr << "fcntl failed: " << strerror(errno) << std::endl;
        close(m_fd);
        m_fd = -1;
        return false;
    }
    int opt = 1;
    if(setsockopt(m_fd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt)) < 0){
        std::cerr << "setsockopt SO_REUSEADDR failed: " << strerror(errno) << std::endl;
    }
    memset(&serv,0,sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_port = htons(static_cast<uint16_t>(port));
    if(ip == "0.0.0.0"){
        serv.sin_addr.s_addr = INADDR_ANY;
    }else{
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
    struct epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = m_fd;
    if(epoll_ctl(m_epfd,EPOLL_CTL_ADD,m_fd,&ev) < 0){
        std::cerr << "epoll add failed: " << strerror(errno) << std::endl;
        close(m_epfd);
        m_epfd = -1;
        close(m_fd);
        m_fd = -1;
        return false;
    }

    if(ip != "127.0.0.1" && ip != "::1"){
        std::cerr << "警告：管理端口绑定在非环回地址 " << ip
                  << "，明文 HTTP 有泄露风险，务必置于 SSH 隧道/防火墙之后" << std::endl;
    }
    tokens_path = keys_dir + "/register_tokens.txt";
    pubkey_path = keys_dir + "/server_sig.pub";
    admin_token = loadOrCreateAdminToken(keys_dir);
    if(admin_token.empty()){
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

    auto handleConn = [this](int fd, Session& conn) {
        conn.last_active = time(nullptr);
        bool close_it = false;
        bool peer_closed = false;

        char tmp[4096];
        while (!close_it) {
            const ssize_t nr = recv(fd, tmp, sizeof(tmp), 0);
            if (nr > 0) {
                conn.s_recvbuf.append(tmp, static_cast<size_t>(nr));
                if (conn.s_recvbuf.size() > kMaxRequest) {
                    sendAll(fd, makeResponse(413, "{\"error\":\"request too large\"}"));
                    close_it = true;
                }
                continue;
            }
            if (nr == 0) { peer_closed = true; break; }
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == EINTR) continue;
            close_it = true;
            break;
        }

        if (!close_it) {
            HttpRequest req;
            const int r = parseRequest(conn.s_recvbuf, req);
            if (r == 0) {
                close_it = peer_closed;
            } else if (r == 2) {
                sendAll(fd, makeResponse(400, "{\"error\":\"bad request\"}"));
                close_it = true;
            } else if (r == 3) {
                sendAll(fd, makeResponse(413, "{\"error\":\"request too large\"}"));
                close_it = true;
            } else if (authBlocked(conn.ip)) {
                close_it = true;
            } else if (req.method == "GET" && req.path == "/") {
                sendAll(fd, makeResponse(200, kAdminPage, "text/html; charset=utf-8"));
                close_it = true;
            } else {
                const HttpReply rep = onRequest(req, conn.ip);
                sendAll(fd, makeResponse(rep.status, rep.body));
                close_it = true;
            }
        }

        if (close_it) closeConn(fd);
    };

    while(m_isrunning){
        sweep();

        int n = epoll_wait(m_epfd,events,kMaxEvents,kTimeoutMs);
        if(n == 0){
            continue;
        }
        if(n < 0){
            if(errno == EINTR) continue;
            std::cerr << "epoll_wait failed: " << strerror(errno) << std::endl;
            break;
        }
        for(int i = 0; i < n;i++){
            int fd = events[i].data.fd;
            uint32_t revents = events[i].events;
            if(revents & (EPOLLERR | EPOLLHUP)){
                closeConn(fd);
                continue;
            }
            if(fd == m_fd && (revents & EPOLLIN)){
                while(true){
                    sockaddr_in clt{};
                    socklen_t clt_len = sizeof(clt);
                    int client_id = accept4(m_fd,(sockaddr*)&clt,&clt_len,SOCK_NONBLOCK | SOCK_CLOEXEC);
                    if(client_id < 0){
                        if(errno == EAGAIN || errno == EWOULDBLOCK) break;
                        if(errno == EINTR || errno == ECONNABORTED) continue;
                        std::cerr << "accept failed: " << strerror(errno) << std::endl;
                        break;
                    }
                    char ipbuf[INET_ADDRSTRLEN]{};
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
                        continue;
                    }
                    conns[client_id] = std::move(conn);
                    std::cout << "new client: " << (ipstr ? ipstr : "unknown") << std::endl;
                }
            }
            else if (revents & EPOLLIN)
            {
                auto it = conns.find(fd);
                if(it == conns.end()) continue;
                handleConn(fd, *it->second);
            }
        }
    }
}

bool AdminServer::checkAuth(const HttpRequest& req)
{
    if (admin_token.empty()) return false;
    auto it = req.headers.find("authorization");
    if (it == req.headers.end()) return false;
    const std::string& v = it->second;
    if (v.rfind("Bearer ", 0) != 0) return false;
    const std::string given = v.substr(kBearerPrefixLen);
    if (given.size() != admin_token.size()) return false;
    return CRYPTO_memcmp(given.data(), admin_token.data(), admin_token.size()) == 0;
}

void AdminServer::noteAuthFail(const std::string& ip)
{
    const time_t now = time(nullptr);
    auto& slot = auth_fails[ip];
    if (now - slot.first >= kAuthWindowSec) {
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
    return it->second.second >= kAuthFailLimit &&
           now - it->second.first < kAuthWindowSec;
}

class AdminService final : public AdminServer {
public:
    explicit AdminService(const std::string& keys_dir)
        : tokens_path_(keys_dir + "/register_tokens.txt"),
          pubkey_path_(keys_dir + "/server_sig.pub") {}

    std::string vpn_ip_ = "0.0.0.0";
    int vpn_port_ = 51820;

protected:
    HttpReply onRequest(const HttpRequest& req, const std::string& ip) override {
        if (req.method == "GET" && req.path == "/api/info") return apiInfo();
        if (!checkAuth(req)) {
            noteAuthFail(ip);
            appendAudit(ip, "auth_fail " + req.method + " " + req.path);
            return {401, "{\"error\":\"unauthorized\"}"};
        }
        if (req.method == "GET" && req.path == "/api/tokens") return apiList();
        if (req.method == "GET" && req.path == "/api/export") return apiExport();
        if (req.method == "POST" && req.path == "/api/tokens") return apiGen(req, ip);
        if (req.method == "DELETE" && req.path.rfind("/api/tokens/", 0) == 0) return apiDel(req, ip);
        if (req.path.rfind("/api/", 0) == 0) {
            const bool known = req.path == "/api/info" || req.path == "/api/tokens"
                            || req.path == "/api/export"
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
        std::string pk = "\"pubkey_pem\":null,\"pubkey_hex\":null";
        if (readPubkey(pubkey_path_, pem, hex))
            pk = "\"pubkey_pem\":\"" + jsonEscape(pem) + "\",\"pubkey_hex\":\"" + hex + "\"";
        return {200, "{\"version\":\"1.0\"," + pk +
                     ",\"ip\":\"" + jsonEscape(vpn_ip_) +
                     "\",\"port\":" + std::to_string(vpn_port_) + "}"};
    }

    HttpReply apiExport() const {
        std::string pem, hex;
        std::string pk = "\"pubkey_pem\":null,\"pubkey_hex\":null";
        if (readPubkey(pubkey_path_, pem, hex))
            pk = "\"pubkey_pem\":\"" + jsonEscape(pem) + "\",\"pubkey_hex\":\"" + hex + "\"";
        bool ok = false;
        const std::vector<std::string> toks = listTokens(tokens_path_, ok);
        if (!ok) return {500, "{\"error\":\"read tokens failed\"}"};
        std::string body = "{\"version\":\"1.0\"," + pk +
                           ",\"ip\":\"" + jsonEscape(vpn_ip_) +
                           "\",\"port\":" + std::to_string(vpn_port_) +
                           ",\"tokens\":[";
        for (size_t i = 0; i < toks.size(); ++i) {
            if (i) body += ",";
            body += "\"" + toks[i] + "\"";
        }
        return {200, body + "]}"};
    }

    HttpReply apiList() const {
        bool ok = false;
        const std::vector<std::string> toks = listTokens(tokens_path_, ok);
        if (!ok) return {500, "{\"error\":\"read tokens failed\"}"};
        std::string body = "{\"tokens\":[";
        for (size_t i = 0; i < toks.size(); ++i) {
            if (i) body += ",";
            body += "\"" + toks[i] + "\"";
        }
        return {200, body + "]}"};
    }

    HttpReply apiGen(const HttpRequest& req, const std::string& ip) {
        const int count = parseCount(req.body);
        if (count < 0) return {400, "{\"error\":\"count must be 1-1000\"}"};
        std::vector<std::string> fresh;
        if (!appendTokens(tokens_path_, count, fresh))
            return {500, "{\"error\":\"append tokens failed\"}"};
        appendAudit(ip, "gen count=" + std::to_string(count));
        std::string body = "{\"tokens\":[";
        for (size_t i = 0; i < fresh.size(); ++i) {
            if (i) body += ",";
            body += "\"" + fresh[i] + "\"";
        }
        return {200, body + "]}"};
    }

    HttpReply apiDel(const HttpRequest& req, const std::string& ip) {
        const std::string token = req.path.substr(12);
        const int r = removeToken(tokens_path_, token);
        if (r < 0) return {500, "{\"error\":\"remove failed\"}"};
        if (r == 0) return {404, "{\"error\":\"token not found\"}"};
        appendAudit(ip, "del token=" + token.substr(0, 8) + "...");
        return {200, "{\"deleted\":true}"};
    }

    static int parseCount(const std::string& body)
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
    ::umask(077);

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
