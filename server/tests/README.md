# server/tests

## 浏览器代理入口运行期自测（Windows 开发机可跑）

`server/Socks5/socks5.cpp` 与 `server/HttpsProxy/httpsproxy.cpp` 正式部署在
Linux，但逻辑验证不必等 Linux 环境：用 Winsock 兼容垫片（`shim_include/` +
`socks5_win_shim.h`）把同一份源码原样编译到 Windows，用**真实 socket +
真实 OpenSSL** 跑端到端用例。

```bat
:: VS2022 x64 Native Tools 命令行（cl 在 PATH）
:: TLS 用例需要 libssl/libcrypto（示例用 conda 的 OpenSSL 3.5，与仓库头文件同版本）
cd /d <仓库根>
cl /nologo /std:c++17 /EHsc /utf-8 /DPROXY_TEST_TLS ^
   /I"server\tests\shim_include" /I"server\Socks5" /I"server\HttpsProxy" /I"server\Proxy" ^
   /I"D:\Users\123\miniconda3\Library\include" ^
   server\tests\proxy_selftest.cpp server\Socks5\socks5.cpp server\HttpsProxy\httpsproxy.cpp ^
   /Fe:proxy_selftest.exe ^
   /link /LIBPATH:"D:\Users\123\miniconda3\Library\lib" libssl.lib libcrypto.lib ws2_32.lib

:: 运行前把 libssl-3-x64.dll / libcrypto-3-x64.dll 放到同目录或 PATH
proxy_selftest.exe
```

不加 `/DPROXY_TEST_TLS` 则跳过 TLS 用例（不需要 libssl）。

### 覆盖用例

**SOCKS5（server/Socks5）**

1. IPv4 CONNECT + 双向中继（回显校验）
2. 域名目标（ATYP=0x03，getaddrinfo 分支）
3. 目标端口不可达 → 失败应答
4. 不支持的命令（BIND）→ REP=0x07
5. RFC1929 认证：错误密码拒绝 / 正确密码放行
6. `stop()` 回收、`port=0` 未启用不报错

**HTTP CONNECT 代理（server/HttpsProxy，明文）**

1. CONNECT 200 并建立隧道 + 双向中继
2. 无凭据 → 407 + `Proxy-Authenticate: Basic`
3. 错误凭据 → 407；正确凭据 → 200
4. 绝对形式 `GET http://…` 转发（含剥离 Proxy-* 头）+ 响应体校验
5. 非绝对形式请求 → 501

**HTTPS CONNECT 代理（TLS）**

1. 本地生成自签证书（OpenSSL API）→ 代理加载成功
2. 客户端真实 TLS 握手且**证书链校验通过**（`SSL_VERIFY_PEER`）
3. TLS 隧道内 CONNECT 200 + 双向中继（密文承载）
4. **明文 CONNECT 打到 TLS 端口不生效**（确认真在加密）
5. TLS 模式缺证书 → 拒绝启动

### 垫片说明与边界

- 垫片把 Winsock 包装成 POSIX 语义（errno 映射、`accept4`、`fcntl` 非阻塞、
  `WSAPoll`、`sys/time.h` 等），**只为测试存在**，不参与 Linux 构建；
- 已知平台差异（不影响 Linux 生产代码）：Windows 的 `SO_SNDTIMEO/SO_RCVTIMEO`
  取毫秒而非 `struct timeval`，垫片下该超时不生效；
- 自测通过 ≠ 可跳过 Linux 上的真实回归（防火墙、`getaddrinfo` 行为、
  高并发下的 fd/线程回收仍建议在目标环境冒烟）。

## 加密层往返测试（GCM）

`Crypt.cpp` / `server/Crypt/crypt.cpp` 的 `aes256_gcm_seal/open` 曾在实测中
暴露"输出缓冲未按密文尺寸扩容"的回归，故保留一组往返断言（双段明文往返、
篡改 tag/AAD 拒绝、空载荷、out_cap 抛错、100 轮上下文复用、旧 vector 版本
互操作）。用 MSVC 直接编译一个临时 main 调这些 API 即可，模板见
`../../Crypt.h` 的接口签名（本项目自带 last-known-good 记录在提交历史中）。
