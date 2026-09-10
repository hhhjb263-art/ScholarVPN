# ScholarVPN 隧道线格式规格（Android 客户端实现依据）

> 本文档从 Windows 客户端（`src/tunnel_protoco.h` / `src/UDP.cpp` / `Crypt.cpp`）
> 与 Linux 服务端（`server/Buffer/tunnel_protoco.h` / `server/UDP/UDP.cpp`）逐字节提取，
> 是 Kotlin 端实现的**唯一验收标准**。任何实现差异都会导致三阶段认证或数据面失败。

## 1. 帧头（tunnel_header，12 字节，`#pragma pack(1)` 无填充）

```
偏移  长度  字段          字节序
0     4    magic        原始 struct 内存拷贝 → 小端（x86/ARM 均为 LE）
                        值 = 0x4D56504E → 线上字节为 4E 50 56 4D
4     1    version      协议版本 = 传输标识：v_udp=1，v_tcp=2
5     1    type         消息类型（见 §2）
6     2    payload_len  大端（htons）
8     4    sequence     大端（htonl），每会话从 0 递增
```

⚠️ **字节序混合**：magic 按小端写入，payload_len/sequence 按大端写入。
Kotlin 端建议直接按字节常量比对 magic，不要用整数读。

每条消息 = `帧头(12) + payload`；UDP 一报文一帧，TCP 按 `payload_len` 分帧。

长度约束：`Max_payload_len = 1429`（超长帧 = 非法，断开）；
数据面明文载荷 ≤ `KMax_data_payload = 1400`（对应 TUN MTU 1400）。

## 2. 消息类型（type 字段）

| 值 | 名称 | 加密 | 方向 | payload |
|----|------|------|------|---------|
| 0 | m_hand_request | - | （旧握手，未用） | |
| 1 | m_hand_response | - | （旧握手，未用） | |
| 2 | m_data | 密文 | 双向 | IP 包 |
| 3 | m_heart | 密文* | 双向 | 空 |
| 4 | m_heart_response | 密文* | 双向 | 空 |
| 5 | disconnect | 密文 | 双向 | 空（服务端→客户端时带内层） |
| 6 | m_key_exchange | - | （旧握手，未用） | |
| 7 | m_key_response | - | （旧握手，未用） | |
| 8 | m_auth_hello | 明文 | C→S | nonce_c(16) |
| 9 | m_auth_server_hello | 明文 | S→C | 见 §3 阶段1 |
| 10 | m_auth_client_hello | 明文 | C→S | dh_cli_pub(32) |
| 11 | m_identity | 密文 | C→S | 见 §4 |
| 12 | m_identity_ok | 密文 | S→C | virtual_ip(4,大端) + prefix(1) |
| 13 | m_identity_deny | 密文 | S→C | reason(1)：0=未注册 1=令牌无效/已使用 |

\* 心跳在密钥就绪（阶段2完成）后一律密文；两端都拒绝处理密钥就绪前的
明文数据帧（防伪造注入），明文仅阶段1三种消息合法。

版本校验：接收时 `version` 必须等于本端传输的标识
（UDP 会话收 v_udp，TCP 会话收 v_tcp），不符直接丢弃。

## 3. 三阶段认证

### 阶段 1（明文，密钥协商 + 服务器验签）

```
C→S  auth_hello:        nonce_c(16, 随机)
S→C  auth_server_hello: nonce_s(16) || dh_srv_pub(32) || sig_srv(64)   共 112 字节
C→S  auth_client_hello: dh_cli_pub(32)   （临时 X25519 公钥）
```

- `sig_srv` = 服务器 Ed25519 私钥对 `sig_payload = nonce_c || nonce_s || dh_srv_pub` 的签名；
- 客户端用**内置/配置的服务器公钥**验签，失败 = 疑似中间人，立即断开；
- 客户端超时重传用**同一 nonce_c**（服务端幂等重发同一 ServerHello）。

### 阶段 2（密钥派生，无报文）

```
ss      = X25519(dh_cli_priv, dh_srv_pub)
prk     = HKDF-Extract(salt = nonce_c || nonce_s, ikm = ss)     // HMAC-SHA256
key_tx  = HKDF-Expand(prk, "tx", 32)    // 客户端→服务端（客户端发送用）
key_rx  = HKDF-Expand(prk, "rx", 32)    // 服务端→客户端（客户端接收解密用）
```

两端用相同 nonce_c/nonce_s 派生出相同结果；客户端 key_tx 加密、key_rx 解密。

### 阶段 3（密文身份报文，C→S）

```
m_identity 的内层明文 body =
  flags(1)                    // 0=登录 1=注册
  token_len(1)                // 注册模式为令牌字节数；登录模式 0
  token(token_len)            // 一次性注册令牌（注册模式才有）
  identity_payload
  sig_cli(64)                 // 客户端 Ed25519 私钥对 identity_payload 的签名

identity_payload =
  nonce_c(16) || nonce_s(16) || dh_cli_pub(32) || dh_srv_pub(32)
  || sig_cli_pub(32) || id_len(1) || client_id
```

服务端校验：会话上下文绑定（nonce/DHpub 与本会话一致，防跨会话重放）→
用报文携带的 sig_cli_pub 验签 → 注册（令牌一次性作废，公钥入
`keys/registered_clients.txt`）或登录（公钥查表）→ 分配虚拟 IP → 回 `m_identity_ok`。

## 4. 加密封装（AES-256-GCM，数据面统一格式）

密钥就绪后，`m_data / m_heart / m_heart_response / m_identity /
m_identity_ok / m_identity_deny / disconnect` 一律按以下格式封装：

```
帧头.payload_len = inner_len(1 + data_len) + 12 + 16   ← 先改帧头再当 AAD！
密文 payload = nonce(12, 随机) || ciphertext(inner_len) || tag(16)
AAD         = 12 字节帧头（含已更新的 payload_len 字段）
inner 明文   = 内层type(1) || 载荷
key         = 发送方向用 key_tx，接收方向用 key_rx
```

解密失败（tag 校验不过）静默丢弃。明文载荷上限 1400，
对应密文 payload 上限 1400+1+12+16 = 1429 = Max_payload_len。

## 5. 心跳与保活

| 参数 | 客户端 | 服务端 |
|------|--------|--------|
| 心跳间隔 | 1s | 10s |
| 失联判定 | 5s 无任何合法报文 | 30s |
| 未认证会话清理 | — | 10s（握手超时） |

客户端对 `m_heart` 回 `m_heart_response`（密文）；心跳重置对端失联计时。

## 6. 多用户通告

`m_identity_ok` payload：`virtual_ip(4, 大端/网络序) || prefix(1)`——
客户端认证通过后必须采用该地址配置 VpnService（`addAddress`），
服务端按此虚拟 IP 做下行查表转发。

## 7. 服务端行为备忘（联调判读用）

- 未认证会话不转发任何 TUN 流量；
- 同一 client_id 重复登录踢旧会话（client_id 仅显示/互踢用，凭证=公钥）；
- `--transport both`（默认）同端口 UDP+TCP 双栈监听，TCP 连接复用同一套
  会话表/认证/加密/心跳；
- 服务器身份密钥：`keys/server_sig.key/.pub`（Ed25519，PEM），
  Android 端内置的验证公钥取 `.pub` 内的 raw 32 字节（PEM 转换一次即可）。
