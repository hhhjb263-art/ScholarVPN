# -*- coding: utf-8 -*-
"""
ScholarVPN 假服务端（调试用）：完整走一遍三阶段握手，把手机发出的每一帧
原始字节落盘，供与 C++ 实现逐字段比对。
用法: python fake_server.py  （监听 127.0.0.1:4444，配合 adb reverse tcp:443 tcp:4444）
"""
import socket, struct, hmac, hashlib, os, sys, threading, time
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = bytes([0x4E, 0x50, 0x56, 0x4D])
VERSION_TCP = 2
T_DATA, T_HEART, T_HEART_RESP, T_DISC = 2, 3, 4, 5
T_AUTH_HELLO, T_SRV_HELLO, T_CLI_HELLO = 8, 9, 10
T_IDENTITY, T_ID_OK, T_ID_DENY = 11, 12, 13
HDR = 12
NONCE, TAG = 12, 16

LOG = open(r"D:\Vis  c++\ScholarVPN\android\fake_capture.log", "w", encoding="utf-8")
def log(s):
    print(s); LOG.write(s + "\n"); LOG.flush()

def hmacsha(key, data): return hmac.new(key, data, hashlib.sha256).digest()
def hkdf_expand(prk, info, n):
    okm, t, gen, c = b"", b"", 0, 1
    while gen < n:
        t = hmacsha(prk, t + info.encode() + bytes([c]))
        take = min(len(t), n - gen); okm += t[:take]; gen += take; c += 1
    return okm

def hdr(ver, t, plen, seq):
    return MAGIC + struct.pack(">BBHI", ver & 0xFF, t & 0xFF, plen, seq & 0xFFFFFFFF)
    # 注意：version/type 相邻两个 uint8，用 >BB 打包；payload_len 用 >H（大端）

def parse_hdr(b):
    if b[:4] != MAGIC: raise ValueError("magic 不匹配: %s" % b[:4].hex())
    ver, t = b[4], b[5]
    plen, seq = struct.unpack(">HI", b[6:12])
    return ver, t, plen, seq

def recv_exact(c, n):
    buf = b""
    while len(buf) < n:
        d = c.recv(n - len(buf))
        if not d: raise ConnectionError("对端关闭（已收 %d/%d）" % (len(buf), n))
        buf += d
    return buf

def recv_frame(c):
    h = recv_exact(c, HDR)
    ver, t, plen, seq = parse_hdr(h)
    payload = recv_exact(c, plen) if plen else b""
    log("[recv] ver=%d type=%d plen=%d seq=%d payload=%s" % (ver, t, plen, seq, payload.hex()))
    return ver, t, plen, seq, payload, h

def send_frame(c, t, payload, seq):
    c.sendall(hdr(VERSION_TCP, t, len(payload), seq) + payload)
    log("[send] type=%d plen=%d seq=%d payload=%s" % (t, len(payload), seq, payload[:64].hex() + ("..." if len(payload) > 64 else "")))

def main():
    ed_priv = Ed25519PrivateKey.generate()
    x_priv = X25519PrivateKey.generate()
    ed_pub_raw = ed_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    x_pub_raw = x_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    log("=== 本假服务端 Ed25519 公钥（raw base64，写进手机卡片）===")
    import base64
    log("PUB_RAW_B64=" + base64.b64encode(ed_pub_raw).decode())

    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 4444)); srv.listen(1)
    log("listening 127.0.0.1:4444")
    c, addr = srv.accept(); log("accepted " + str(addr))
    c.settimeout(15)

    srv_seq = 0
    # ---- 阶段1：auth_hello ----
    ver, t, plen, seq, payload, h = recv_frame(c)
    nonceC = payload
    log("[分析] auth_hello: nonceC=%s" % nonceC.hex())
    nonceS = os.urandom(16)
    sig = ed_priv.sign(nonceC + nonceS + x_pub_raw)
    hello = nonceS + x_pub_raw + sig
    send_frame(c, T_SRV_HELLO, hello, srv_seq); srv_seq += 1

    # ---- 阶段2：auth_client_hello（★ 关键比对点）----
    ver, t, plen, seq, payload, h = recv_frame(c)
    log("[分析] client_hello 帧头: ver=%d(期望2) type=%d(期望10) plen=%d(期望32) seq=%d" % (ver, t, plen, seq))
    dhCliPub = payload
    log("[分析] dhCliPub=%s" % dhCliPub.hex())
    shared = x_priv.exchange(X25519PublicKey.from_public_bytes(dhCliPub))
    log("[分析] shared=%s" % shared.hex())
    prk = hmacsha(nonceC + nonceS, shared)          # HKDF-Extract(salt=nonceC||nonceS, ikm=shared)
    key_s2c = hkdf_expand(prk, "rx", 32)            # 服务端发送
    key_c2s = hkdf_expand(prk, "tx", 32)            # 服务端接收
    log("[分析] key_s2c=%s" % key_s2c.hex())
    log("[分析] key_c2s=%s" % key_c2s.hex())

    aes_c2s = AESGCM(key_c2s)
    # ---- 阶段3：identity（密文）----
    ver, t, plen, seq, payload, h = recv_frame(c)
    log("[分析] identity 帧: ver=%d type=%d plen=%d seq=%d" % (ver, t, plen, seq))
    nonce, ct = payload[:NONCE], payload[NONCE:]
    aad = hdr(ver, t, plen, seq)
    try:
        plain = aes_c2s.decrypt(nonce, ct, aad)
        log("[分析] identity 解密成功! inner_type=%d 明文=%s" % (plain[0], plain[1:].hex()))
        b = plain[1:]
        flags, toklen = b[0], b[1]
        token = b[2:2+toklen]
        rest = b[2+toklen:]
        log("[分析] flags=%d token_len=%d token=%s" % (flags, toklen, token.hex()))
        p = rest
        log("[分析] payload: nonceC=%s" % p[:16].hex())
        log("[分析]           nonceS=%s" % p[16:32].hex())
        log("[分析]           dhCli=%s" % p[32:64].hex())
        log("[分析]           dhSrv=%s" % p[64:96].hex())
        log("[分析]           cliPub=%s" % p[96:128].hex())
        idlen = p[128]
        log("[分析]           idLen=%d clientId=%s" % (idlen, p[129:129+idlen].decode()))
        sig = p[129+idlen:]
        log("[分析]           sig=%s (%d 字节)" % (sig.hex()[:32] + "...", len(sig)))
        # 用报文携带的 cliPub 验签（对齐服务端 handle_identity 第 3 步）
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            Ed25519PublicKey.from_public_bytes(p[96:128]).verify(sig, p[:129+idlen])
            log("[分析] cli 签名验证: 通过")
        except Exception as e:
            log("[分析] cli 签名验证: 失败 %s" % e)
        # 服务端重建 payload 时用的 client_id 是会话里的 clientId（登录模式）/
        # 报文里的（注册模式）——对比见服务端 handle_identity
    except Exception as e:
        log("[分析] identity 解密失败: %s" % e)
        log("[分析] ★★★ 若走到这里，说明手机的会话密钥派生/封装与服务端不一致 ★★★")

    # ---- 回 identity_ok，让手机走完握手（建立 tun 后立即停）----
    vip = bytes([10, 8, 0, 50]) + bytes([24])
    inner = bytes([T_ID_OK]) + vip
    nonce = os.urandom(NONCE)
    aad = hdr(VERSION_TCP, T_ID_OK, NONCE + len(inner), srv_seq)
    ct = aes = None
    ct = AESGCM(key_s2c).encrypt(nonce, inner, aad)
    send_frame(c, T_ID_OK, nonce + ct, srv_seq); srv_seq += 1
    log("=== identity_ok 已回，等待心跳/数据（60s）===")
    c.settimeout(60)
    try:
        while True:
            ver, t, plen, seq, payload, h = recv_frame(c)
            if t == T_HEART:
                send_frame(c, T_HEART_RESP, b"", srv_seq); srv_seq += 1
    except Exception as e:
        log("结束: %s" % e)
    c.close()

threading.Thread(target=main, daemon=True).start()
print("运行中，Ctrl+C 退出")
import time
while True: time.sleep(3600)
