# -*- coding: utf-8 -*-
"""离线解密抓到的身份帧：用假服务端派生的 key_c2s 解手机的 type=11 帧。"""
import re, hmac, hashlib, struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

LOG = r"D:\Vis  c++/ScholarVPN/android/fake_capture.log"
MAGIC = bytes([0x4E, 0x50, 0x56, 0x4D])

log = open(LOG, encoding="utf-8").read()

# 从日志取派生材料
shared = bytes.fromhex(re.search(r"shared=(\w+)", log).group(1))
nonceC = bytes.fromhex(re.search(r"auth_hello: nonceC=(\w+)", log).group(1))
# nonceS 从 ServerHello 的 payload 前缀取
srv = re.search(r"\[send\] type=9 plen=112 seq=0 payload=(\w+)", log).group(1)
nonceS = bytes.fromhex(srv[:32])

def hkdf_expand(prk, info, n):
    okm, t, gen, c = b"", b"", 0, 1
    while gen < n:
        t = hmac.new(prk, t + info.encode() + bytes([c]), hashlib.sha256).digest()
        take = min(len(t), n - gen); okm += t[:take]; gen += take; c += 1
    return okm

prk = hmac.new(nonceC + nonceS, shared, hashlib.sha256).digest()
key_c2s = hkdf_expand(prk, "tx", 32)
key_s2c = hkdf_expand(prk, "rx", 32)
print("key_c2s =", key_c2s.hex())
print("key_s2c =", key_s2c.hex())

# 取所有 type=11 的帧（seq 与完整 payload）
frames = []
for m in re.finditer(r"\[recv\] ver=2 type=11 plen=(\d+) seq=(\d+) payload=(\w+)", log):
    frames.append((int(m.group(2)), int(m.group(1)), bytes.fromhex(m.group(3))))
print("抓到 type=11 帧:", len(frames), "个")

aes = AESGCM(key_c2s)
for seq, plen, payload in frames[:3]:
    nonce, ct = payload[:12], payload[12:]
    aad = MAGIC + struct.pack(">BBHI", 2, 11, plen, seq)
    try:
        plain = aes.decrypt(nonce, ct, aad)
        print(f"\n[seq={seq}] 解密成功! inner_type={plain[0]} 明文长度={len(plain)-1}")
        b = plain[1:]
        flags, toklen = b[0], b[1]
        token = b[2:2+toklen]
        rest = b[2+toklen:]
        print("  flags =", flags, "(1=注册模式)")
        print("  token =", token.hex()[:32], "... (", toklen, "字节 )")
        print("  payload: nonceC =", rest[:16].hex())
        print("           nonceS =", rest[16:32].hex())
        print("           dhCli  =", rest[32:64].hex())
        print("           dhSrv  =", rest[64:96].hex())
        print("           cliPub =", rest[96:128].hex())
        idlen = rest[128]
        print("           idLen  =", idlen, " clientId =", rest[129:129+idlen].decode())
        sig = rest[129+idlen:]
        print("           sig    =", len(sig), "字节")
        # 用报文里的 cliPub 验签（对齐服务端第 3 步）
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        try:
            Ed25519PublicKey.from_public_bytes(rest[96:128]).verify(sig, rest[:129+idlen])
            print("  cli 签名验证: 通过")
        except Exception as e:
            print("  cli 签名验证: 失败!", e)
        break
    except Exception as e:
        print(f"[seq={seq}] 解密失败: {type(e).__name__} {e}")
