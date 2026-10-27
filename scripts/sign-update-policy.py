#!/usr/bin/env python3
# ============================================================================
# scripts/sign-update-policy.py —— 发布侧：生成密钥 / 签署更新策略
#
# 客户端的更新检查依赖三样东西，全部由本脚本产出：
#   1. release.key / release_pub.pem   发布密钥对（私钥绝对不能进仓库！）
#   2. update-policy.ini               策略文件
#   3. update-policy.ini.sig           对策略文件**原始字节**的 Ed25519 签名（base64）
#
# ⚠️ 签名对象是文件的原始字节流——传输时不得做任何转换（比如改行尾、加 BOM），
#    否则客户端验签必失败。上传前用 --verify 再自检一遍。
#
# 用法（典型一次发布）：
#   python scripts/sign-update-policy.py gen-keys --out-dir keys
#   python scripts/sign-update-policy.py make --key keys/release.key \
#       --latest 1.7.0 --minimum 1.6.0 \
#       --url https://dl.example.com/scholarvpn/ScholarVPN-1.7.0-setup.exe \
#       --sha256 9f2c8a41... \
#       --size 48213000 --notes "修复认证边界问题" \
#       --out-dir dist
#   python scripts/sign-update-policy.py verify \
#       --policy dist/update-policy.ini --sig dist/update-policy.ini.sig \
#       --pub keys/release_pub.pem
# ============================================================================

import argparse
import base64
import datetime
import pathlib
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


# ---------------------------------------------------------------- 密钥 ----

def gen_keys(out_dir: pathlib.Path) -> None:
    priv_path = out_dir / "release.key"
    pub_path = out_dir / "release_pub.pem"
    if priv_path.exists() or pub_path.exists():
        print(f"拒绝：{priv_path} 或 {pub_path} 已存在。", file=sys.stderr)
        print("密钥对只能生成一次；重发新密钥意味着所有存量客户端都要换公钥。", file=sys.stderr)
        sys.exit(1)

    key = Ed25519PrivateKey.generate()
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)
    print(f"已生成：{priv_path}（私钥，妥善保管，不入仓库）")
    print(f"已生成：{pub_path}（公钥，填进客户端 [Update] PublicKey）")


def load_priv(path: pathlib.Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        print(f"{path} 不是 Ed25519 私钥", file=sys.stderr)
        sys.exit(1)
    return key


def load_pub(path: pathlib.Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        print(f"{path} 不是 Ed25519 公钥", file=sys.stderr)
        sys.exit(1)
    return key


# ---------------------------------------------------------------- 策略 ----

def ver_tuple(v):
    """("1.7.0") -> (1, 7, 0)；非法返回 None"""
    try:
        return tuple(int(x) for x in v.strip().split("."))
    except ValueError:
        return None


def make_policy(args) -> None:
    # 防呆：minimum 高于 latest 会把所有客户端锁进死局——
    # 客户端更新到 latest 仍低于 minimum，永远无法解锁。
    # （唯一自救是运维把 minimum 降回来重新上传。）
    if args.minimum:
        mt = ver_tuple(args.minimum)
        lt = ver_tuple(args.latest)
        if mt is None or lt is None or len(mt) == 0:
            print(f"版本号格式错误（应为 x.y.z 数字）："
                  f"latest={args.latest} minimum={args.minimum}", file=sys.stderr)
            sys.exit(1)
        if mt > lt:
            print(f"拒绝：minimum({args.minimum}) 高于 latest({args.latest})。\n"
                  f"这样配置会让所有客户端被锁死，且更新到 latest 也无法解锁。\n"
                  f"如确需强制：minimum 应等于或略低于 latest。", file=sys.stderr)
            sys.exit(1)
    lines = [
        "# ScholarVPN 客户端更新策略",
        f"# 生成时间: {datetime.datetime.now().isoformat(timespec='seconds')}",
        f"latest    = {args.latest}",
    ]
    if args.minimum:
        lines.append(f"minimum   = {args.minimum}")
    if args.notes:
        lines.append(f"notes      = {args.notes}")
    lines.append(f"url       = {args.url}")
    lines.append(f"sha256    = {args.sha256}")
    if args.size:
        lines.append(f"size      = {args.size}")
    lines.append(f"generated = {int(datetime.datetime.now().timestamp())}")

    body = "\n".join(lines) + "\n"

    out_dir = pathlib.Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    policy_path = out_dir / "update-policy.ini"
    sig_path = policy_path.with_suffix(policy_path.suffix + ".sig")

    policy_path.write_bytes(body.encode("utf-8"))   # 注意：原始字节，保持 LF

    key = load_priv(pathlib.Path(args.key))
    sig = key.sign(body.encode("utf-8"))
    sig_path.write_bytes(base64.encodebytes(sig).replace(b"\n", b""))

    print(f"已生成：{policy_path}")
    print(f"已生成：{sig_path}")
    print()
    print("自检（强烈建议执行）：")
    print(f"  python scripts/sign-update-policy.py verify --policy {policy_path} "
          f"--sig {sig_path} --pub {args.pub if args.pub else '<release_pub.pem>'}")


def sign_only(args) -> None:
    policy_path = pathlib.Path(args.policy)
    sig_path = pathlib.Path(args.sig) if args.sig else \
        policy_path.with_suffix(policy_path.suffix + ".sig")
    key = load_priv(pathlib.Path(args.key))
    data = policy_path.read_bytes()
    sig_path.write_bytes(base64.encodebytes(key.sign(data)).replace(b"\n", b""))
    print(f"已签名：{sig_path}")


def verify(args) -> int:
    data = pathlib.Path(args.policy).read_bytes()
    sig = base64.b64decode(pathlib.Path(args.sig).read_bytes())
    pub = load_pub(pathlib.Path(args.pub))
    try:
        pub.verify(sig, data)
    except Exception as e:   # noqa: BLE001 - 验签失败要给人看原因
        print(f"验签失败：{e}", file=sys.stderr)
        return 1
    print("验签通过：文件与签名匹配")
    return 0


# ---------------------------------------------------------------- 入口 ----

def main() -> int:
    ap = argparse.ArgumentParser(description="生成发布密钥 / 签署客户端更新策略")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("gen-keys", help="生成发布密钥对（只能一次）")
    p.add_argument("--out-dir", default="keys")

    p = sub.add_parser("make", help="生成策略文件并签名")
    p.add_argument("--key", required=True, help="release.key 路径")
    p.add_argument("--latest", required=True, help="最新版本号")
    p.add_argument("--minimum", help="最低可用版本（低于此强制升级）")
    p.add_argument("--url", required=True, help="安装包下载地址")
    p.add_argument("--sha256", required=True, help="安装包 SHA-256")
    p.add_argument("--size", type=int, help="安装包字节数")
    p.add_argument("--notes", help="更新说明（单行）")
    p.add_argument("--pub", help="release_pub.pem（仅用于打印自检命令）")
    p.add_argument("--out-dir", default="dist")

    p = sub.add_parser("sign", help="只对已有策略文件重新签名")
    p.add_argument("--policy", required=True)
    p.add_argument("--sig")
    p.add_argument("--key", required=True)

    p = sub.add_parser("verify", help="发布前自检")
    p.add_argument("--policy", required=True)
    p.add_argument("--sig", required=True)
    p.add_argument("--pub", required=True)

    args = ap.parse_args()

    if args.cmd == "gen-keys":
        gen_keys(pathlib.Path(args.out_dir))
        return 0
    if args.cmd == "make":
        make_policy(args)
        return 0
    if args.cmd == "sign":
        sign_only(args)
        return 0
    if args.cmd == "verify":
        return verify(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
