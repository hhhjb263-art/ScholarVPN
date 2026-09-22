#!/usr/bin/env python3
"""生成扩展图标（16/48/128 PNG）：靛紫渐变圆角方块 + 白色盾形。

不依赖 Pillow：手写最小 PNG 编码（RGBA8 + zlib）。
重新生成：python make_icons.py
"""
import os
import struct
import zlib

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icons")

# 品牌渐变（与 Android 主题一致）：靛蓝 → 紫
C1 = (76, 91, 212)
C2 = (146, 91, 212)
WHITE = (255, 255, 255)


def lerp(a, b, t):
    return tuple(int(round(a[i] + (b[i] - a[i]) * t)) for i in range(3))


def in_rounded_rect(u, v, r):
    """圆角方块内判定（u,v ∈ [0,1]，r = 圆角半径比例）"""
    cx = min(max(u, r), 1 - r)
    cy = min(max(v, r), 1 - r)
    return (u - cx) ** 2 + (v - cy) ** 2 <= r * r or (
        r <= u <= 1 - r or r <= v <= 1 - r
    ) and (0 <= u <= 1 and 0 <= v <= 1)


def in_shield(u, v):
    """盾形：顶部圆角矩形 + 下半收尖"""
    cu, cv = u - 0.5, v
    top, mid, bottom = 0.18, 0.52, 0.84
    half, r = 0.20, 0.09
    if cv < top or cv > bottom:
        return False
    if abs(cu) > half:
        return False
    if cv <= mid:
        if cv < top + r:
            # 顶部两角圆化：距角心 (half-r, top+r) 的弧内
            dx = abs(cu) - (half - r)
            dy = (top + r) - cv
            if dx > 0 and dy > 0 and dx * dx + dy * dy > r * r:
                return False
        return True
    t = (cv - mid) / (bottom - mid)
    return abs(cu) <= half * (1.0 - t) + 0.012


def pixel(u, v):
    """返回 (r,g,b,a)"""
    if not in_rounded_rect(u, v, 0.22):
        return (0, 0, 0, 0)
    bg = lerp(C1, C2, min(max((u + v) / 2.0, 0.0), 1.0))
    if in_shield(u, v):
        return WHITE + (255,)
    return bg + (255,)


def png_bytes(size):
    rows = []
    for y in range(size):
        row = bytearray()
        for x in range(size):
            u = (x + 0.5) / size
            v = (y + 0.5) / size
            row.extend(pixel(u, v))
        rows.append(bytes(row))

    raw = b"".join(b"\x00" + r for r in rows)  # filter type 0

    def chunk(tag, data):
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)  # RGBA8
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    for size in (16, 48, 128):
        path = os.path.join(OUT_DIR, f"icon{size}.png")
        with open(path, "wb") as f:
            f.write(png_bytes(size))
        print(f"written {path}")


if __name__ == "__main__":
    main()
