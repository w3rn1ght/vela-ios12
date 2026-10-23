"""Генератор иконки Vela без внешних зависимостей (чистый Python + zlib)."""

import math
import pathlib
import struct
import zlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "Resources"
SIZE = 1024
SS = 2  # supersampling


def lerp(a, b, t):
    return a + (b - a) * t


def mix(c1, c2, t):
    return tuple(lerp(c1[i], c2[i], t) for i in range(3))


def dist_to_segment(px, py, ax, ay, bx, by):
    vx, vy = bx - ax, by - ay
    wx, wy = px - ax, py - ay
    length2 = vx * vx + vy * vy
    t = 0.0 if length2 == 0 else max(0.0, min(1.0, (wx * vx + wy * vy) / length2))
    dx, dy = px - (ax + t * vx), py - (ay + t * vy)
    return math.hypot(dx, dy)


def render(size=SIZE, ss=SS):
    top = (0x10, 0x12, 0x2B)
    bottom = (0x4A, 0x1F, 0x7A)
    accent = (0x8B, 0x5C, 0xFF)

    # вершины «V» и толщина в долях стороны
    a = (0.285, 0.315)
    b = (0.500, 0.720)
    c = (0.715, 0.315)
    thickness = 0.081
    ring_radius = 0.360
    ring_thickness = 0.011

    out = bytearray()
    inv = 1.0 / (size * ss)

    for y in range(size):
        out.append(0)  # PNG filter: none
        for x in range(size):
            r = g = bch = 0.0
            for sy in range(ss):
                for sx in range(ss):
                    u = (x * ss + sx + 0.5) * inv
                    v = (y * ss + sy + 0.5) * inv

                    # фон: диагональный градиент + мягкое свечение от центра
                    t = min(1.0, max(0.0, (u * 0.35 + v * 0.75)))
                    bg = mix(top, bottom, t)
                    dcenter = math.hypot(u - 0.5, v - 0.42)
                    glow = max(0.0, 1.0 - dcenter / 0.75) ** 2
                    bg = mix(bg, accent, 0.22 * glow)

                    col = bg
                    # тонкое кольцо
                    dring = abs(math.hypot(u - 0.5, v - 0.5) - ring_radius)
                    if dring < ring_thickness:
                        alpha = 1.0 - dring / ring_thickness
                        col = mix(col, (0xFF, 0xFF, 0xFF), 0.13 * alpha)

                    # «V»
                    d1 = dist_to_segment(u, v, a[0], a[1], b[0], b[1])
                    d2 = dist_to_segment(u, v, c[0], c[1], b[0], b[1])
                    d = min(d1, d2)
                    edge = thickness
                    if d < edge + 0.004:
                        alpha = 1.0 if d < edge else (edge + 0.004 - d) / 0.004
                        mark = mix((0xE9, 0xEC, 0xFF), (0xFF, 0xFF, 0xFF), 1.0 - v)
                        col = mix(col, mark, alpha)

                    r += col[0]
                    g += col[1]
                    bch += col[2]

            n = ss * ss
            out += bytes((int(r / n), int(g / n), int(bch / n)))
    return out


def write_png(path, width, height, raw):
    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data +
                struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) +
           chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + chunk(b"IEND", b""))
    path.write_bytes(png)


def downsample(raw, src, dst):
    if src == dst:
        return raw
    stride_src = 1 + src * 3
    stride_dst = 1 + dst * 3
    out = bytearray()
    factor = src // dst
    for y in range(dst):
        out.append(0)
        for x in range(dst):
            r = g = b = 0
            for dy in range(factor):
                row = (y * factor + dy) * stride_src + 1
                for dx in range(factor):
                    i = row + (x * factor + dx) * 3
                    r += raw[i]
                    g += raw[i + 1]
                    b += raw[i + 2]
            n = factor * factor
            out += bytes((r // n, g // n, b // n))
    assert len(out) == stride_dst * dst
    return out


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    base = render()

    targets = {
        # iPhone
        "AppIcon60x60.png": 60,
        "AppIcon60x60@2x.png": 120,
        "AppIcon60x60@3x.png": 180,
        "Icon-60.png": 60,
        "Icon-60@2x.png": 120,
        "Icon-60@3x.png": 180,
        "Icon-Small.png": 29,
        "Icon-Small@2x.png": 58,
        "Icon-Small@3x.png": 87,
        "Icon-40.png": 40,
        "Icon-40@2x.png": 80,
        "Icon-40@3x.png": 120,
        # iPad
        "AppIcon76x76.png": 76,
        "AppIcon76x76@2x.png": 152,
        "AppIcon83.5x83.5@2x.png": 167,
        "Icon-72.png": 72,
        "Icon-72@2x.png": 144,
        "Icon-76.png": 76,
        "Icon-76@2x.png": 152,
        "Icon-83.5@2x.png": 167,
        # иконка для App Store / настроек
        "AppIcon1024.png": 1024,
    }
    for name, size in targets.items():
        data = downsample(base, SIZE, size) if size != SIZE else base
        write_png(OUT / name, size, size, data)
        print("wrote", name, size)


if __name__ == "__main__":
    main()
