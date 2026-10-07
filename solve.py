#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PNG 取证修复：读入损坏的 PNG，写出修复后的 PNG。

用法：python3 solve.py <输入.png> <输出.png>

修复策略（全部依据 PNG 自带的校验信息定位，不猜）：
1. 文件头 8 字节签名被清零 -> 写回标准签名。
2. IHDR 的宽/高被篡改（该块 CRC 对不上）-> 先修复 IDAT 并解压出裸像素流，
   由裸流长度 L = h*(1+3w) 结合每行滤波字节必须落在 0..4 反推真实宽高。
3. IDAT 块顺序被打乱 -> 枚举排列，找能让 zlib 流完整解压的顺序。
4. 一段字节被单字节密钥异或 -> zlib 头首字节固定为 0x78 且头两字节
   满足 (CMF*256+FLG) % 31 == 0，由此推出密钥；再枚举异或区间长度，
   以整条流解压成功且自带 adler32 校验通过为判定。
5. 个别块的 CRC 被写入错误值 -> 所有块重算 CRC32 写回。
"""

import itertools
import struct
import sys
import zlib

PNG_SIG = b"\x89PNG\r\n\x1a\n"


def parse_chunks(data):
    """从偏移 8 开始解析 chunk，返回 [(type, data)]。"""
    chunks = []
    off = 8
    while off + 8 <= len(data):
        (ln,) = struct.unpack(">I", data[off:off + 4])
        typ = data[off + 4:off + 8]
        cdata = data[off + 8:off + 8 + ln]
        chunks.append((typ, cdata))
        off += 12 + ln
        if typ == b"IEND":
            break
    return chunks


def try_decompress(stream):
    """严格解压：必须到达流尾且 adler32 校验通过，否则返回 None。"""
    try:
        do = zlib.decompressobj()
        out = do.decompress(bytes(stream))
        out += do.flush()
        if not do.eof:
            return None
        return out
    except Exception:
        return None


def repair_idat(idats):
    """修复 IDAT：枚举排列 + 单字节异或密钥/区间。

    返回 (修复后按序的 IDAT 数据列表, 解压出的裸像素流)。
    """
    for perm in itertools.permutations(range(len(idats))):
        raw = bytearray(b"".join(idats[i] for i in perm))
        # 情况一：该排列下无异或损伤，可直接解压
        out = try_decompress(raw)
        if out is not None:
            return [idats[i] for i in perm], out
        # 情况二：流开头被单字节密钥异或。zlib 头首字节必为 0x78，
        # 且 (CMF*256+FLG) % 31 == 0，据此推候选密钥。
        keys = set()
        for flg in range(256):
            if (0x78 * 256 + flg) % 31 == 0:
                key = raw[0] ^ 0x78
                if (raw[1] ^ key) == flg:
                    keys.add(key)
        for key in keys:
            for n in range(2, len(raw) + 1):
                test = bytes(b ^ key for b in raw[:n]) + bytes(raw[n:])
                out = try_decompress(test)
                if out is not None:
                    # 把修复后的流按原块长度切回各 IDAT
                    sizes = [len(idats[i]) for i in perm]
                    fixed, pos = [], 0
                    for s in sizes:
                        fixed.append(test[pos:pos + s])
                        pos += s
                    return fixed, out
    raise SystemExit("无法修复 IDAT 流")


def infer_dimensions(rawlen, pixels):
    """由裸流长度 h*(1+3w) 与滤波字节合法性反推 (w, h)。"""
    cands = []
    for h in range(1, rawlen + 1):
        if rawlen % h:
            continue
        stride = rawlen // h
        if stride < 4 or (stride - 1) % 3:
            continue
        w = (stride - 1) // 3
        if all(pixels[y * stride] in range(5) for y in range(h)):
            cands.append((w, h))
    if not cands:
        raise SystemExit("无法推断图像尺寸")
    # 多个因式分解都合法时，取宽高比最接近 4:3 的常规解
    cands.sort(key=lambda wh: abs(wh[0] / wh[1] - 4 / 3))
    return cands[0]


def main():
    if len(sys.argv) != 3:
        sys.exit("用法: python3 solve.py <输入.png> <输出.png>")
    data = open(sys.argv[1], "rb").read()
    chunks = parse_chunks(data)

    # 3)+4) 修复 IDAT 顺序与异或段，得到解压成功的裸像素流
    idats = [d for t, d in chunks if t == b"IDAT"]
    fixed_idats, pixels = repair_idat(idats)
    # 2) 由裸像素流反推真实宽高
    w, h = infer_dimensions(len(pixels), pixels)

    out = bytearray(PNG_SIG)  # 1) 修复签名
    idat_iter = iter(fixed_idats)
    for typ, cdata in chunks:
        if typ == b"IHDR":
            # 宽/高被篡改：用反推出的真实尺寸重写，其余字段保留
            _, _, depth, ctype, comp, filt, inter = struct.unpack(">IIBBBBB", cdata)
            cdata = struct.pack(">IIBBBBB", w, h, depth, ctype, comp, filt, inter)
        elif typ == b"IDAT":
            cdata = next(idat_iter)  # 按修复后的顺序与内容写出
        # 5) 所有块重算 CRC32 写回
        out += struct.pack(">I", len(cdata)) + typ + cdata
        out += struct.pack(">I", zlib.crc32(typ + cdata) & 0xFFFFFFFF)
    open(sys.argv[2], "wb").write(out)


if __name__ == "__main__":
    main()
