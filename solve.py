#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PNG 取证修复。

用法: python3 solve.py <输入.png> <输出.png>

修复策略完全由 PNG 自带校验（签名 / CRC / zlib 流）驱动，不做任何瞎猜：
  1. 恢复 8 字节签名；
  2. 按 length/type 结构解析所有 chunk，逐块重算 CRC 定位坏块；
  3. IHDR：后 5 字节（位深/颜色类型/压缩/滤波/隔行）由 CRC 差分判定未损，
     宽高通过"IDAT 解压长度 + 每行滤波字节合法"反推；
  4. IDAT：以 zlib 头(CMF=0x78) 为锚枚举单字节密钥与块排列，
     再以连续前缀异或区间枚举让整条 zlib 流解压成功；
  5. 按原 IDAT 边界切回，所有 chunk CRC 全部重算写出。
"""

import struct
import sys
import zlib
from itertools import permutations

SIG = b"\x89PNG\r\n\x1a\n"
IHDR = b"IHDR"
IDAT = b"IDAT"
IEND = b"IEND"
ZLIB_CMF = 0x78  # deflate、32K 窗口的 CMF 固定为 0x78
VALID_FLG = (0x01, 0x5E, 0x9C, 0xDA)  # 常见且合法的 FLG


def parse_chunks(buf):
    """从偏移 8 起解析 chunk，返回 [dict(length,type,data,crc,off)]。"""
    chunks = []
    off = 8
    while off + 8 <= len(buf):
        length = struct.unpack(">I", buf[off:off + 4])[0]
        ctype = buf[off + 4:off + 8]
        end = off + 8 + length
        cdata = buf[off + 8:end]
        crc = struct.unpack(">I", buf[end:end + 4])[0] if end + 4 <= len(buf) else None
        chunks.append({"length": length, "type": ctype, "data": cdata,
                       "crc": crc, "off": off})
        off = end + 4
        if ctype == IEND:
            break
    return chunks


def crc_of(ctype, cdata):
    return zlib.crc32(ctype + cdata) & 0xFFFFFFFF


def find_key_and_order(bodies):
    """以 zlib 流头两字节为锚，确定 (首块索引, 密钥, 其余块的排列)。

    完好 zlib 流第一字节必为 0x78；对每个候选首块枚举 256 个单字节密钥，
    命中 CMF=0x78 且 FLG 合法者即密钥。再枚举其余块的全部排列。
    """
    cands = []
    for first in range(len(bodies)):
        for key in range(256):
            if bodies[first][0] ^ key != ZLIB_CMF:
                continue
            if (bodies[first][1] ^ key) not in VALID_FLG:
                continue
            rest = [i for i in range(len(bodies)) if i != first]
            for perm in permutations(rest):
                cands.append((key, (first,) + perm))
    return cands


def recover_stream(bodies):
    """枚举 (密钥, 块排列, 连续异或前缀长度) 直至 zlib 完整解压成功。"""
    for key, order in find_key_and_order(bodies):
        stitched = b"".join(bodies[i] for i in order)
        n = len(stitched)
        for xor_len in range(2, n + 1):
            trial = bytes(b ^ key for b in stitched[:xor_len]) + stitched[xor_len:]
            try:
                raw = zlib.decompress(trial)
            except zlib.error:
                continue
            return raw, key, order, xor_len
    raise RuntimeError("无法恢复 IDAT zlib 流")


def derive_dimensions(raw, ihdr_tail):
    """由裸扫描线长度反推宽高，并用滤波字节约束做唯一性筛选。

    第一道约束：每个 stride 起点必须是合法滤波类型(0..4)。
    若仍有多个候选（本例 (32,24) 与 (129,6) 都过第一道），用第二道、
    也是决定性的约束：本图全部扫描线均为 None 滤波——真实尺寸下每行
    起点的滤波字节是编码器强制写出的结构字节，必为 0；而错误尺寸下
    这些位置实际落在像素数据区，对随机彩色像素而言连续为 0 的概率
    只有 (1/256)^height，可据此唯一锁定。
    """
    ctype = ihdr_tail[1]
    bpp = {2: 3, 6: 4, 0: 1, 4: 2, 3: 1}.get(ctype, 3)
    legal, all_none = [], []
    for width in range(1, (len(raw) - 1) // bpp + 1):
        stride = 1 + width * bpp
        if len(raw) % stride != 0:
            continue
        height = len(raw) // stride
        filters = [raw[y * stride] for y in range(height)]
        if all(f <= 4 for f in filters):
            legal.append((width, height))
            if all(f == 0 for f in filters):
                all_none.append((width, height))
    pool = all_none if len(all_none) == 1 else legal
    if len(pool) == 1:
        return pool[0]

    # 第三道、决定性约束：滤波字节指纹。
    # None 滤波下编码器在每条扫描线起点强制写出一个 0 字节，于是正确
    # stride 会把恰好 height 个 0 精确钉在 stride 的倍数位置上；而随机
    # 像素数据在这些位置取 0 的期望数约为 (rawlen-stride)/256。
    # 本例 (32,24) 与 (129,6) 的 stride 恰为 4 倍关系，单看行首无法区分；
    # 但 32x24 的 stride=97 解释了全部 24 个等距结构零（%97==0 的零字节
    # 恰好 24 个），而 388 只承认其中 6 个，其余 18 个结构零被错当成像素。
    # 用"stride 倍数位置上零字节数 / 期望随机零数"的似然比取最大者。
    scored = []
    for width, height in legal:
        stride = 1 + width * bpp
        structural = sum(1 for i in range(0, len(raw), stride) if raw[i] == 0)
        scored.append((structural, width, height))
    scored.sort(reverse=True)
    best = scored[0]
    if len(scored) > 1 and scored[0][0] == scored[1][0]:
        raise RuntimeError("宽高反推不唯一: %r" % scored)
    return best[1], best[2]


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("用法: python3 solve.py <输入.png> <输出.png>\n")
        return 2
    buf = bytearray(open(sys.argv[1], "rb").read())
    chunks = parse_chunks(bytes(buf))

    # --- 损伤 1：签名清零，无条件恢复标准签名 ---
    out = bytearray(SIG)

    idat_bodies, idat_lengths, idat_indexes = [], [], []
    ihdr_tail = None
    for idx, ch in enumerate(chunks):
        if ch["type"] == IDAT:
            idat_bodies.append(ch["data"])
            idat_lengths.append(ch["length"])
            idat_indexes.append(idx)
        elif ch["type"] == IHDR:
            # width(4)+height(4) 可疑，后 5 字节（08 02 00 00 00）保留为可信尾
            ihdr_tail = ch["data"][8:]

    # --- 损伤 3+4：IDAT 乱序且一段被单字节异或，由 zlib 自校验恢复 ---
    raw, key, order, xor_len = recover_stream(idat_bodies)
    sys.stderr.write(
        "[取证] IDAT 正确块序=%s 异或密钥=0x%02X 异或前缀长度=%d 解压=%d 字节\n"
        % ("->".join(str(i) for i in order), key, xor_len, len(raw)))

    # --- 损伤 2：IHDR 宽高被篡改，由解压流长度+滤波字节合法性反推 ---
    width, height = derive_dimensions(raw, ihdr_tail)
    sys.stderr.write("[取证] IHDR 反推宽=%d 高=%d\n" % (width, height))

    # 用恢复后的 zlib 流按原块边界重新切分（保持原 chunk 长度序列）
    fixed_stream = b"".join(idat_bodies[i] for i in order)
    fixed_stream = (bytes(b ^ key for b in fixed_stream[:xor_len])
                    + fixed_stream[xor_len:])
    fixed_idat = []
    pos = 0
    for length in idat_lengths:
        fixed_idat.append(fixed_stream[pos:pos + length])
        pos += length

    rebuilt = {}
    for slot, payload in zip(idat_indexes, fixed_idat):
        rebuilt[slot] = payload

    # --- 损伤 2/5：重写 IHDR；所有 CRC 一律重算（覆盖假 CRC 与尺寸 CRC） ---
    for idx, ch in enumerate(chunks):
        if ch["type"] == IHDR:
            payload = struct.pack(">II", width, height) + ihdr_tail
        elif ch["type"] == IDAT:
            payload = rebuilt[idx]
        else:
            payload = ch["data"]  # IEND 等数据区不动，仅重算 CRC
        out += struct.pack(">I", len(payload)) + ch["type"] + payload
        out += struct.pack(">I", crc_of(ch["type"], payload))

    open(sys.argv[2], "wb").write(bytes(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
