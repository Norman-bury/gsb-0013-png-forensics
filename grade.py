#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""task13（PNG 取证修复）判分脚本。

规则：
1. 交付一个 solve.py，支持 `python3 solve.py <输入.png> <输出.png>`，
   读入损坏的 PNG，写出修复后的 PNG。
2. 判分先跑 solve.py 生成修复文件，再逐项校验：
   - 文件头 8 字节签名是 89 50 4E 47 0D 0A 1A 0A
   - 每个 chunk 的 CRC32 与重算值一致
   - IHDR 宽 32 高 24，位深 8，颜色类型 2（RGB），压缩/滤波/隔行都为 0
   - 所有 IDAT 数据按序拼接后 zlib 解压成功，解压出的裸像素流与原图一致
   - 最后一个 chunk 是 IEND 且数据为空

用法：
  python3 grade.py
"""

import argparse
import hashlib
import os
import struct
import subprocess
import sys
import tempfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
DAMAGED = os.path.join(HERE, "damaged.png")

# 原始图的裸扫描线数据（24 行 × (1 滤波字节 + 32×3 RGB) = 2328 字节）的 sha256。
EXPECTED_RAW_SHA256 = "fba5d7bd119bb20d4af6727ea6a4ca57b0bf0560df78776c36f745400a063782"

SIG = b"\x89PNG\r\n\x1a\n"
IHDR_TYPE = b"IHDR"
IDAT_TYPE = b"IDAT"
IEND_TYPE = b"IEND"


def parse_chunks(data):
    """返回 [(length, type, chunk_data, crc, data_off)] 列表，从偏移 8 开始。"""
    chunks = []
    off = 8
    while off + 8 <= len(data):
        (ln,) = struct.unpack(">I", data[off:off + 4])
        typ = data[off + 4:off + 8]
        cdata = data[off + 8:off + 8 + ln]
        crc_off = off + 8 + ln
        if crc_off + 4 > len(data):
            chunks.append((ln, typ, cdata, None, off + 8))
            return chunks
        (crc,) = struct.unpack(">I", data[crc_off:crc_off + 4])
        chunks.append((ln, typ, cdata, crc, off + 8))
        off = crc_off + 4
        if typ == IEND_TYPE:
            break
    return chunks


def validate(path):
    """校验修复后的 PNG，返回 (ok, 信息列表)。"""
    msgs = []
    if not os.path.exists(path):
        return False, ["修复文件不存在：" + path]
    data = open(path, "rb").read()

    # 1. 签名
    if data[:8] != SIG:
        return False, ["[FAIL] 文件头签名错误：%s" % data[:8].hex()]
    msgs.append("[OK] 文件头签名正确")

    # 2. 分块 + CRC
    chunks = parse_chunks(data)
    if not chunks:
        return False, ["[FAIL] 分块解析失败"]
    bad_crc = []
    for ln, typ, cdata, crc, _ in chunks:
        if crc is None:
            bad_crc.append(typ.decode(errors="replace"))
            continue
        calc = zlib.crc32(typ + cdata) & 0xFFFFFFFF
        if calc != crc:
            bad_crc.append(typ.decode(errors="replace"))
    if bad_crc:
        return False, ["[FAIL] 以下 chunk 的 CRC 校验不过：%s" % ", ".join(bad_crc)]
    msgs.append("[OK] 所有 chunk 的 CRC 校验通过")

    # 3. IHDR
    ihdrs = [c for c in chunks if c[1] == IHDR_TYPE]
    if len(ihdrs) != 1:
        return False, ["[FAIL] IHDR 块数量不是 1"]
    ln, typ, cdata, crc, _ = ihdrs[0]
    if len(cdata) != 13:
        return False, ["[FAIL] IHDR 数据长度不是 13"]
    w, h, depth, ctype, comp, filt, inter = struct.unpack(">IIBBBBB", cdata)
    ihdr_ok = (w == 32 and h == 24 and depth == 8 and ctype == 2
               and comp == 0 and filt == 0 and inter == 0)
    if not ihdr_ok:
        return False, ["[FAIL] IHDR 字段不对：宽 %d 高 %d 位深 %d 颜色类型 %d 压缩 %d 滤波 %d 隔行 %d"
                       % (w, h, depth, ctype, comp, filt, inter)]
    msgs.append("[OK] IHDR 宽 32 高 24，位深 8，RGB，压缩/滤波/隔行为 0")

    # 4. IDAT 解压 + 内容比对
    idats = [c for c in chunks if c[1] == IDAT_TYPE]
    if not idats:
        return False, ["[FAIL] 没有 IDAT 块"]
    raw = b"".join(c[2] for c in idats)
    try:
        pixels = zlib.decompress(raw)
    except Exception as e:
        return False, ["[FAIL] IDAT zlib 解压失败：%s" % e]
    got = hashlib.sha256(pixels).hexdigest()
    if got != EXPECTED_RAW_SHA256:
        return False, ["[FAIL] 解压出的图像内容与原图不一致（sha256 %s）" % got]
    msgs.append("[OK] IDAT 解压成功，图像内容与原图一致")

    # 5. 结尾必须是 IEND 且数据为空
    last = chunks[-1]
    if last[1] != IEND_TYPE or last[0] != 0:
        return False, ["[FAIL] 最后一个 chunk 不是空数据的 IEND"]
    msgs.append("[OK] 文件以空 IEND 结束")

    return True, msgs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--solve", default=os.path.join(HERE, "solve.py"))
    ap.add_argument("--input", default=DAMAGED)
    args = ap.parse_args()

    print("=" * 60)
    print("判分开始")

    if not os.path.exists(args.solve):
        print("[FAIL] 找不到 solve.py（%s）" % args.solve)
        sys.exit(1)
    if not os.path.exists(args.input):
        print("[FAIL] 找不到输入文件 damaged.png")
        sys.exit(1)

    out = os.path.join(tempfile.mkdtemp(prefix="task13_"), "repaired.png")
    r = subprocess.run(
        [sys.executable, args.solve, args.input, out],
        cwd=HERE, capture_output=True, text=True,
    )
    if r.returncode != 0:
        print("[FAIL] solve.py 退出码非 0（%d）" % r.returncode)
        print(r.stderr[-2000:])
        sys.exit(1)
    print("[OK] solve.py 执行完成，生成 %s" % out)

    ok, msgs = validate(out)
    for m in msgs:
        print(m)

    print("=" * 60)
    print("总结论：", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
