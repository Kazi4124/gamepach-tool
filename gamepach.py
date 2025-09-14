#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, zlib, json, argparse
from pathlib import Path
from colorama import init, Fore

init(autoreset=True)

# ===================== CONFIG =====================
SIG2KEY = {
    bytes.fromhex("9DC7"): bytes.fromhex("E55B4ED1"),
}

MAGIC_EXT = {
    0x9e2a83c1: ".uasset",
    0x61754c1b: ".lua",
    0x090a0d7b: ".dat",
    0x007bfeff: ".dat",
    0x200a0d7b: ".dat",
    0x27da0020: ".res",
    0x00000001: ".res",
    0x7bbfbbef: ".res",
    0x44484b42: ".bnk",
}

GZIP_HEADER = b"\x1F\x8B"
MIN_RESULT_SIZE = 32
MAX_OFFSET_TRY  = 8

# ===================== CORE FUNCTIONS =====================
def is_sig_at(data: bytes, i: int):
    if i + 2 > len(data):
        return None
    return SIG2KEY.get(data[i:i+2], None)

def xor_decode_with_feedback(data: bytes) -> bytes:
    out, key, seg_pos, seg_start_out, i = bytearray(), None, 0, 0, 0
    while i < len(data):
        k = is_sig_at(data, i)
        if k is not None:
            key, seg_pos, seg_start_out = k, 0, len(out)
        if key is not None:
            if seg_pos < 4:
                o = data[i] ^ key[seg_pos]
            else:
                fb_index = seg_start_out + (seg_pos - 4)
                o = data[i] ^ out[fb_index]
            out.append(o)
            seg_pos += 1
        else:
            out.append(data[i])
        i += 1
    return bytes(out)

def xor_reencode_from_original(encoded_original: bytes, decoded_modified: bytes) -> bytes:
    out_enc, key, seg_pos, seg_start_out = bytearray(), None, 0, 0
    for i in range(len(decoded_modified)):
        k = is_sig_at(encoded_original, i)
        if k is not None:
            key, seg_pos, seg_start_out = k, 0, i
        if key is not None:
            if seg_pos < 4:
                b = decoded_modified[i] ^ key[seg_pos]
            else:
                fb_index = seg_start_out + (seg_pos - 4)
                b = decoded_modified[i] ^ decoded_modified[fb_index]
            out_enc.append(b)
            seg_pos += 1
        else:
            out_enc.append(decoded_modified[i])
    return bytes(out_enc)

def is_valid_zlib_header(b1: int, b2: int) -> bool:
    if (b1 & 0x0F) != 8: return False
    return ((b1 << 8) | b2) % 31 == 0

def guess_extension(blob: bytes):
    if len(blob) < 4: return ".uexp"
    return MAGIC_EXT.get(int.from_bytes(blob[:4], "little"), ".uexp")

def try_decompress_at(buf: bytes, start: int, max_offset: int = MAX_OFFSET_TRY):
    modes = [('zlib', 15), ('gzip', 31)]
    for ofs in range(0, max_offset + 1):
        s = start + ofs
        if s >= len(buf) - 2: break
        for mode_name, wbits in modes:
            if mode_name == 'zlib':
                if buf[s] != 0x78 or not is_valid_zlib_header(buf[s], buf[s+1]): continue
            if mode_name == 'gzip':
                if not (buf[s] == 0x1F and buf[s+1] == 0x8B): continue
            try:
                d = zlib.decompressobj(wbits)
                res = d.decompress(buf[s:]) + d.flush()
                consumed = len(buf[s:]) - len(d.unused_data)
                if d.eof and consumed > 0 and res and len(res) >= MIN_RESULT_SIZE:
                    return {"result": res, "consumed": consumed, "ofs": ofs}
            except: continue
    return None

def scan_and_extract_smart(data: bytes, out_dir: Path, manifest_path: Path):
    count, pos, entries = 0, 0, []
    def find_next_candidate(p):
        i, j = data.find(b"\x78", p), data.find(GZIP_HEADER, p)
        idxs = [x for x in [i,j] if x != -1]
        return min(idxs) if idxs else -1
    while True:
        cand = find_next_candidate(pos)
        if cand == -1 or cand >= len(data)-2: break
        trial = try_decompress_at(data, cand)
        if trial:
            res, consumed, ofs = trial["result"], trial["consumed"], trial["ofs"]
            count += 1
            ext = guess_extension(res)
            fname = f"{count:06d}{ext}"
            outpath = out_dir / fname
            outpath.write_bytes(res)
            entries.append({"index": count, "start": cand+ofs, "consumed": consumed, "relpath": fname, "ext": ext})
            pos = cand + ofs + consumed
            # 👉 প্রতিটি ফাইল extract হলে টার্মিনালে দেখাও
            print(f"Extracted: {fname} ({len(res)} bytes)")
        else: 
            pos = cand + 1
    json.dump({"total": count, "entries": entries}, open(manifest_path, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    print(f"\n📦 Unpacked {count} files → {out_dir}")
    return count

# ===================== MAIN =====================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Gamepach Tool CLI")
    parser.add_argument("-a", "--apk", help="Input .pak file path", required=True)
    parser.add_argument("outdir", help="Output directory (for unpack/repack)")
    parser.add_argument("-r", "--repack", action="store_true", help="Repack instead of unpack")
    args = parser.parse_args()

    pak_path, outdir = Path(args.apk), Path(args.outdir)
    if not pak_path.exists():
        print(f"❌ File not found: {pak_path}"); sys.exit(1)

    if args.repack:
        # === REPACK ===
        manifest_path = outdir / "manifest.json"
        if not manifest_path.exists():
            print("⚠️ manifest.json not found in output folder"); sys.exit(1)

        data_enc_orig = pak_path.read_bytes()
        decoded = bytearray(xor_decode_with_feedback(data_enc_orig))
        manifest = json.loads(open(manifest_path, encoding="utf-8").read())
        patched_cnt, skipped_cnt = 0, 0

        for e in manifest.get("entries", []):
            relpath, start, consumed = e["relpath"], int(e["start"]), int(e["consumed"])
            src_edit = outdir / relpath
            if not src_edit.exists(): continue
            raw = src_edit.read_bytes()
            comp = zlib.compress(raw, 9)
            if len(comp) <= consumed:
                decoded[start:start+len(comp)] = comp
                if len(comp) < consumed: decoded[start+len(comp):start+consumed] = b"\x00"*(consumed-len(comp))
                patched_cnt += 1
                print(f"Repacked: {relpath}")
            else: skipped_cnt += 1

        encoded_final = xor_reencode_from_original(data_enc_orig, bytes(decoded))
        result_file = outdir / (pak_path.stem + "_repack.pak")
        result_file.write_bytes(encoded_final)
        print(f"\n✅ Repacked → {result_file} | patched={patched_cnt}, skipped={skipped_cnt}")
    else:
        # === UNPACK ===
        outdir.mkdir(parents=True, exist_ok=True)
        data_enc = pak_path.read_bytes()
        decoded = xor_decode_with_feedback(data_enc)
        scan_and_extract_smart(decoded, outdir, outdir / "manifest.json")