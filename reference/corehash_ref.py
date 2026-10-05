#!/usr/bin/env python3
"""
CoreHash v2 — independent reference implementation (pure Python), written from SPEC.md.

Purpose: cross-verify the C++ reference. It reproduces the algorithm from the specification
alone and must yield bit-identical digests. It is intentionally simple, not fast — a
correctness reference, not a miner.

Run:
  python corehash_ref.py fill     # quick: check the AES fill against the known-good dump
  python corehash_ref.py vectors  # full: check the published test vectors (slow, ~minutes)
"""
import sys, hashlib

M64 = (1 << 64) - 1
GOLDEN = 0x9E3779B97F4A7C15
PAD_WORDS = 524288        # 2^19
PAD_BYTES = PAD_WORDS * 8 # 4 MiB
MASK = PAD_WORDS - 1
ITERS = 262144            # 2^18

def rotl64(x, r):
    r &= 63
    if r == 0:
        return x & M64
    return ((x << r) | (x >> (64 - r))) & M64

# ---- AES round (FIPS-197), matching the x86 AESENC instruction ----
SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")

def xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11b
    return a & 0xff

def aes_round(state, key):
    # SubBytes
    s = [SBOX[b] for b in state]
    # ShiftRows: column-major state, row r shifted left by r
    t = [0] * 16
    for c in range(4):
        for r in range(4):
            t[4 * c + r] = s[4 * ((c + r) & 3) + r]
    s = t
    # MixColumns
    o = [0] * 16
    for c in range(4):
        a0, a1, a2, a3 = s[4*c], s[4*c+1], s[4*c+2], s[4*c+3]
        o[4*c+0] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3
        o[4*c+1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3
        o[4*c+2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3)
        o[4*c+3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3)
    # AddRoundKey
    return bytes(o[i] ^ key[i] for i in range(16))

def blake2b_256(data):
    return hashlib.blake2b(data, digest_size=32).digest()

def fill_blocks(seed, nblocks):
    k0, k1 = seed[0:16], seed[16:32]
    blk = bytes(a ^ b for a, b in zip(k0, k1))
    out = bytearray()
    for _ in range(nblocks):
        blk = aes_round(aes_round(blk, k0), k1)
        out += blk
    return bytes(out)

def le64(b, off):
    return int.from_bytes(b[off:off+8], "little")

def corehash(data):
    seed = blake2b_256(data)
    padb = bytearray(fill_blocks(seed, PAD_BYTES // 16))
    pad = list(int.from_bytes(padb[i*8:i*8+8], "little") for i in range(PAD_WORDS))

    a = le64(seed, 0); b = le64(seed, 8); c = le64(seed, 16); d = le64(seed, 24)
    e = rotl64(a, 17) ^ rotl64(b, 31) ^ rotl64(c, 47) ^ d

    for _ in range(ITERS):
        a1 = (a ^ b) & MASK
        a2 = (c ^ d) & MASK
        v1 = pad[a1]; v2 = pad[a2]
        m = v1 & 3
        if m == 0:   a = (a + v1) & M64; a = rotl64(a, (v1 >> 6) & 63)
        elif m == 1: a = a ^ ((v1 * GOLDEN) & M64)
        elif m == 2: a = ((a - v1) & M64) ^ rotl64(b, v1 & 63)
        else:        a = (a * (v1 | 1)) & M64
        m = v2 & 3
        if m == 0:   c = (c + v2) & M64; c = rotl64(c, (v2 >> 6) & 63)
        elif m == 1: c = c ^ ((v2 * GOLDEN) & M64)
        elif m == 2: c = ((c - v2) & M64) ^ rotl64(d, v2 & 63)
        else:        c = (c * (v2 | 1)) & M64
        b = (b + c) & M64
        d = (d + a) & M64
        e = rotl64(e ^ v1 ^ v2, 23)
        a = a ^ v2 ^ e
        c = c ^ v1 ^ e
        pad[a1] = (v1 + d + e) & M64
        pad[a2] = (v2 + b + e) & M64

    fin = b"".join(x.to_bytes(8, "little") for x in (a, b, c, d, e))
    fin += pad[a & MASK].to_bytes(8, "little")
    fin += pad[c & MASK].to_bytes(8, "little")
    fin += pad[e & MASK].to_bytes(8, "little")
    return blake2b_256(fin)

# ---- checks ----
KNOWN_SEED_EMPTY = "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
KNOWN_FILL64 = ("4f6e64d3864f1d86f2bf36e8f61de1144caed6811a19d2eb37eaa26875498ebe"
                "41b72848fcf8a6057c7737647fa7e94ddb805c5ff61f6ad19abf3b8679ecb141")
VECTORS = [
    (b"",                    "a57de1ac579e73be1b2663623ae406d2cd9cd2801c4d08cd257cc0b9766d5774"),
    (b"abc",                 "b4eb47486a67515b4048da487d86da178b46805467bb31d7eddc58fb2b93ba09"),
    (b"CoreHash-v2",         "01b95fb6f3688c984554aec51a3b47bfad38276924a1877e09fb3c862fdc7df7"),
    (bytes(80),              "103a248e3dc30f10a3fc1c987f8a50eb7cb84612dfeea9454927f84de841621c"),
]

def check_fill():
    seed = blake2b_256(b"")
    ok_seed = seed.hex() == KNOWN_SEED_EMPTY
    print(f"seed(empty): {seed.hex()}  {'OK' if ok_seed else 'MISMATCH'}")
    got = fill_blocks(seed, 4).hex()
    ok_fill = got == KNOWN_FILL64
    print(f"fill[0:64] : {got}")
    print(f"             {'OK — AES round matches hardware AESENC' if ok_fill else 'MISMATCH — AES byte order is off'}")
    return ok_seed and ok_fill

def check_vectors():
    allok = True
    for data, want in VECTORS:
        got = corehash(data).hex()
        ok = got == want
        allok &= ok
        label = repr(data) if len(data) <= 12 else f"{len(data)} bytes"
        print(f"{label:16} -> {got}  {'OK' if ok else 'MISMATCH want '+want}")
    return allok

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "fill"
    if mode == "fill":
        sys.exit(0 if check_fill() else 1)
    elif mode == "vectors":
        if not check_fill():
            print("fill check failed; aborting."); sys.exit(1)
        print("--- full test vectors (slow) ---")
        sys.exit(0 if check_vectors() else 1)
    else:
        print("usage: corehash_ref.py [fill|vectors]"); sys.exit(2)
