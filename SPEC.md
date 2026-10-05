# CoreHash v2 — Formal Specification

**Version:** 2.0 · **Status:** locked · **Type:** CPU-friendly, ASIC/GPU-resistant Proof-of-Work hash.

CoreHash maps an arbitrary byte string to a 256-bit digest. It is designed so that the cost
of computing it is dominated by **latency-bound random access to a 4 MiB scratchpad**, which
(a) keeps old and new CPUs close in per-core throughput and (b) is hostile to GPUs and cheap
ASICs. This document defines the algorithm precisely enough to be re-implemented and audited
independently. The reference implementation is [`src/corehash.cpp`](src/corehash.cpp).

---

## 1. Notation and conventions

- All arithmetic on 64-bit words is **modulo 2⁶⁴** (wrapping), unless stated otherwise.
- `u64` is an unsigned 64-bit integer; `u128` a 128-bit value.
- **Endianness is little-endian everywhere.** `LE64(b)` reads 8 bytes `b[0..8]` as a `u64`
  with `b[0]` least significant. Storing a `u64` writes it least-significant byte first.
- `ROTL64(x, r)` = `((x << r) | (x >> (64 - r)))` for `r` in `0..63` (for `r = 0`, `ROTL64(x,0) = x`).
- `XOR`, `AND`, `OR` are bitwise; `+`, `-`, `*` are mod 2⁶⁴; `mod` is the remainder.
- `a[i:j]` is the byte slice from index `i` (inclusive) to `j` (exclusive).
- Indices into the scratchpad are **word indices** (each word is 8 bytes).

---

## 2. Parameters (constants)

| Name | Value | Meaning |
|------|-------|---------|
| `PAD_BYTES` | `4 194 304` (4 MiB) | scratchpad size in bytes |
| `PAD_WORDS` | `524 288` (2¹⁹) | scratchpad size in 64-bit words |
| `MASK` | `524 287` (2¹⁹ − 1) | address mask (`PAD_WORDS − 1`) |
| `ITERS` | `262 144` (2¹⁸) | dual-lane mixing rounds (⇒ 2¹⁹ memory reads) |
| `GOLDEN` | `0x9E3779B97F4A7C15` | odd multiplier (64-bit fractional golden ratio) |
| `DIGEST` | `32` bytes | output length |

`PAD_WORDS` is a power of two, so `x AND MASK` is a valid word index for any `u64 x`.

---

## 3. Primitives

### 3.1 Blake2b-256
`BLAKE2B(out_len, input)` is Blake2b as defined in **RFC 7693**, unkeyed, with
`digest_length = out_len`, `fanout = 1`, `depth = 1`, and all other parameters zero (the
standard sequential mode). CoreHash uses it only with `out_len = 32`. Reference:
[`src/corehash.cpp`](src/corehash.cpp) `blake2b()`.

### 3.2 AES round
`AESENC(state, key)` is one AES encryption round on a 128-bit block, as defined in
**FIPS-197** and implemented by the x86 `AESENC` instruction:

```
AESENC(state, key) = key XOR MixColumns(ShiftRows(SubBytes(state)))
```

The 128-bit `state` and `key` are the little-endian byte images of the corresponding
16-byte memory regions (i.e. loaded as by `_mm_loadu_si128`). This is a hardware primitive
on every x86 CPU with AES-NI (all Intel/AMD desktop CPUs since ~2010). It is used only to
generate scratchpad contents, not for security-critical encryption.

---

## 4. Algorithm

Input: a byte string `input` of any length. Output: 32-byte digest.

### Step 1 — Seed
```
seed = BLAKE2B(32, input)          // 32 bytes
```

### Step 2 — Scratchpad fill (AES stream)
Let `pad` be `PAD_WORDS` words (4 MiB). Derive two 128-bit keys and a running block, then
fill the pad 16 bytes at a time:
```
k0  = seed[0:16]                   // 128-bit, little-endian image
k1  = seed[16:32]
blk = k0 XOR k1
for j = 0 .. (PAD_BYTES/16 - 1):   // 262144 blocks
    blk = AESENC(blk, k0)
    blk = AESENC(blk, k1)
    store the 16 bytes of blk at pad-bytes [16*j : 16*j + 16]
```
After this, `pad[w] = LE64(pad-bytes[8*w : 8*w + 8])` for `w = 0 .. PAD_WORDS-1`.

### Step 3 — State initialization
```
a = LE64(seed[0:8])
b = LE64(seed[8:16])
c = LE64(seed[16:24])
d = LE64(seed[24:32])
e = ROTL64(a,17) XOR ROTL64(b,31) XOR ROTL64(c,47) XOR d
```

### Step 4 — Mixing loop (dual-lane, latency-bound)
Repeat `ITERS` (262144) times:
```
addr1 = (a XOR b) AND MASK
addr2 = (c XOR d) AND MASK
v1    = pad[addr1]
v2    = pad[addr2]

// lane 1 updates a (branch on the low 2 bits of v1)
switch (v1 AND 3):
  case 0:  a = a + v1;  a = ROTL64(a, (v1 >> 6) AND 63)
  case 1:  a = a XOR (v1 * GOLDEN)
  case 2:  a = (a - v1) XOR ROTL64(b, v1 AND 63)
  case 3:  a = a * (v1 OR 1)

// lane 2 updates c (branch on the low 2 bits of v2)
switch (v2 AND 3):
  case 0:  c = c + v2;  c = ROTL64(c, (v2 >> 6) AND 63)
  case 1:  c = c XOR (v2 * GOLDEN)
  case 2:  c = (c - v2) XOR ROTL64(d, v2 AND 63)
  case 3:  c = c * (v2 OR 1)

// cross-couple the two lanes and the accumulator e
b = b + c                          // uses the updated c
d = d + a                          // uses the updated a
e = ROTL64(e XOR v1 XOR v2, 23)
a = a XOR v2 XOR e
c = c XOR v1 XOR e

// read-modify-write both cells (each write depends on the other lane)
pad[addr1] = v1 + d + e
pad[addr2] = v2 + b + e
```
If `addr1 == addr2` in an iteration, the two reads return the same value and the write to
`addr1` is performed **before** the write to `addr2` (so the `addr2` write wins). This makes
the loop deterministic.

### Step 5 — Finalization
```
fin[0:8]   = LE(a)
fin[8:16]  = LE(b)
fin[16:24] = LE(c)
fin[24:32] = LE(d)
fin[32:40] = LE(e)
fin[40:48] = LE(pad[a AND MASK])
fin[48:56] = LE(pad[c AND MASK])
fin[56:64] = LE(pad[e AND MASK])
output     = BLAKE2B(32, fin[0:64])
```
`output` is the 256-bit CoreHash digest.

---

## 5. Proof-of-Work usage

For mining, `input` is the serialized block header (including the nonce). A block is valid
when `output`, interpreted as a **little-endian 256-bit integer**, is `<= target`, where
`target` is derived from the block's difficulty. Difficulty retargets via LWMA to hold the
network's block interval near the configured block time. (These are consensus rules of the
coin, not of the hash; see [`src/blockchain.cpp`](src/blockchain.cpp) and
[`src/params.cpp`](src/params.cpp).)

---

## 6. Test vectors

`corehash(input)` (hex, from [`src/corehash_vectors.cpp`](src/corehash_vectors.cpp)):

```
input = ""            (0 bytes)  -> a57de1ac579e73be1b2663623ae406d2cd9cd2801c4d08cd257cc0b9766d5774
input = "abc"         (3 bytes)  -> b4eb47486a67515b4048da487d86da178b46805467bb31d7eddc58fb2b93ba09
input = "CoreHash-v2" (11 bytes) -> 01b95fb6f3688c984554aec51a3b47bfad38276924a1877e09fb3c862fdc7df7
input = 80 zero bytes (80 bytes) -> 103a248e3dc30f10a3fc1c987f8a50eb7cb84612dfeea9454927f84de841621c
```

An independent implementation MUST reproduce these exactly. Determinism is verified three
ways, all bit-identical:
- **MSVC (x64)** and **g++ (Linux)** builds of the C++ reference,
- an **independent pure-Python implementation** written from this specification alone
  ([`reference/corehash_ref.py`](reference/corehash_ref.py)) — it reproduces every vector,
  which confirms the specification is complete and unambiguous.

---

## 7. Security properties (measured)

These were measured with the tools in `src/` (build via `build_node.bat`; each prints its
own results). They are empirical evidence, **not** a formal proof.

| Property | Result | Tool |
|----------|--------|------|
| Per-core fairness, i5-2500K vs i7-14650HX | ~1.3× single-thread; old CPU wins per-core at full load | `corehash_bench` |
| AVX2 (4-wide) speedup | 0.62× (slower than scalar) | `avx2_attack` |
| AVX-512 (8-wide) | built, ready to run on AVX-512 hardware | `avx512_attack` |
| Latency-hiding (interleaved streams) | peaks ~1.12× then declines | `latency_test` |
| Scratchpad coverage per hash | ~63% (= 1 − 1/e for 2¹⁹ reads), data-dependent ⇒ fill cannot be skipped | `corehash_audit` |
| Mixing diffusion margin | full avalanche in ~16 of 262144 rounds (~16384× margin) | `corehash_audit` |
| Avalanche (SAC) | mean 0.5001; per-bit ≈ 0.5 | `corehash_analyze` |
| Randomness battery (monobit, runs, chi²,poker, serial corr., longest-run) | all pass on 3 MB | `corehash_battery` |
| Memory safety + UB (ASan/UBSan) | fuzzed clean; found & fixed a `rotl64` shift-by-64 UB (latent cross-platform consensus split) | `fuzz` |
| Thread safety (ThreadSanitizer) | 0 data races under mining + RPC + P2P load; found & fixed a `localtime` race and a non-atomic flag | TSan build of `nhashd` |
| Crash-safe persistence | atomic write (temp + fsync + rename) + corruption-tolerant load | `storage.cpp` |
| Consensus / reorg | deep reorg, clean rollback, over-pay & duplicate rejection | `reorg_test` |
| Constant-time Ed25519 signing | scalar mult uses branchless `cmov` (one double + one add per bit); scalar reduction mod L uses a branchless conditional subtract — no secret-dependent branch, timing, or cache access. Bit-identical to the reference, so RFC 8032 vectors still pass | `ed25519_test` |
| P2P per-peer rate limiting | token bucket (512 burst / 128 msg·s⁻¹) on cheap control messages (GETBLOCKS/GETADDR/HELLO/ADDR); BLOCK/TX exempt (self-throttling); floods are banned | `daemon.cpp` |
| Flow-controlled block sync | GETBLOCKS serves at most one batch (default 500 blocks) so a request can't force serializing the whole chain under lock; the receiver pulls successive batches until caught up | two-node regtest sync test |
| Fee-prioritized, size-bounded block template | miners select mempool txs highest fee-per-byte first and stop before `MAX_BLOCK_SIZE`, so a full mempool (up to 5000 txs ≈ 1.25 MB) can never produce an over-cap block that `connect()` would reject and stall production; the coinbase claims exactly the fees of the included set | `block_template_test` |
| Minimum relay fee (anti-spam) | the mempool refuses loose txs paying below a per-byte floor, so the pool of 5000 slots can't be flooded for free; strictly a *relay policy* — cheaper txs are still consensus-valid, so it can never fork the chain — and sized well under the pool's payout fee (which itself sizes to tx bytes) | `block_template_test` |
| Checkpoints | a block at a pinned height must have the pinned hash, so no reorg can rewrite history at or below the last checkpoint (a side branch that diverges earlier can never present the right hash); mainnet-only (regtest has none) and matched to the live chain, so honest sync is unaffected | `block_template_test` |
| Peer misbehavior scoring | faults accrue points and a peer is banned only past a threshold (invalid block 100 = instant; a flood trip or one corrupted frame 50), so a single hiccup on a flaky link no longer earns an hour-long ban while repeated abuse still does | `daemon.cpp` |

**Resistance mechanisms:**
1. **Latency-bound serial dependency** — each iteration's addresses depend on the previous
   iteration's state, so a single hash is a dependency chain that stalls on memory.
2. **Dual-lane reads** — two independent reads in flight per iteration saturate a single
   core's memory-level parallelism, shrinking the gain from running many parallel streams.
3. **Data-dependent branch** (`v AND 3`) — forces SIMD to compute all branches and select,
   and causes warp divergence on GPUs.
4. **Full 4 MiB working set with random 8-byte access** — hostile to GPUs (thousands of
   threads × 4 MiB, uncoalesced) and expensive for ASICs (SRAM per core). The 4 MiB size
   fits an i5-2500K's 6 MiB L3 for a single thread; larger would slow old single-thread,
   smaller would let many-core CPUs pull ahead.
5. **AES-NI fill** — equal speed on all 2010+ x86 CPUs, removing the compute-bound,
   vectorizable fill that gave newer CPUs an edge in v1.

---

## 8. Design rationale (v1 → v2)

- **v1** filled with ChaCha8 (a compute-bound ~22% of the hash that AVX2 could accelerate)
  and mixed one lane with a single read per iteration.
- **v2** replaces the fill with AES-NI (equal old/new, ~5.6% of the hash), adds the second
  memory lane and the `e` accumulator with cross-coupling, and derives addresses from the
  full state. This improved measured per-core fairness (~1.7× → ~1.3×), worsened the AVX2
  attack's speedup (0.90× → 0.62×), and reduced the latency-hiding gain (1.23× → 1.12×),
  while passing the deep audit and statistical battery.

---

## 9. Non-goals and known limitations (honest)

- **No formal cryptanalysis or third-party audit** has been performed. The evidence in §7 is
  empirical. A production coin with real value SHOULD obtain an independent review.
- **Requires x86 AES-NI.** There is currently no portable/ARM fallback for the fill; a
  non-AES CPU cannot compute CoreHash with the reference code as built.
- **Not ASIC-proof.** A dedicated ASIC with 4 MiB of on-die SRAM per core is buildable; the
  design raises the cost, it does not make it infinite. No CPU PoW is ASIC-proof.
- **Verification cost equals mining cost** (~one hash). This is inherent to memory-hard PoW
  and acceptable at multi-minute block times.
- CoreHash provides no privacy properties; it is a PoW hash, not a commitment or MAC scheme.

---

## 10. References

- **RFC 7693** — The BLAKE2 Cryptographic Hash and MAC.
- **FIPS-197** — Advanced Encryption Standard (AES); the `AESENC` round.
- Reference implementation (C++): [`src/corehash.cpp`](src/corehash.cpp), header
  [`src/corehash.h`](src/corehash.h).
- Independent second implementation (Python): [`reference/corehash_ref.py`](reference/corehash_ref.py).
- Analysis tools: `corehash_bench`, `avx2_attack`, `avx512_attack`, `latency_test`,
  `corehash_analyze`, `corehash_audit`, `corehash_battery` (all in `src/`).

---

## Appendix A — Reference pseudocode (complete)

```
function CoreHash(input) -> 32 bytes:
    seed = BLAKE2B(32, input)

    # fill 4 MiB scratchpad
    k0 = seed[0:16]; k1 = seed[16:32]; blk = k0 XOR k1
    for j in 0 .. 262143:
        blk = AESENC(blk, k0); blk = AESENC(blk, k1)
        pad_bytes[16j : 16j+16] = blk
    # pad[w] = LE64(pad_bytes[8w : 8w+8]),  w in 0..524287

    a = LE64(seed[0:8]);  b = LE64(seed[8:16])
    c = LE64(seed[16:24]); d = LE64(seed[24:32])
    e = ROTL64(a,17) XOR ROTL64(b,31) XOR ROTL64(c,47) XOR d

    for i in 0 .. 262143:
        addr1 = (a XOR b) AND 524287
        addr2 = (c XOR d) AND 524287
        v1 = pad[addr1]; v2 = pad[addr2]
        a = LANE(a, b, v1)          # the 4-way switch of §4, lane 1
        c = LANE(c, d, v2)          # the 4-way switch of §4, lane 2
        b = b + c; d = d + a
        e = ROTL64(e XOR v1 XOR v2, 23)
        a = a XOR v2 XOR e; c = c XOR v1 XOR e
        pad[addr1] = v1 + d + e; pad[addr2] = v2 + b + e

    fin = LE(a)||LE(b)||LE(c)||LE(d)||LE(e)
        || LE(pad[a AND 524287]) || LE(pad[c AND 524287]) || LE(pad[e AND 524287])
    return BLAKE2B(32, fin)

function LANE(x, partner, v) -> u64:
    switch (v AND 3):
      0: x = x + v;  return ROTL64(x, (v >> 6) AND 63)
      1: return x XOR (v * 0x9E3779B97F4A7C15)
      2: return (x - v) XOR ROTL64(partner, v AND 63)
      3: return x * (v OR 1)
```
