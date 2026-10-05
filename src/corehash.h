// CoreHash v2 - CPU-friendly, ASIC/GPU-resistant Proof-of-Work.
//
// v2 changes over v1 (all measured on i5-2500K .. i7-14650HX):
//   * Scratchpad fill uses AES-NI instead of ChaCha8. AES-NI exists on every x86 CPU
//     since ~2010 (the i5-2500K included) and is one hardware instruction, equally fast
//     on old and new CPUs -> removes the ~22% compute-bound, AVX2-vectorizable fill that
//     let modern CPUs pull ahead in v1.
//   * The mixing loop issues TWO independent memory reads per iteration (dual-lane) and
//     cross-couples them, so a single hash keeps 2 memory requests in flight. This
//     saturates memory-level parallelism within one hash and shrinks the advantage a
//     massively parallel device (GPU/ASIC) gets from running many streams to hide latency.
//   * Addresses depend on the full state and an extra accumulator (e) -> better diffusion.
//
//   Parameters LOCKED: 4 MB scratchpad (fits Sandy Bridge's 6 MB L3), 2^18 dual-lane
//   rounds (= 2^19 memory reads, matching v1's memory traffic).
#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>

namespace ch {

// One-shot Blake2b (RFC 7693), no key, outlen <= 64. Used throughout the codebase
// as the general-purpose 256-bit hash (seed, merkle, txid, block id helpers).
void blake2b(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen);

// --- CoreHash PoW parameters (LOCKED v2) ---
constexpr size_t   COREHASH_PAD_BYTES = 4u * 1024 * 1024;      // 4 MB
constexpr size_t   COREHASH_PAD_WORDS = COREHASH_PAD_BYTES / 8; // 524288
constexpr uint64_t COREHASH_ITERS     = 262144;                // 2^18 dual-lane rounds

// Reusable context holding the scratchpad, so a miner avoids re-allocating 4 MB on every
// nonce. One context per thread. The scratchpad is allocated on HUGE/LARGE pages when the
// OS allows it (fewer TLB misses on the random 4 MB access -> ~15-30% more hashrate and
// better hashes-per-watt), falling back to normal pages otherwise. Non-copyable (owns the
// allocation). The allocation method never changes the hash output.
struct CoreHashCtx {
    uint64_t* pad_ptr    = nullptr;
    int       alloc_kind = 0;      // internal: how pad_ptr was allocated
    unsigned long long alloc_bytes = 0;
    CoreHashCtx();
    ~CoreHashCtx();
    CoreHashCtx(const CoreHashCtx&) = delete;
    CoreHashCtx& operator=(const CoreHashCtx&) = delete;
    uint64_t* data() { return pad_ptr; }
};

// True if any scratchpad in this process was allocated on huge/large pages.
bool corehash_using_huge_pages();

// Compute CoreHash of `input` (typically a serialized 80-byte block header, nonce
// included) into out[32]. Deterministic and endian-independent across platforms.
void corehash(const uint8_t* input, size_t len, uint8_t out[32], CoreHashCtx& ctx);

} // namespace ch
