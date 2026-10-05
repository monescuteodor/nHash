// Latency-hiding / parallelism stress test for CoreHash (the real GPU/ASIC question).
//
// A GPU or ASIC does NOT beat a CPU with wider SIMD (see avx2_attack.cpp - AVX2 loses).
// It wins, if at all, by running MANY independent hashes at once to hide memory latency:
// a latency-bound loop stalls a single stream waiting on RAM, but K independent streams
// can keep K memory requests in flight. This test emulates that on ONE CPU core by
// interleaving K independent hash streams and measuring how throughput scales with K.
//
//   * If H/s scales up with K  -> latency is hidable -> a massively parallel device could
//                                 win: the "latency-bound => GPU-resistant" premise is weak.
//   * If H/s plateaus/drops    -> capacity + random-access bandwidth (4 MB per hash) is the
//                                 real wall: more parallelism just thrashes cache -> resistant.
//
// Build: g++ -O2 -std=c++17 (no special ISA needed).  Usage: latency_test [seconds=4]
#include "corehash.h"
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <chrono>
#include <immintrin.h>

using namespace ch;

static inline uint64_t rotl64s(uint64_t x, int n) { return (x << n) | (x >> (64 - n)); }
static const uint64_t GOLDEN = 0x9E3779B97F4A7C15ULL;

// v2 AES-NI fill (matches src/corehash.cpp).
static void fill_scratchpad(uint64_t* pad, size_t words, const uint8_t seed[32]) {
    __m128i k0 = _mm_loadu_si128((const __m128i*)seed);
    __m128i k1 = _mm_loadu_si128((const __m128i*)(seed + 16));
    __m128i blk = _mm_xor_si128(k0, k1);
    __m128i* out = (__m128i*)pad; size_t nblk = (words * 8) / 16;
    for (size_t i = 0; i < nblk; i++) { blk = _mm_aesenc_si128(blk, k0); blk = _mm_aesenc_si128(blk, k1); _mm_storeu_si128(out + i, blk); }
}
// One v2 dual-lane mixing iteration: TWO independent reads in flight per step.
static inline void mix_step(uint64_t* pad, uint64_t mask,
                            uint64_t& a, uint64_t& b, uint64_t& c, uint64_t& d, uint64_t& e) {
    uint64_t addr1 = (a ^ b) & mask, addr2 = (c ^ d) & mask;
    uint64_t v1 = pad[addr1], v2 = pad[addr2];
    switch (v1 & 3) {
        case 0:  a = a + v1; a = rotl64s(a, (int)((v1 >> 6) & 63)); break;
        case 1:  a = a ^ (v1 * GOLDEN);                            break;
        case 2:  a = (a - v1) ^ rotl64s(b, (int)(v1 & 63));        break;
        default: a = a * (v1 | 1ULL);                              break;
    }
    switch (v2 & 3) {
        case 0:  c = c + v2; c = rotl64s(c, (int)((v2 >> 6) & 63)); break;
        case 1:  c = c ^ (v2 * GOLDEN);                            break;
        case 2:  c = (c - v2) ^ rotl64s(d, (int)(v2 & 63));        break;
        default: c = c * (v2 | 1ULL);                              break;
    }
    b += c; d += a; e = rotl64s(e ^ v1 ^ v2, 23); a ^= v2 ^ e; c ^= v1 ^ e;
    pad[addr1] = v1 + d + e; pad[addr2] = v2 + b + e;
}

// Run K independent streams interleaved in one thread for the given wall-clock budget.
// Returns hashes/second (a "hash" = one full COREHASH_ITERS mixing pass, matching real work).
static double bench_interleaved(int K, double seconds) {
    const uint64_t pw = COREHASH_PAD_WORDS, mask = pw - 1;
    std::vector<uint64_t*> pads(K);
    for (int k = 0; k < K; k++) pads[k] = (uint64_t*)malloc(pw * 8);
    std::vector<uint64_t> a(K), b(K), c(K), d(K), e(K);
    const char* hdr = "CoreHash-latency-test-000";
    uint64_t nonce = 0, done = 0;

    auto reseed = [&](int k) {
        uint8_t seed[32], buf[64]; size_t hl = strlen(hdr);
        memcpy(buf, hdr, hl); uint64_t nn = nonce++; memcpy(buf + hl, &nn, 8);
        blake2b(seed, 32, buf, hl + 8);
        fill_scratchpad(pads[k], pw, seed);
        memcpy(&a[k], seed, 8); memcpy(&b[k], seed + 8, 8);
        memcpy(&c[k], seed + 16, 8); memcpy(&d[k], seed + 24, 8);
        e[k] = rotl64s(a[k], 17) ^ rotl64s(b[k], 31) ^ rotl64s(c[k], 47) ^ d[k];
    };
    for (int k = 0; k < K; k++) reseed(k);

    auto t0 = std::chrono::steady_clock::now();
    auto elapsed = [&]{ return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count(); };

    while (elapsed() < seconds) {
        // One full mixing pass for all K streams, interleaved so their reads overlap.
        for (uint64_t i = 0; i < COREHASH_ITERS; i++)
            for (int k = 0; k < K; k++)
                mix_step(pads[k], mask, a[k], b[k], c[k], d[k], e[k]);
        done += K;               // K hashes' worth of mixing completed
        for (int k = 0; k < K; k++) reseed(k);   // fresh work (includes fill, like real mining)
    }
    double dt = elapsed();
    for (int k = 0; k < K; k++) free(pads[k]);
    // prevent the whole thing being optimized away
    volatile uint64_t sink = 0; for (int k = 0; k < K; k++) sink ^= a[k] ^ e[k]; (void)sink;
    return done / dt;
}

int main(int argc, char** argv) {
    double seconds = (argc > 1) ? atof(argv[1]) : 4.0; if (seconds < 1) seconds = 1;
    printf("CoreHash latency-hiding test  (single thread, interleaved streams)\n");
    printf("each stream = 4 MB scratchpad, %llu iters.  %.0fs per K.\n\n",
           (unsigned long long)COREHASH_ITERS, seconds);
    printf("%-4s %-12s %-10s %s\n", "K", "H/s", "per-stream", "working set");
    double base = 0;
    for (int K : {1, 2, 3, 4, 6, 8}) {
        double hs = bench_interleaved(K, seconds);
        if (K == 1) base = hs;
        printf("%-4d %-12.1f %-10.1f %d MB   %s\n", K, hs, hs / K, K * 4,
               (K * 4 <= 24) ? "" : "(exceeds L3)");
        (void)base;
    }
    printf("\nRead per-stream: if it stays ~flat, latency IS hidden by parallelism (a GPU/ASIC\n");
    printf("threat). If per-stream throughput collapses as the working set grows, capacity +\n");
    printf("random-access bandwidth is the wall -> parallel hardware just thrashes cache.\n");
    return 0;
}
