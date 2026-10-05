// AVX-512 stress test / optimization attack on CoreHash v2 (dual-lane mix, AES-NI fill).
//
// The strongest SIMD attack a CPU can mount. Unlike AVX2, AVX-512 has the weapons that
// hurt this design in principle:
//   * native SCATTER  (_mm512_i64scatter_epi64) - AVX2 had none, forcing scalar writes
//   * native 64-bit MULTIPLY (_mm512_mullo_epi64, AVX-512DQ) - AVX2 had to emulate it
//   * native variable ROTATE (_mm512_rolv_epi64)
//   * 8 lanes (8 nonces at once) and mask registers for branch selection
// If any wide-SIMD approach can beat scalar, this is it. It processes 8 nonces at once and
// verifies output bit-identical to ch::corehash.
//
// This machine may not have AVX-512 (most consumer Intel chips fuse it off): the program
// checks CPUID at startup and exits cleanly if AVX-512F+DQ are missing, so it is safe to
// ship and run anywhere. On AVX-512 hardware (Zen4/Zen5, many Xeons) it runs the real test.
//
// Build: /arch:AVX512 (MSVC)  or  -mavx512f -mavx512dq -maes -mavx2 (g++).
// Usage: avx512_attack [seconds=5]
#include "corehash.h"
#include <immintrin.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <chrono>
#ifdef _WIN32
  #include <intrin.h>
#else
  #include <cpuid.h>
#endif

using namespace ch;

static inline uint64_t rotl64s(uint64_t x, int n) { return (x << n) | (x >> (64 - n)); }
static const uint64_t GOLDEN = 0x9E3779B97F4A7C15ULL;

static bool has_avx512() {
    int r[4] = {0,0,0,0};
#ifdef _WIN32
    __cpuidex(r, 7, 0);
#else
    __cpuid_count(7, 0, r[0], r[1], r[2], r[3]);
#endif
    bool f  = (r[1] >> 16) & 1;   // AVX-512F
    bool dq = (r[1] >> 17) & 1;   // AVX-512DQ (mullo_epi64)
    return f && dq;
}

// v2 AES-NI fill (identical to corehash.cpp; used by both paths).
static void fill_scratchpad(uint64_t* pad, size_t words, const uint8_t seed[32]) {
    __m128i k0 = _mm_loadu_si128((const __m128i*)seed);
    __m128i k1 = _mm_loadu_si128((const __m128i*)(seed + 16));
    __m128i blk = _mm_xor_si128(k0, k1);
    __m128i* out = (__m128i*)pad; size_t nblk = (words * 8) / 16;
    for (size_t i = 0; i < nblk; i++) { blk = _mm_aesenc_si128(blk, k0); blk = _mm_aesenc_si128(blk, k1); _mm_storeu_si128(out + i, blk); }
}
static void seed_state(const uint8_t* in, size_t len, uint8_t seed[32],
                       uint64_t& a, uint64_t& b, uint64_t& c, uint64_t& d, uint64_t& e) {
    blake2b(seed, 32, in, len);
    memcpy(&a, seed, 8); memcpy(&b, seed + 8, 8); memcpy(&c, seed + 16, 8); memcpy(&d, seed + 24, 8);
    e = rotl64s(a, 17) ^ rotl64s(b, 31) ^ rotl64s(c, 47) ^ d;
}
static void finalize(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e,
                     const uint64_t* pad, uint64_t mask, uint8_t out[32]) {
    uint8_t fin[64];
    memcpy(fin, &a, 8); memcpy(fin + 8, &b, 8); memcpy(fin + 16, &c, 8); memcpy(fin + 24, &d, 8); memcpy(fin + 32, &e, 8);
    uint64_t s0 = pad[a & mask], s1 = pad[c & mask], s2 = pad[e & mask];
    memcpy(fin + 40, &s0, 8); memcpy(fin + 48, &s1, 8); memcpy(fin + 56, &s2, 8);
    blake2b(out, 32, fin, 64);
}

// ---- scalar reference (v2) ----
static void corehash_scalar(const uint8_t* hdr, size_t hlen, uint64_t nonce, uint8_t out[32], uint64_t* pad) {
    const uint64_t mask = COREHASH_PAD_WORDS - 1;
    uint64_t a, b, c, d, e; uint8_t seed[32], buf[128];
    size_t hl = hlen > 100 ? 100 : hlen; memcpy(buf, hdr, hl); memcpy(buf + hl, &nonce, 8);
    seed_state(buf, hl + 8, seed, a, b, c, d, e);
    fill_scratchpad(pad, COREHASH_PAD_WORDS, seed);
    for (uint64_t i = 0; i < COREHASH_ITERS; i++) {
        uint64_t addr1 = (a ^ b) & mask, addr2 = (c ^ d) & mask;
        uint64_t v1 = pad[addr1], v2 = pad[addr2];
        switch (v1 & 3) {
            case 0: a = a + v1; a = rotl64s(a, (int)((v1 >> 6) & 63)); break;
            case 1: a = a ^ (v1 * GOLDEN); break;
            case 2: a = (a - v1) ^ rotl64s(b, (int)(v1 & 63)); break;
            default:a = a * (v1 | 1ULL); break; }
        switch (v2 & 3) {
            case 0: c = c + v2; c = rotl64s(c, (int)((v2 >> 6) & 63)); break;
            case 1: c = c ^ (v2 * GOLDEN); break;
            case 2: c = (c - v2) ^ rotl64s(d, (int)(v2 & 63)); break;
            default:c = c * (v2 | 1ULL); break; }
        b += c; d += a; e = rotl64s(e ^ v1 ^ v2, 23); a ^= v2 ^ e; c ^= v1 ^ e;
        pad[addr1] = v1 + d + e; pad[addr2] = v2 + b + e;
    }
    finalize(a, b, c, d, e, pad, mask, out);
}

// ============================================================================
// AVX-512 path (guarded at runtime by has_avx512()). Only executes on capable HW.
// ============================================================================
#if defined(_MSC_VER)
  #define TARGET512
#else
  #define TARGET512 __attribute__((target("avx512f,avx512dq,avx2,aes")))
#endif

// One lane's branch (v2), 8-wide. Updates X using value V and partner P.
TARGET512
static inline __m512i branch_lane8(__m512i X, __m512i P, __m512i V) {
    const __m512i v3 = _mm512_set1_epi64(3), v63 = _mm512_set1_epi64(63),
                  vone = _mm512_set1_epi64(1), vgold = _mm512_set1_epi64((long long)GOLDEN);
    __m512i t   = _mm512_and_si512(V, v3);
    __m512i cnt0 = _mm512_and_si512(_mm512_srli_epi64(V, 6), v63);
    __m512i r0  = _mm512_rolv_epi64(_mm512_add_epi64(X, V), cnt0);
    __m512i r1  = _mm512_xor_si512(X, _mm512_mullo_epi64(V, vgold));
    __m512i cnt2 = _mm512_and_si512(V, v63);
    __m512i r2  = _mm512_xor_si512(_mm512_sub_epi64(X, V), _mm512_rolv_epi64(P, cnt2));
    __m512i r3  = _mm512_mullo_epi64(X, _mm512_or_si512(V, vone));
    __m512i res = r3;
    res = _mm512_mask_blend_epi64(_mm512_cmpeq_epi64_mask(t, _mm512_set1_epi64(2)), res, r2);
    res = _mm512_mask_blend_epi64(_mm512_cmpeq_epi64_mask(t, _mm512_set1_epi64(1)), res, r1);
    res = _mm512_mask_blend_epi64(_mm512_cmpeq_epi64_mask(t, _mm512_setzero_si512()), res, r0);
    return res;
}

TARGET512
static void corehash_x8(const uint8_t* hdr, size_t hlen, uint64_t nonce0, uint8_t out[8][32], uint64_t* pad8) {
    const uint64_t pw = COREHASH_PAD_WORDS, mask = pw - 1;
    uint64_t A[8], B[8], C[8], D[8], E[8]; uint8_t seed[32], buf[128];
    size_t hl = hlen > 100 ? 100 : hlen;
    for (int l = 0; l < 8; l++) {
        uint64_t nonce = nonce0 + l; memcpy(buf, hdr, hl); memcpy(buf + hl, &nonce, 8);
        seed_state(buf, hl + 8, seed, A[l], B[l], C[l], D[l], E[l]);
        fill_scratchpad(pad8 + (size_t)l * pw, pw, seed);
    }
    __m512i a = _mm512_loadu_si512(A), b = _mm512_loadu_si512(B), c = _mm512_loadu_si512(C),
            d = _mm512_loadu_si512(D), e = _mm512_loadu_si512(E);
    const __m512i vmask = _mm512_set1_epi64((long long)mask);
    const __m512i lanebase = _mm512_set_epi64((long long)(7*pw),(long long)(6*pw),(long long)(5*pw),(long long)(4*pw),
                                              (long long)(3*pw),(long long)(2*pw),(long long)(1*pw),0);
    for (uint64_t i = 0; i < COREHASH_ITERS; i++) {
        __m512i addr1 = _mm512_and_si512(_mm512_xor_si512(a, b), vmask);
        __m512i addr2 = _mm512_and_si512(_mm512_xor_si512(c, d), vmask);
        __m512i idx1 = _mm512_add_epi64(addr1, lanebase), idx2 = _mm512_add_epi64(addr2, lanebase);
        __m512i v1 = _mm512_i64gather_epi64(idx1, (const long long*)pad8, 8);
        __m512i v2 = _mm512_i64gather_epi64(idx2, (const long long*)pad8, 8);
        __m512i na = branch_lane8(a, b, v1);
        __m512i nc = branch_lane8(c, d, v2);
        b = _mm512_add_epi64(b, nc);
        d = _mm512_add_epi64(d, na);
        e = _mm512_rol_epi64(_mm512_xor_si512(e, _mm512_xor_si512(v1, v2)), 23);
        a = _mm512_xor_si512(na, _mm512_xor_si512(v2, e));
        c = _mm512_xor_si512(nc, _mm512_xor_si512(v1, e));
        __m512i wr1 = _mm512_add_epi64(v1, _mm512_add_epi64(d, e));
        __m512i wr2 = _mm512_add_epi64(v2, _mm512_add_epi64(b, e));
        _mm512_i64scatter_epi64((long long*)pad8, idx1, wr1, 8);
        _mm512_i64scatter_epi64((long long*)pad8, idx2, wr2, 8);
    }
    _mm512_storeu_si512(A, a); _mm512_storeu_si512(B, b); _mm512_storeu_si512(C, c);
    _mm512_storeu_si512(D, d); _mm512_storeu_si512(E, e);
    for (int l = 0; l < 8; l++) finalize(A[l], B[l], C[l], D[l], E[l], pad8 + (size_t)l * pw, mask, out[l]);
}

static double now_s() { return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count(); }

int main(int argc, char** argv) {
    int seconds = (argc > 1) ? atoi(argv[1]) : 5; if (seconds < 1) seconds = 1;
    const uint64_t pw = COREHASH_PAD_WORDS;
    const char* hdr = "CoreHash-avx512-attack-header"; size_t hlen = strlen(hdr);

    printf("CoreHash v2 AVX-512 attack  (8 nonces/iteration, dual-lane, single thread)\n");
    printf("scratchpad=4MB  iters=%llu\n\n", (unsigned long long)COREHASH_ITERS);

    if (!has_avx512()) {
        printf("This CPU does not report AVX-512F+DQ -> cannot run the AVX-512 path here.\n");
        printf("(Most consumer Intel chips fuse AVX-512 off. Run this on Zen4/Zen5 or a Xeon.)\n");
        printf("The program is built and ready; it will run the real test on AVX-512 hardware.\n");
        return 2;
    }

    uint64_t* pad1 = (uint64_t*)malloc(pw * 8);
    uint64_t* pad8 = (uint64_t*)malloc(8 * pw * 8);
    if (!pad1 || !pad8) { printf("alloc failed (need ~32 MB for 8 scratchpads)\n"); return 1; }

    bool ok = true;
    for (uint64_t base = 0; base < 8 && ok; base += 8) {
        uint8_t o8[8][32]; corehash_x8((const uint8_t*)hdr, hlen, base, o8, pad8);
        for (int l = 0; l < 8; l++) {
            uint8_t os[32]; corehash_scalar((const uint8_t*)hdr, hlen, base + l, os, pad1);
            uint8_t oref[32]; uint8_t buf[128]; size_t hl = hlen; uint64_t nonce = base + l;
            memcpy(buf, hdr, hl); memcpy(buf + hl, &nonce, 8);
            CoreHashCtx ctx; corehash(buf, hl + 8, oref, ctx);
            if (memcmp(o8[l], os, 32) != 0 || memcmp(o8[l], oref, 32) != 0) {
                printf("MISMATCH at nonce %llu\n", (unsigned long long)(base + l)); ok = false; break;
            }
        }
    }
    if (!ok) { printf("\nAVX-512 output does NOT match the reference -> not a valid attack.\n"); free(pad1); free(pad8); return 1; }
    printf("correctness: AVX-512 x8 == scalar == ch::corehash  (bit-identical) OK\n\n");

    double scalar_hs;
    { uint8_t o[32]; uint64_t n = 0, cnt = 0; double t0 = now_s();
      while (now_s() - t0 < seconds) { corehash_scalar((const uint8_t*)hdr, hlen, n++, o, pad1); cnt++; }
      double dt = now_s() - t0; scalar_hs = cnt / dt;
      printf("scalar     : %8.1f H/s  (%llu hashes in %.2fs)\n", scalar_hs, (unsigned long long)cnt, dt); }
    double avx512_hs;
    { uint8_t o8[8][32]; uint64_t n = 0, cnt = 0; double t0 = now_s();
      while (now_s() - t0 < seconds) { corehash_x8((const uint8_t*)hdr, hlen, n, o8, pad8); n += 8; cnt += 8; }
      double dt = now_s() - t0; avx512_hs = cnt / dt;
      printf("AVX-512 x8 : %8.1f H/s  (%llu hashes in %.2fs)\n", avx512_hs, (unsigned long long)cnt, dt); }

    printf("\nspeedup (AVX-512 / scalar): %.2fx\n", avx512_hs / scalar_hs);
    if (avx512_hs <= scalar_hs * 1.15) printf("=> AVX-512 gives NO meaningful advantage: the mixing loop resists SIMD.\n");
    else printf("=> AVX-512 IS faster by %.0f%%: a fairness weakness to investigate.\n", 100.0 * (avx512_hs / scalar_hs - 1.0));
    free(pad1); free(pad8); return 0;
}
