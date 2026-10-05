// AVX2 stress test / optimization attack on CoreHash v2 (dual-lane mix, AES-NI fill).
//
// Processes 4 nonces at once, one per 64-bit AVX2 lane. This is the realistic miner
// optimization and the real fairness threat: modern CPUs have AVX2, the i5-2500K has only
// AVX1, so a large AVX2 win would put old CPUs at a disadvantage. Output is verified
// bit-identical to ch::corehash. The AES-NI fill and final Blake2b are identical (scalar)
// in both paths, so the comparison isolates the security-critical dual-lane mixing loop.
//
// Build (needs AVX2 + AES): /arch:AVX2 (MSVC) or -mavx2 -maes (g++).
// Usage: avx2_attack [seconds=5]
#include "corehash.h"
#include <immintrin.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <chrono>

using namespace ch;

static inline uint64_t rotl64s(uint64_t x, int n) { return (x << n) | (x >> (64 - n)); }
static const uint64_t GOLDEN = 0x9E3779B97F4A7C15ULL;

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

// ---- scalar reference (v2), phases split so we can time the mix ----
static void mix_scalar(uint64_t* pad, uint64_t mask, uint64_t& A, uint64_t& B, uint64_t& C, uint64_t& D, uint64_t& E) {
    uint64_t a = A, b = B, c = C, d = D, e = E;
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
    A = a; B = b; C = c; D = d; E = e;
}
static void corehash_scalar(const uint8_t* hdr, size_t hlen, uint64_t nonce, uint8_t out[32], uint64_t* pad) {
    const uint64_t mask = COREHASH_PAD_WORDS - 1;
    uint64_t a, b, c, d, e; uint8_t seed[32], buf[128];
    size_t hl = hlen > 100 ? 100 : hlen; memcpy(buf, hdr, hl); memcpy(buf + hl, &nonce, 8);
    seed_state(buf, hl + 8, seed, a, b, c, d, e);
    fill_scratchpad(pad, COREHASH_PAD_WORDS, seed);
    mix_scalar(pad, mask, a, b, c, d, e);
    finalize(a, b, c, d, e, pad, mask, out);
}

// ---- AVX2 helpers ----
static inline __m256i mul64_v(__m256i x, __m256i y) {
    __m256i xh = _mm256_srli_epi64(x, 32), yh = _mm256_srli_epi64(y, 32);
    __m256i ll = _mm256_mul_epu32(x, y), lh = _mm256_mul_epu32(x, yh), hl = _mm256_mul_epu32(xh, y);
    return _mm256_add_epi64(ll, _mm256_slli_epi64(_mm256_add_epi64(lh, hl), 32));
}
static inline __m256i rotlv(__m256i x, __m256i c) {
    return _mm256_or_si256(_mm256_sllv_epi64(x, c), _mm256_srlv_epi64(x, _mm256_sub_epi64(_mm256_set1_epi64x(64), c)));
}
static inline __m256i rotl23(__m256i x) { return _mm256_or_si256(_mm256_slli_epi64(x, 23), _mm256_srli_epi64(x, 41)); }
// One lane's branch: updates X using value V and partner P (v&3 selects). Returns new X.
static inline __m256i branch_lane(__m256i X, __m256i P, __m256i V,
                                  __m256i v3, __m256i v63, __m256i v1c, __m256i v2c, __m256i vzero,
                                  __m256i vone, __m256i vgold) {
    __m256i t = _mm256_and_si256(V, v3);
    __m256i cnt0 = _mm256_and_si256(_mm256_srli_epi64(V, 6), v63);
    __m256i r0 = rotlv(_mm256_add_epi64(X, V), cnt0);
    __m256i r1 = _mm256_xor_si256(X, mul64_v(V, vgold));
    __m256i cnt2 = _mm256_and_si256(V, v63);
    __m256i r2 = _mm256_xor_si256(_mm256_sub_epi64(X, V), rotlv(P, cnt2));
    __m256i r3 = mul64_v(X, _mm256_or_si256(V, vone));
    __m256i res = r3;
    res = _mm256_blendv_epi8(res, r2, _mm256_cmpeq_epi64(t, v2c));
    res = _mm256_blendv_epi8(res, r1, _mm256_cmpeq_epi64(t, v1c));
    res = _mm256_blendv_epi8(res, r0, _mm256_cmpeq_epi64(t, vzero));
    return res;
}

// v2 dual-lane mix for 4 nonces at once. pad4: 4 scratchpads, lane-major.
static void mix_avx2_x4(uint64_t* pad4, uint64_t A[4], uint64_t B[4], uint64_t C[4], uint64_t D[4], uint64_t E[4]) {
    const uint64_t pw = COREHASH_PAD_WORDS, mask = pw - 1;
    __m256i a = _mm256_set_epi64x(A[3],A[2],A[1],A[0]), b = _mm256_set_epi64x(B[3],B[2],B[1],B[0]);
    __m256i c = _mm256_set_epi64x(C[3],C[2],C[1],C[0]), d = _mm256_set_epi64x(D[3],D[2],D[1],D[0]);
    __m256i e = _mm256_set_epi64x(E[3],E[2],E[1],E[0]);
    const __m256i vmask = _mm256_set1_epi64x((long long)mask);
    const __m256i lanebase = _mm256_set_epi64x((long long)(3*pw),(long long)(2*pw),(long long)(1*pw),0);
    const __m256i v3=_mm256_set1_epi64x(3), v63=_mm256_set1_epi64x(63), v1c=_mm256_set1_epi64x(1),
                  v2c=_mm256_set1_epi64x(2), vzero=_mm256_setzero_si256(), vone=_mm256_set1_epi64x(1),
                  vgold=_mm256_set1_epi64x((long long)GOLDEN);
    alignas(32) uint64_t i1[4], i2[4], w1[4], w2[4];

    for (uint64_t i = 0; i < COREHASH_ITERS; i++) {
        __m256i addr1 = _mm256_and_si256(_mm256_xor_si256(a, b), vmask);
        __m256i addr2 = _mm256_and_si256(_mm256_xor_si256(c, d), vmask);
        __m256i idx1 = _mm256_add_epi64(addr1, lanebase), idx2 = _mm256_add_epi64(addr2, lanebase);
        __m256i v1 = _mm256_i64gather_epi64((const long long*)pad4, idx1, 8);
        __m256i v2 = _mm256_i64gather_epi64((const long long*)pad4, idx2, 8);
        __m256i na = branch_lane(a, b, v1, v3, v63, v1c, v2c, vzero, vone, vgold);
        __m256i nc = branch_lane(c, d, v2, v3, v63, v1c, v2c, vzero, vone, vgold);
        b = _mm256_add_epi64(b, nc);
        d = _mm256_add_epi64(d, na);
        e = rotl23(_mm256_xor_si256(e, _mm256_xor_si256(v1, v2)));
        a = _mm256_xor_si256(na, _mm256_xor_si256(v2, e));
        c = _mm256_xor_si256(nc, _mm256_xor_si256(v1, e));
        __m256i wr1 = _mm256_add_epi64(v1, _mm256_add_epi64(d, e));
        __m256i wr2 = _mm256_add_epi64(v2, _mm256_add_epi64(b, e));
        _mm256_store_si256((__m256i*)i1, idx1); _mm256_store_si256((__m256i*)i2, idx2);
        _mm256_store_si256((__m256i*)w1, wr1); _mm256_store_si256((__m256i*)w2, wr2);
        for (int l = 0; l < 4; l++) { pad4[i1[l]] = w1[l]; pad4[i2[l]] = w2[l]; }
    }
    alignas(32) uint64_t oa[4],ob[4],oc[4],od[4],oe[4];
    _mm256_store_si256((__m256i*)oa,a);_mm256_store_si256((__m256i*)ob,b);_mm256_store_si256((__m256i*)oc,c);
    _mm256_store_si256((__m256i*)od,d);_mm256_store_si256((__m256i*)oe,e);
    for (int l=0;l<4;l++){A[l]=oa[l];B[l]=ob[l];C[l]=oc[l];D[l]=od[l];E[l]=oe[l];}
}
static void corehash_x4(const uint8_t* hdr, size_t hlen, uint64_t nonce0, uint8_t out[4][32], uint64_t* pad4) {
    const uint64_t pw = COREHASH_PAD_WORDS, mask = pw - 1;
    uint64_t A[4],B[4],C[4],D[4],E[4]; uint8_t seed[32], buf[128];
    size_t hl = hlen > 100 ? 100 : hlen;
    for (int l = 0; l < 4; l++) {
        uint64_t nonce = nonce0 + l; memcpy(buf, hdr, hl); memcpy(buf + hl, &nonce, 8);
        seed_state(buf, hl + 8, seed, A[l], B[l], C[l], D[l], E[l]);
        fill_scratchpad(pad4 + l * pw, pw, seed);
    }
    mix_avx2_x4(pad4, A, B, C, D, E);
    for (int l = 0; l < 4; l++) finalize(A[l], B[l], C[l], D[l], E[l], pad4 + l * pw, mask, out[l]);
}

static double now_s() { return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count(); }

int main(int argc, char** argv) {
    int seconds = (argc > 1) ? atoi(argv[1]) : 5; if (seconds < 1) seconds = 1;
    const uint64_t pw = COREHASH_PAD_WORDS;
    const char* hdr = "CoreHash-avx2-attack-header-000"; size_t hlen = strlen(hdr);

    printf("CoreHash v2 AVX2 attack  (4 nonces/iteration, dual-lane, single thread)\n");
    printf("scratchpad=4MB  iters=%llu  bench=%ds/phase\n\n", (unsigned long long)COREHASH_ITERS, seconds);

    uint64_t* pad1 = (uint64_t*)malloc(pw * 8);
    uint64_t* pad4 = (uint64_t*)malloc(4 * pw * 8);
    if (!pad1 || !pad4) { printf("alloc failed\n"); return 1; }

    bool ok = true;
    for (uint64_t base = 0; base < 8 && ok; base += 4) {
        uint8_t o4[4][32]; corehash_x4((const uint8_t*)hdr, hlen, base, o4, pad4);
        for (int l = 0; l < 4; l++) {
            uint8_t os[32], oref[32]; corehash_scalar((const uint8_t*)hdr, hlen, base + l, os, pad1);
            uint8_t buf[128]; size_t hl = hlen; uint64_t nonce = base + l;
            memcpy(buf, hdr, hl); memcpy(buf + hl, &nonce, 8);
            CoreHashCtx ctx; corehash(buf, hl + 8, oref, ctx);
            if (memcmp(o4[l], os, 32) != 0 || memcmp(o4[l], oref, 32) != 0) {
                printf("MISMATCH at nonce %llu\n", (unsigned long long)(base + l)); ok = false; break;
            }
        }
    }
    if (!ok) { printf("\nAVX2 output does NOT match the reference -> not a valid attack.\n"); free(pad1); free(pad4); return 1; }
    printf("correctness: AVX2 x4 == scalar == ch::corehash  (bit-identical) OK\n\n");

    double scalar_hs;
    { uint8_t o[32]; uint64_t n = 0, cnt = 0; double t0 = now_s();
      while (now_s() - t0 < seconds) { corehash_scalar((const uint8_t*)hdr, hlen, n++, o, pad1); cnt++; }
      double dt = now_s() - t0; scalar_hs = cnt / dt;
      printf("scalar   : %8.1f H/s  (%llu hashes in %.2fs)\n", scalar_hs, (unsigned long long)cnt, dt); }
    double avx2_hs;
    { uint8_t o4[4][32]; uint64_t n = 0, cnt = 0; double t0 = now_s();
      while (now_s() - t0 < seconds) { corehash_x4((const uint8_t*)hdr, hlen, n, o4, pad4); n += 4; cnt += 4; }
      double dt = now_s() - t0; avx2_hs = cnt / dt;
      printf("AVX2 x4  : %8.1f H/s  (%llu hashes in %.2fs)\n", avx2_hs, (unsigned long long)cnt, dt); }

    printf("\nspeedup (AVX2 / scalar): %.2fx\n", avx2_hs / scalar_hs);
    if (avx2_hs <= scalar_hs * 1.15) printf("=> AVX2 gives NO meaningful advantage: the mixing loop resists SIMD.\n");
    else printf("=> AVX2 IS faster by %.0f%%: a fairness weakness to investigate.\n", 100.0 * (avx2_hs / scalar_hs - 1.0));
    free(pad1); free(pad4); return 0;
}
