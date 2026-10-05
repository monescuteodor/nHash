#include "corehash.h"
#include <cstring>
#include <cstdlib>
#include <atomic>
#include <mutex>
#include <immintrin.h>   // AES-NI + SSE2 (fill). Compile g++ with -maes.
#ifdef _WIN32
  #include <windows.h>
  #pragma comment(lib, "Advapi32.lib")   // for the "lock pages in memory" privilege
#elif defined(__linux__)
  #include <sys/mman.h>
#endif

namespace ch {

// ============================ scratchpad allocation (huge pages) ============================
// Atomic: read by the dashboard while worker threads set it during their ctor.
static std::atomic<bool> g_huge_active{false};
bool corehash_using_huge_pages() { return g_huge_active.load(std::memory_order_relaxed); }

#ifdef _WIN32
static std::once_flag g_priv_once;
static bool g_priv_ok = false;    // written only inside call_once -> safe to read after
static void ensure_lock_priv() {
    std::call_once(g_priv_once, [] {
        HANDLE tok; if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return;
        LUID luid;
        if (LookupPrivilegeValue(NULL, SE_LOCK_MEMORY_NAME, &luid)) {
            TOKEN_PRIVILEGES tp; tp.PrivilegeCount = 1; tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL);
            g_priv_ok = (GetLastError() == ERROR_SUCCESS);
        }
        CloseHandle(tok);
    });
}
#endif

CoreHashCtx::CoreHashCtx() {
    const size_t bytes = COREHASH_PAD_BYTES;
    alloc_bytes = bytes;
#ifdef _WIN32
    ensure_lock_priv();
    if (g_priv_ok) {
        SIZE_T lp = GetLargePageMinimum();
        if (lp) {
            size_t r = ((bytes + lp - 1) / lp) * lp;
            void* p = VirtualAlloc(NULL, r, MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES, PAGE_READWRITE);
            if (p) { pad_ptr = (uint64_t*)p; alloc_kind = 1; alloc_bytes = r; g_huge_active.store(true, std::memory_order_relaxed); return; }
        }
    }
    pad_ptr = (uint64_t*)malloc(bytes); alloc_kind = 0;
#elif defined(__linux__)
    const size_t HP = 2 * 1024 * 1024;
    size_t r = ((bytes + HP - 1) / HP) * HP;
  #ifdef MAP_HUGETLB
    void* p = mmap(NULL, r, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
    if (p != MAP_FAILED) { pad_ptr = (uint64_t*)p; alloc_kind = 2; alloc_bytes = r; g_huge_active.store(true, std::memory_order_relaxed); return; }
  #endif
    void* q = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (q != MAP_FAILED) {
  #ifdef MADV_HUGEPAGE
        madvise(q, bytes, MADV_HUGEPAGE);   // transparent huge pages, if enabled
  #endif
        pad_ptr = (uint64_t*)q; alloc_kind = 3; alloc_bytes = bytes; return;
    }
    pad_ptr = (uint64_t*)malloc(bytes); alloc_kind = 0;
#else
    pad_ptr = (uint64_t*)malloc(bytes); alloc_kind = 0;
#endif
}

CoreHashCtx::~CoreHashCtx() {
    if (!pad_ptr) return;
#ifdef _WIN32
    if (alloc_kind == 1) VirtualFree(pad_ptr, 0, MEM_RELEASE); else free(pad_ptr);
#elif defined(__linux__)
    if (alloc_kind == 2 || alloc_kind == 3) munmap(pad_ptr, (size_t)alloc_bytes); else free(pad_ptr);
#else
    free(pad_ptr);
#endif
}

// ============================ Blake2b (RFC 7693) ============================
static const uint64_t B2B_IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
    0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};
static const uint8_t B2B_SIGMA[12][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4},
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8},
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13},
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9},
    {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11},
    {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10},
    { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0},
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3}
};
// Rotations masked to avoid shifting by 64 (undefined behaviour in C++ when n == 0).
// On x86 the result is unchanged, but this makes it defined on every compiler/architecture
// — critical for cross-platform consensus.
static inline uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << ((64 - n) & 63)); }
static inline uint64_t rotl64(uint64_t x, int n) { return (x << n) | (x >> ((64 - n) & 63)); }

#define B2B_G(r,i,a,b,c,d) \
    a = a + b + m[B2B_SIGMA[r][2*i+0]]; d = rotr64(d ^ a, 32); c = c + d; b = rotr64(b ^ c, 24); \
    a = a + b + m[B2B_SIGMA[r][2*i+1]]; d = rotr64(d ^ a, 16); c = c + d; b = rotr64(b ^ c, 63);

static void b2b_compress(uint64_t h[8], const uint8_t block[128], uint64_t t0, uint64_t t1, int last) {
    uint64_t v[16], m[16];
    for (int i = 0; i < 16; i++) memcpy(&m[i], block + 8 * i, 8); // x86 little-endian
    for (int i = 0; i < 8; i++) v[i] = h[i];
    for (int i = 0; i < 8; i++) v[8 + i] = B2B_IV[i];
    v[12] ^= t0; v[13] ^= t1;
    if (last) v[14] = ~v[14];
    for (int r = 0; r < 12; r++) {
        B2B_G(r,0,v[0],v[4],v[8], v[12]); B2B_G(r,1,v[1],v[5],v[9], v[13]);
        B2B_G(r,2,v[2],v[6],v[10],v[14]); B2B_G(r,3,v[3],v[7],v[11],v[15]);
        B2B_G(r,4,v[0],v[5],v[10],v[15]); B2B_G(r,5,v[1],v[6],v[11],v[12]);
        B2B_G(r,6,v[2],v[7],v[8], v[13]); B2B_G(r,7,v[3],v[4],v[9], v[14]);
    }
    for (int i = 0; i < 8; i++) h[i] ^= v[i] ^ v[8 + i];
}

void blake2b(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen) {
    uint64_t h[8];
    memcpy(h, B2B_IV, sizeof(h));
    h[0] ^= 0x01010000ULL ^ (uint64_t)outlen; // fanout=1, depth=1, no key
    uint64_t t0 = 0, t1 = 0;
    uint8_t block[128];
    size_t i = 0;
    while (inlen - i > 128) {
        memcpy(block, in + i, 128);
        t0 += 128; if (t0 < 128) t1++;
        b2b_compress(h, block, t0, t1, 0);
        i += 128;
    }
    size_t rem = inlen - i;
    memset(block, 0, 128);
    if (rem) memcpy(block, in + i, rem);
    t0 += rem; if (t0 < rem) t1++;
    b2b_compress(h, block, t0, t1, 1);
    memcpy(out, h, outlen);
}

// ============================ AES-NI scratchpad fill ============================
// Fills the 4 MB scratchpad with a keyed AES stream seeded from `seed` (32 bytes).
// AES-NI is present on every x86 CPU since ~2010 (i5-2500K included) and runs in one
// hardware instruction, so this phase is equally fast on old and new CPUs -> no AVX2/
// SIMD advantage. Two aesenc rounds per 16-byte block, chained so it can't be
// precomputed without the seed. Deterministic and identical across MSVC and g++.
static void fill_scratchpad(uint64_t* pad, size_t words, const uint8_t seed[32]) {
    __m128i k0  = _mm_loadu_si128((const __m128i*)seed);
    __m128i k1  = _mm_loadu_si128((const __m128i*)(seed + 16));
    __m128i blk = _mm_xor_si128(k0, k1);
    __m128i* out = (__m128i*)pad;
    size_t nblk = (words * 8) / 16;    // 16-byte blocks
    for (size_t i = 0; i < nblk; i++) {
        blk = _mm_aesenc_si128(blk, k0);
        blk = _mm_aesenc_si128(blk, k1);
        _mm_storeu_si128(out + i, blk);
    }
}

// ============================ CoreHash v2 ============================
static const uint64_t GOLDEN = 0x9E3779B97F4A7C15ULL;

void corehash(const uint8_t* input, size_t len, uint8_t out[32], CoreHashCtx& ctx) {
    uint8_t seed[32];
    blake2b(seed, 32, input, len);

    uint64_t* pad = ctx.data();
    fill_scratchpad(pad, COREHASH_PAD_WORDS, seed);

    const uint64_t mask = COREHASH_PAD_WORDS - 1;
    uint64_t a, b, c, d;
    memcpy(&a, seed, 8); memcpy(&b, seed + 8, 8);
    memcpy(&c, seed + 16, 8); memcpy(&d, seed + 24, 8);
    uint64_t e = rotl64(a, 17) ^ rotl64(b, 31) ^ rotl64(c, 47) ^ d; // 5th accumulator

    for (uint64_t i = 0; i < COREHASH_ITERS; i++) {
        // Two independent addresses -> two memory reads in flight per iteration.
        uint64_t addr1 = (a ^ b) & mask;
        uint64_t addr2 = (c ^ d) & mask;
        uint64_t v1 = pad[addr1];
        uint64_t v2 = pad[addr2];

        // Lane 1 updates a (data-dependent branch -> GPU divergence).
        switch (v1 & 3) {
            case 0:  a = a + v1; a = rotl64(a, (int)((v1 >> 6) & 63)); break;
            case 1:  a = a ^ (v1 * GOLDEN);                            break;
            case 2:  a = (a - v1) ^ rotl64(b, (int)(v1 & 63));         break;
            default: a = a * (v1 | 1ULL);                              break;
        }
        // Lane 2 updates c.
        switch (v2 & 3) {
            case 0:  c = c + v2; c = rotl64(c, (int)((v2 >> 6) & 63)); break;
            case 1:  c = c ^ (v2 * GOLDEN);                            break;
            case 2:  c = (c - v2) ^ rotl64(d, (int)(v2 & 63));         break;
            default: c = c * (v2 | 1ULL);                              break;
        }
        // Cross-couple the two lanes + the accumulator so they can't be split apart.
        b += c; d += a;
        e = rotl64(e ^ v1 ^ v2, 23);
        a ^= v2 ^ e;
        c ^= v1 ^ e;
        // Read-modify-write both cells; each write depends on the other lane -> coupling.
        pad[addr1] = v1 + d + e;
        pad[addr2] = v2 + b + e;
    }

    uint8_t fin[64];
    memcpy(fin,      &a, 8); memcpy(fin + 8,  &b, 8);
    memcpy(fin + 16, &c, 8); memcpy(fin + 24, &d, 8);
    memcpy(fin + 32, &e, 8);
    uint64_t s0 = pad[a & mask], s1 = pad[c & mask], s2 = pad[e & mask];
    memcpy(fin + 40, &s0, 8); memcpy(fin + 48, &s1, 8); memcpy(fin + 56, &s2, 8);
    blake2b(out, 32, fin, 64);
}

} // namespace ch
