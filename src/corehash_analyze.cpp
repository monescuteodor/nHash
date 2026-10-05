// Statistical quality analysis of CoreHash v2 output. A good PoW hash must behave like a
// random function: strong avalanche (flip 1 input bit -> ~50% of output bits flip, each
// output bit independently ~50%), balanced output bits, and uniform output bytes. Failing
// any of these hints at exploitable structure (shortcuts / bias). Uses ch::corehash.
//
// Build: MSVC (no flag) or g++ -maes.  Usage: corehash_analyze [avalanche_samples=400] [balance_hashes=1500]
#include "corehash.h"
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <cmath>
#ifdef _MSC_VER
  #include <intrin.h>
  static inline int popc64(uint64_t x){ return (int)__popcnt64(x); }
#else
  static inline int popc64(uint64_t x){ return __builtin_popcountll(x); }
#endif

using namespace ch;

static void H(const uint8_t in[80], uint8_t out[32], CoreHashCtx& ctx) { corehash(in, 80, out, ctx); }
static int hamming256(const uint8_t a[32], const uint8_t b[32]) {
    int d = 0; for (int i = 0; i < 4; i++) { uint64_t x, y; memcpy(&x, a+8*i, 8); memcpy(&y, b+8*i, 8); d += popc64(x ^ y); } return d;
}

int main(int argc, char** argv) {
    int SAMP = (argc > 1) ? atoi(argv[1]) : 400;   // avalanche input samples
    int NBAL = (argc > 2) ? atoi(argv[2]) : 1500;  // hashes for balance/uniformity
    if (SAMP < 50) SAMP = 50; if (NBAL < 200) NBAL = 200;
    CoreHashCtx ctx;
    std::mt19937_64 rng(0xC0FFEE);

    printf("CoreHash v2 statistical analysis\n");
    printf("(avalanche over %d flips, distribution over %d hashes)\n\n", SAMP, NBAL);

    // ---- 1) Avalanche / Strict Avalanche Criterion ----
    // Flip one random input bit; measure how many of the 256 output bits change.
    long long total_flips = 0;
    long perbit[256]; for (int i = 0; i < 256; i++) perbit[i] = 0;
    for (int s = 0; s < SAMP; s++) {
        uint8_t in[80]; for (int i = 0; i < 80; i++) in[i] = (uint8_t)rng();
        uint8_t h0[32], h1[32]; H(in, h0, ctx);
        int bit = rng() % (80 * 8);
        in[bit >> 3] ^= (uint8_t)(1u << (bit & 7));
        H(in, h1, ctx);
        total_flips += hamming256(h0, h1);
        for (int b = 0; b < 256; b++) {
            int db = ((h0[b>>3] >> (b&7)) & 1) ^ ((h1[b>>3] >> (b&7)) & 1);
            perbit[b] += db;
        }
    }
    double mean_flip = (double)total_flips / SAMP / 256.0;   // want ~0.5
    double pbmin = 1, pbmax = 0;
    for (int b = 0; b < 256; b++) { double r = (double)perbit[b] / SAMP; if (r < pbmin) pbmin = r; if (r > pbmax) pbmax = r; }
    printf("1) Avalanche\n");
    printf("   mean output bits flipped : %.4f   (ideal 0.5000)\n", mean_flip);
    printf("   per-output-bit flip rate : min %.3f  max %.3f   (ideal ~0.5 each = SAC)\n", pbmin, pbmax);

    // ---- 2) Output bit balance + byte uniformity over sequential nonces ----
    long ones[256]; for (int i = 0; i < 256; i++) ones[i] = 0;
    long bytehist[256]; for (int i = 0; i < 256; i++) bytehist[i] = 0;
    uint8_t base[80]; for (int i = 0; i < 80; i++) base[i] = (uint8_t)(i * 7 + 1);
    for (int n = 0; n < NBAL; n++) {
        memcpy(base + 72, &n, sizeof(n));    // vary the tail like a nonce
        uint8_t h[32]; H(base, h, ctx);
        for (int b = 0; b < 256; b++) ones[b] += (h[b>>3] >> (b&7)) & 1;
        for (int i = 0; i < 32; i++) bytehist[h[i]]++;
    }
    double bmin = 1, bmax = 0;
    for (int b = 0; b < 256; b++) { double r = (double)ones[b] / NBAL; if (r < bmin) bmin = r; if (r > bmax) bmax = r; }
    // chi-square for byte uniformity (255 dof); expected per bucket = 32*NBAL/256
    double exp = 32.0 * NBAL / 256.0, chi = 0;
    for (int i = 0; i < 256; i++) { double d = bytehist[i] - exp; chi += d * d / exp; }
    printf("\n2) Output distribution\n");
    printf("   per-bit ones fraction    : min %.3f  max %.3f   (ideal ~0.5 each)\n", bmin, bmax);
    printf("   byte chi-square (255 dof): %.1f   (healthy ~205-310; ~255 is perfect)\n", chi);

    // ---- verdict ----
    bool ok = std::fabs(mean_flip - 0.5) < 0.01 && pbmin > 0.40 && pbmax < 0.60
              && bmin > 0.44 && bmax < 0.56 && chi > 180 && chi < 340;
    printf("\n=> %s\n", ok ? "PASS: output is well-mixed and uniform (behaves like a random function)."
                           : "CHECK: one or more metrics are off — worth strengthening the mixing.");
    return ok ? 0 : 1;
}
