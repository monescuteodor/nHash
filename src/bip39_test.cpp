// BIP39 self-test: official test vectors, round-trip, and checksum/typo rejection.
#include "bip39.h"
#include <cstdio>
#include <cstring>
#include <string>

static int fails = 0;
static void check(bool ok, const char* name) {
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) fails++;
}

int main() {
    printf("BIP39 mnemonic tests\n");

    // Vector 1: 32 bytes of 0x00 -> "abandon" x23 + "art" (canonical Trezor vector).
    uint8_t z[32]; memset(z, 0x00, 32);
    std::string exp0; for (int i = 0; i < 23; i++) exp0 += "abandon "; exp0 += "art";
    check(bip39::mnemonic_from_entropy(z) == exp0, "vector: all-zero entropy -> abandon...art");

    // Vector 2: 32 bytes of 0xff -> "zoo" x23 + "vote" (canonical Trezor vector).
    uint8_t f[32]; memset(f, 0xff, 32);
    std::string expff; for (int i = 0; i < 23; i++) expff += "zoo "; expff += "vote";
    check(bip39::mnemonic_from_entropy(f) == expff, "vector: all-ones entropy -> zoo...vote");

    // Round-trip: arbitrary entropy -> mnemonic -> entropy.
    uint8_t e[32], e2[32];
    for (int i = 0; i < 32; i++) e[i] = (uint8_t)(i * 7 + 13);
    std::string m = bip39::mnemonic_from_entropy(e);
    bool rt = bip39::entropy_from_mnemonic(m, e2) && memcmp(e, e2, 32) == 0;
    check(rt, "round-trip: entropy -> 24 words -> entropy");

    // Decoding the all-zero vector recovers all-zero entropy.
    uint8_t back[32];
    bool ok0 = bip39::entropy_from_mnemonic(exp0, back);
    bool zeros = ok0; for (int i = 0; i < 32; i++) if (back[i] != 0) zeros = false;
    check(ok0 && zeros, "decode: abandon...art -> all-zero entropy");

    // Checksum: corrupt the last word of a valid phrase -> must be rejected.
    std::string bad = exp0.substr(0, exp0.rfind(' ') + 1) + "abandon"; // ...art -> ...abandon
    uint8_t tmp[32];
    check(!bip39::entropy_from_mnemonic(bad, tmp), "reject: bad checksum (typo)");

    // Unknown word -> rejected.
    check(!bip39::entropy_from_mnemonic("notaword " + exp0.substr(exp0.find(' ') + 1), tmp), "reject: unknown word");

    // Wrong word count -> rejected.
    check(!bip39::entropy_from_mnemonic("abandon abandon abandon", tmp), "reject: wrong word count");

    if (fails == 0) printf("ALL TESTS PASSED\n");
    else printf("%d TEST(S) FAILED\n", fails);
    return fails ? 1 : 0;
}
