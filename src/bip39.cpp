#include "bip39.h"
#include "bip39_wordlist.h"
#include <cstring>
#include <sstream>
#include <vector>
#include <algorithm>
#include <cctype>

namespace bip39 {

// ---------------------------- SHA-256 (for the BIP39 checksum) ----------------------------
namespace {
inline uint32_t ror(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
void sha256(uint8_t out[32], const uint8_t* in, size_t len) {
    uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    size_t total = len + 1 + 8;
    size_t nblk = (total + 63) / 64;
    std::vector<uint8_t> buf(nblk * 64, 0);
    memcpy(buf.data(), in, len);
    buf[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) buf[buf.size() - 1 - i] = (uint8_t)(bits >> (8 * i));
    for (size_t b = 0; b < nblk; b++) {
        const uint8_t* p = buf.data() + b * 64;
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) | ((uint32_t)p[i*4+2] << 8) | p[i*4+3];
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = ror(w[i-15],7) ^ ror(w[i-15],18) ^ (w[i-15] >> 3);
            uint32_t s1 = ror(w[i-2],17) ^ ror(w[i-2],19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h[0],bb=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = ror(e,6) ^ ror(e,11) ^ ror(e,25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + K256[i] + w[i];
            uint32_t S0 = ror(a,2) ^ ror(a,13) ^ ror(a,22);
            uint32_t maj = (a & bb) ^ (a & c) ^ (bb & c);
            uint32_t t2 = S0 + maj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=bb; bb=a; a=t1+t2;
        }
        h[0]+=a;h[1]+=bb;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }
    for (int i = 0; i < 8; i++) { out[i*4]=(uint8_t)(h[i]>>24); out[i*4+1]=(uint8_t)(h[i]>>16); out[i*4+2]=(uint8_t)(h[i]>>8); out[i*4+3]=(uint8_t)h[i]; }
}

// Index of a word in the sorted BIP39 list, or -1 if not present (binary search).
int word_index(const std::string& w) {
    int lo = 0, hi = 2047;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        int c = w.compare(BIP39_WORDS[mid]);
        if (c == 0) return mid;
        if (c < 0) hi = mid - 1; else lo = mid + 1;
    }
    return -1;
}
} // anonymous namespace

std::string mnemonic_from_entropy(const uint8_t ent[32]) {
    // 256 bits entropy + 8-bit checksum (first byte of SHA-256(entropy)) = 264 bits = 24 * 11.
    uint8_t h[32]; sha256(h, ent, 32);
    uint8_t data[33];
    memcpy(data, ent, 32);
    data[32] = h[0];
    std::string out;
    for (int i = 0; i < 24; i++) {
        int idx = 0, bitpos = i * 11;
        for (int b = 0; b < 11; b++) {
            int bp = bitpos + b;
            int bit = (data[bp / 8] >> (7 - (bp % 8))) & 1;
            idx = (idx << 1) | bit;
        }
        if (i) out += ' ';
        out += BIP39_WORDS[idx];
    }
    return out;
}

bool entropy_from_mnemonic(const std::string& mnemonic, uint8_t ent[32]) {
    // Tokenize on whitespace, lowercasing each word.
    std::vector<std::string> words;
    std::istringstream is(mnemonic);
    std::string w;
    while (is >> w) { std::transform(w.begin(), w.end(), w.begin(), [](unsigned char c){ return (char)std::tolower(c); }); words.push_back(w); }
    if (words.size() != 24) return false;

    uint8_t data[33] = {0};
    for (int i = 0; i < 24; i++) {
        int idx = word_index(words[i]);
        if (idx < 0) return false;
        int bitpos = i * 11;
        for (int b = 0; b < 11; b++) {
            int bit = (idx >> (10 - b)) & 1;
            int bp = bitpos + b;
            if (bit) data[bp / 8] |= (uint8_t)(1 << (7 - (bp % 8)));
        }
    }
    // Verify the 8-bit checksum against SHA-256 of the recovered entropy.
    uint8_t h[32]; sha256(h, data, 32);
    if (h[0] != data[32]) return false;
    memcpy(ent, data, 32);
    return true;
}

} // namespace bip39
