#include "wallet.h"
#include "ed25519.h"
#include <cstring>
#include <fstream>
#include <random>

// ============================ addresses & signing ============================
std::vector<uint8_t> pubkey_hash(const uint8_t pub[32]) {
    uint8_t h[32];
    ch::blake2b(h, 32, pub, 32);
    return std::vector<uint8_t>(h, h + 32);
}

Wallet Wallet::from_seed(const uint8_t seed[32]) {
    Wallet w;
    memcpy(w.seed, seed, 32);
    ed::publickey(w.pub, w.seed);
    return w;
}

Wallet Wallet::from_passphrase(const std::string& phrase) {
    uint8_t seed[32];
    ch::blake2b(seed, 32, (const uint8_t*)phrase.data(), phrase.size());
    return from_seed(seed);
}

void sign_tx(Transaction& tx, const Wallet& w) {
    uint256 sh = tx.sighash();
    uint8_t sig[64];
    for (auto& in : tx.vin) {
        ed::sign(sig, w.seed, w.pub, sh.b.data(), 32);
        in.sig.assign(sig, sig + 64);
        in.sig.insert(in.sig.end(), w.pub, w.pub + 32);
    }
}

// ============================ wallet-file crypto ============================
// HMAC-SHA512.
static void hmac_sha512(const uint8_t* key, size_t klen, const uint8_t* msg, size_t mlen, uint8_t out[64]) {
    uint8_t k[128] = {0};
    if (klen > 128) { ed::sha512(k, key, klen); } else { memcpy(k, key, klen); }
    uint8_t ipad[128], opad[128];
    for (int i = 0; i < 128; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
    std::vector<uint8_t> in; in.insert(in.end(), ipad, ipad + 128); in.insert(in.end(), msg, msg + mlen);
    uint8_t inner[64]; ed::sha512(inner, in.data(), in.size());
    std::vector<uint8_t> out_in; out_in.insert(out_in.end(), opad, opad + 128); out_in.insert(out_in.end(), inner, inner + 64);
    ed::sha512(out, out_in.data(), out_in.size());
}

// PBKDF2-HMAC-SHA512, dkLen = 64 (a single block).
static void pbkdf2(const std::string& pw, const uint8_t* salt, size_t slen, uint32_t iters, uint8_t out[64]) {
    std::vector<uint8_t> block(salt, salt + slen);
    block.push_back(0); block.push_back(0); block.push_back(0); block.push_back(1); // INT_32_BE(1)
    uint8_t u[64]; hmac_sha512((const uint8_t*)pw.data(), pw.size(), block.data(), block.size(), u);
    uint8_t t[64]; memcpy(t, u, 64);
    for (uint32_t i = 1; i < iters; i++) {
        hmac_sha512((const uint8_t*)pw.data(), pw.size(), u, 64, u);
        for (int j = 0; j < 64; j++) t[j] ^= u[j];
    }
    memcpy(out, t, 64);
}

// ChaCha20 (IETF: 32-byte key, 12-byte nonce, 32-bit counter). Produces `n` (<=64) keystream bytes.
static inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
static void chacha20_keystream(const uint8_t key[32], const uint8_t nonce[12], uint8_t* out, size_t n) {
    uint32_t s[16];
    s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) memcpy(&s[4 + i], key + 4 * i, 4);
    s[12] = 0; // counter
    for (int i = 0; i < 3; i++) memcpy(&s[13 + i], nonce + 4 * i, 4);
    uint32_t x[16]; memcpy(x, s, 64);
    for (int r = 0; r < 10; r++) {
        auto QR = [&](int a, int b, int c, int d) {
            x[a]+=x[b]; x[d]^=x[a]; x[d]=rotl32(x[d],16);
            x[c]+=x[d]; x[b]^=x[c]; x[b]=rotl32(x[b],12);
            x[a]+=x[b]; x[d]^=x[a]; x[d]=rotl32(x[d], 8);
            x[c]+=x[d]; x[b]^=x[c]; x[b]=rotl32(x[b], 7);
        };
        QR(0,4,8,12); QR(1,5,9,13); QR(2,6,10,14); QR(3,7,11,15);
        QR(0,5,10,15); QR(1,6,11,12); QR(2,7,8,13); QR(3,4,9,14);
    }
    uint8_t blk[64];
    for (int i = 0; i < 16; i++) { uint32_t v = x[i] + s[i]; memcpy(blk + 4 * i, &v, 4); }
    memcpy(out, blk, n);
}

static const char WMAGIC[4] = { 'C','H','W','E' };

bool wallet_write(const std::string& path, const uint8_t seed[32], const std::string& password) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    if (password.empty()) { f.write((const char*)seed, 32); return (bool)f; } // legacy unencrypted

    uint8_t pub[32]; ed::publickey(pub, seed);
    uint8_t salt[16], nonce[12];
    std::random_device rd;
    for (auto& b : salt)  b = (uint8_t)rd();
    for (auto& b : nonce) b = (uint8_t)rd();
    uint8_t dk[64]; pbkdf2(password, salt, 16, 200000, dk);
    uint8_t ks[32]; chacha20_keystream(dk /*enc key*/, nonce, ks, 32);
    uint8_t ct[32]; for (int i = 0; i < 32; i++) ct[i] = seed[i] ^ ks[i];
    // MAC over nonce||ct with the second half of the derived key.
    std::vector<uint8_t> macin(nonce, nonce + 12); macin.insert(macin.end(), ct, ct + 32);
    uint8_t mac[64]; hmac_sha512(dk + 32, 32, macin.data(), macin.size(), mac);

    uint8_t ver = 1;
    f.write(WMAGIC, 4); f.write((const char*)&ver, 1);
    f.write((const char*)pub, 32); f.write((const char*)salt, 16);
    f.write((const char*)nonce, 12); f.write((const char*)ct, 32); f.write((const char*)mac, 32);
    return (bool)f;
}

static bool read_all(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return false;
    std::streamsize n = f.tellg(); f.seekg(0);
    out.resize((size_t)n); if (n > 0) f.read((char*)out.data(), n);
    return true;
}

bool wallet_read_pubkey(const std::string& path, uint8_t pub[32], bool& encrypted) {
    std::vector<uint8_t> b;
    if (!read_all(path, b)) return false;
    if (b.size() >= 37 && memcmp(b.data(), WMAGIC, 4) == 0) {
        memcpy(pub, b.data() + 5, 32); encrypted = true; return true;
    }
    if (b.size() == 32) { ed::publickey(pub, b.data()); encrypted = false; return true; }
    return false;
}

bool wallet_read_seed(const std::string& path, const std::string& password, uint8_t seed[32]) {
    std::vector<uint8_t> b;
    if (!read_all(path, b)) return false;
    if (b.size() == 32) { memcpy(seed, b.data(), 32); return true; } // legacy unencrypted
    if (b.size() < 5 + 32 + 16 + 12 + 32 + 32 || memcmp(b.data(), WMAGIC, 4) != 0) return false;
    const uint8_t* p = b.data() + 5;
    const uint8_t* salt = p + 32; const uint8_t* nonce = salt + 16;
    const uint8_t* ct = nonce + 12; const uint8_t* mac = ct + 32;
    uint8_t dk[64]; pbkdf2(password, salt, 16, 200000, dk);
    std::vector<uint8_t> macin(nonce, nonce + 12); macin.insert(macin.end(), ct, ct + 32);
    uint8_t want[64]; hmac_sha512(dk + 32, 32, macin.data(), macin.size(), want);
    if (memcmp(want, mac, 32) != 0) return false; // wrong password or corrupted
    uint8_t ks[32]; chacha20_keystream(dk, nonce, ks, 32);
    for (int i = 0; i < 32; i++) seed[i] = ct[i] ^ ks[i];
    return true;
}
