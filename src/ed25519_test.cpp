// Validate the from-scratch Ed25519 against SHA-512 and RFC 8032 test vectors.
#include "ed25519.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static std::vector<uint8_t> hx(const std::string& h) {
    std::vector<uint8_t> v;
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        v.push_back((uint8_t)std::stoi(h.substr(i, 2), nullptr, 16));
    return v;
}
static std::string tohex(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s; for (size_t i = 0; i < n; i++) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
    return s;
}

static int failures = 0;
static void check(const char* name, bool ok) {
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) failures++;
}

int main() {
    printf("SHA-512:\n");
    {
        uint8_t out[64];
        ed::sha512(out, (const uint8_t*)"abc", 3);
        std::string got = tohex(out, 64);
        std::string want = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                           "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
        check("SHA512(\"abc\")", got == want);
    }

    struct Vec { const char* seed; const char* pub; const char* msg; const char* sig; };
    Vec vs[] = {
        {"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
         "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
        {"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
         "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
        {"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
         "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
         "af82",
         "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"},
    };

    printf("RFC 8032 Ed25519 vectors:\n");
    for (int i = 0; i < 3; i++) {
        auto seed = hx(vs[i].seed);
        auto wpub = hx(vs[i].pub);
        auto msg  = hx(vs[i].msg);
        auto wsig = hx(vs[i].sig);

        uint8_t pub[32]; ed::publickey(pub, seed.data());
        check((std::string("test ") + std::to_string(i+1) + " pubkey").c_str(),
              memcmp(pub, wpub.data(), 32) == 0);

        uint8_t sig[64]; ed::sign(sig, seed.data(), pub, msg.data(), msg.size());
        check((std::string("test ") + std::to_string(i+1) + " signature").c_str(),
              memcmp(sig, wsig.data(), 64) == 0);

        bool v = ed::verify(sig, pub, msg.data(), msg.size());
        check((std::string("test ") + std::to_string(i+1) + " verify").c_str(), v);

        // Tamper: flip one message/sig bit -> must reject.
        std::vector<uint8_t> m2 = msg; m2.push_back(0x00);
        bool vbad_msg = ed::verify(sig, pub, m2.data(), m2.size());
        uint8_t sig2[64]; memcpy(sig2, sig, 64); sig2[10] ^= 1;
        bool vbad_sig = ed::verify(sig2, pub, msg.data(), msg.size());
        check((std::string("test ") + std::to_string(i+1) + " rejects tampering").c_str(),
              !vbad_msg && !vbad_sig);
    }

    printf(failures == 0 ? "\nALL TESTS PASSED\n" : "\n%d FAILURE(S)\n", failures);
    return failures == 0 ? 0 : 1;
}
