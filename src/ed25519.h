// Ed25519 signatures (RFC 8032), implemented from scratch, no external deps.
// SHA-512 + GF(2^255-19) field + edwards25519 group + sign/verify.
// Portable across MSVC and g++ (validated with RFC 8032 test vectors).
#pragma once
#include <cstdint>
#include <cstddef>

namespace ed {

// SHA-512 one-shot.
void sha512(uint8_t out[64], const uint8_t* in, size_t len);

// Derive the 32-byte public key from a 32-byte secret seed.
void publickey(uint8_t pub[32], const uint8_t seed[32]);

// Produce a 64-byte signature over msg. `pub` must be publickey(seed).
void sign(uint8_t sig[64], const uint8_t seed[32], const uint8_t pub[32],
          const uint8_t* msg, size_t mlen);

// Verify a 64-byte signature. Returns true iff valid.
bool verify(const uint8_t sig[64], const uint8_t pub[32],
            const uint8_t* msg, size_t mlen);

} // namespace ed
