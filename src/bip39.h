// BIP39 mnemonic backup for nHash wallets. A wallet's 32-byte Ed25519 seed is 256 bits of
// entropy, which BIP39 encodes as a 24-word English mnemonic with an 8-bit checksum — the
// standard, cross-compatible "seed phrase" you can write on paper to recover the wallet.
#pragma once
#include <cstdint>
#include <string>

namespace bip39 {

// Encode 32 bytes of entropy as a 24-word space-separated BIP39 mnemonic.
std::string mnemonic_from_entropy(const uint8_t ent[32]);

// Decode a 24-word mnemonic back to 32 bytes of entropy. Returns false on a wrong word
// count, an unknown word, or a checksum mismatch (which catches typos in the phrase).
bool entropy_from_mnemonic(const std::string& mnemonic, uint8_t ent[32]);

} // namespace bip39
