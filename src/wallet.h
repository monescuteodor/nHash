// Wallet: Ed25519 keypair, address (= Blake2b of pubkey), transaction signing.
#pragma once
#include "block.h"
#include <string>

// A recipient address is the 32-byte Blake2b hash of the Ed25519 public key.
std::vector<uint8_t> pubkey_hash(const uint8_t pub[32]);

struct Wallet {
    uint8_t seed[32];
    uint8_t pub[32];

    static Wallet from_seed(const uint8_t seed[32]);
    static Wallet from_passphrase(const std::string& phrase); // deterministic demo key

    std::vector<uint8_t> address() const { return pubkey_hash(pub); }
};

// Sign every input of `tx` with `w` (assumes all inputs are owned by this wallet).
// Each input's unlocking data becomes: signature(64) || pubkey(32).
void sign_tx(Transaction& tx, const Wallet& w);

// ---- Wallet file storage ----
// Write a wallet. password="" stores the raw seed (legacy/unencrypted); otherwise the
// seed is encrypted (PBKDF2-HMAC-SHA512 -> ChaCha20 + HMAC-SHA512), with the public key
// kept in cleartext so the address is viewable without the password.
bool wallet_write(const std::string& path, const uint8_t seed[32], const std::string& password);
// Read only the public key (no password needed). `encrypted` reports the file's kind.
bool wallet_read_pubkey(const std::string& path, uint8_t pub[32], bool& encrypted);
// Recover the secret seed; needs the password if the file is encrypted. False on wrong password.
bool wallet_read_seed(const std::string& path, const std::string& password, uint8_t seed[32]);
