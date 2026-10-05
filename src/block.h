// Consensus data structures: transactions, block header (CoreHash PoW), block, merkle.
#pragma once
#include "primitives.h"
#include "corehash.h"

// A reference to a previous transaction output being spent.
struct OutPoint {
    uint256  txid;      // transaction that created the output
    uint32_t index = 0; // which output within it

    bool operator==(const OutPoint& o) const { return txid == o.txid && index == o.index; }
    bool operator!=(const OutPoint& o) const { return !(*this == o); }
    bool operator<(const OutPoint& o) const {
        if (txid != o.txid) return txid < o.txid;
        return index < o.index;
    }
};

// A transaction input. `sig` is a placeholder for the unlocking data
// (signature + pubkey); real signature verification arrives with the wallet milestone.
struct TxIn {
    OutPoint             prev;
    std::vector<uint8_t> sig;
    uint32_t             sequence = 0xffffffff;
};

// A transaction output: an amount locked to a recipient (pubkey hash).
struct TxOut {
    uint64_t             amount = 0;
    std::vector<uint8_t> pubkey_hash; // 32-byte Blake2b of recipient pubkey (0-length = OP-less)
};

struct Transaction {
    uint32_t             version = 1;
    std::vector<TxIn>    vin;
    std::vector<TxOut>   vout;
    uint64_t             lock_time = 0;

    void    serialize(Writer& w) const;
    uint256 txid() const;          // Blake2b of the serialized transaction
    uint256 sighash() const;       // Blake2b of the tx with all input sigs cleared (SIGHASH_ALL)
    bool    is_coinbase() const;   // exactly one input with a null prevout
};

// Build the block-subsidy coinbase transaction for a given height.
Transaction make_coinbase(uint64_t height, uint64_t reward,
                          const std::vector<uint8_t>& miner_pubkey_hash);

struct BlockHeader {
    uint32_t version = 1;
    uint256  prev_hash;      // id of the previous block's header
    uint256  merkle_root;    // commits to the transaction set
    uint64_t timestamp = 0;  // unix seconds
    uint32_t bits = 0;       // compact PoW target (nBits-style)
    uint64_t nonce = 0;

    void    serialize(Writer& w) const;
    uint256 pow_hash(ch::CoreHashCtx& ctx) const; // CoreHash over the serialized header
};

struct Block {
    BlockHeader              header;
    std::vector<Transaction> txs;
    uint256 compute_merkle_root() const;
    void    serialize(Writer& w) const;
};

// ---- Deserialization (inverse of the serialize() methods above) ----
Transaction read_transaction(Reader& r);
BlockHeader read_block_header(Reader& r);
Block       read_block(Reader& r);

// ---- Compact difficulty target (nBits) <-> 256-bit target ----
uint256  bits_to_target(uint32_t bits);
uint32_t target_to_bits(const uint256& target);

// Merkle root over a list of leaf hashes (Blake2b pair hashing, last duplicated if odd).
uint256 merkle_root(const std::vector<uint256>& leaves);
