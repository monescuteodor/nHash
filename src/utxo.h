// UTXO set + transaction validation (existence, no double-spend, amounts, maturity).
#pragma once
#include "block.h"
#include <map>
#include <string>

namespace consensus {
    constexpr uint64_t MAX_MONEY         = 21000000ULL * 100000000ULL; // 21M * COIN
    constexpr uint64_t COINBASE_MATURITY = 10; // superseded by g_params.coinbase_maturity
    constexpr size_t   MAX_TX_SIZE       = 100000; // reject absurdly large transactions
}

// One unspent output.
struct UTXOEntry {
    uint64_t             amount = 0;
    std::vector<uint8_t> pubkey_hash;
    uint64_t             height = 0;      // block height that created it
    bool                 is_coinbase = false;

    bool operator==(const UTXOEntry& o) const {
        return amount == o.amount && pubkey_hash == o.pubkey_hash
            && height == o.height && is_coinbase == o.is_coinbase;
    }
};

// The set of all currently-unspent outputs (the ledger's real state).
struct UTXOSet {
    std::map<OutPoint, UTXOEntry> map;

    const UTXOEntry* find(const OutPoint& op) const {
        auto it = map.find(op);
        return it == map.end() ? nullptr : &it->second;
    }
    void add(const OutPoint& op, const UTXOEntry& e) { map[op] = e; }
    void remove(const OutPoint& op) { map.erase(op); }

    // Total spendable balance for a given recipient pubkey_hash.
    uint64_t balance_of(const std::vector<uint8_t>& pubkey_hash) const;
};

// Validate a NON-coinbase transaction against `view`. Fills `fee` (inputs - outputs).
// Does not modify the view. Signatures are NOT checked yet (wallet milestone).
bool check_tx(const Transaction& tx, const UTXOSet& view, uint64_t spend_height,
              uint64_t& fee, std::string& err);

// Apply a transaction to the view: remove spent inputs, add created outputs.
void apply_tx(UTXOSet& view, const Transaction& tx, uint64_t height);
