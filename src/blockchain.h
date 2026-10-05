// Chain state: consensus parameters, difficulty retarget, mining, block validation.
#pragma once
#include "block.h"
#include "utxo.h"
#include <vector>
#include <string>
#include <set>

namespace consensus {
    constexpr uint64_t COIN             = 100000000ULL; // 1 coin = 1e8 base units
    // Emission: 50 coins/block, halving every 210,000 blocks. Sum = 210000*50*2 =
    // 21,000,000 coins total (hard cap). At the mainnet 300s block time a halving is
    // ~2 years, so the supply approaches 21M over the usual multi-decade tail.
    constexpr uint64_t INITIAL_REWARD   = 50 * COIN;    // first-era block subsidy
    constexpr uint64_t HALVING_INTERVAL = 210000;       // blocks between halvings
    // NOTE: the live block time / retarget window come from g_params (see params.cpp:
    // mainnet 300s/60, regtest 60s/12). The two constants below are used only by the
    // standalone node_demo display and are NOT the consensus values.
    constexpr int64_t  BLOCK_TIME       = 300;          // demo display only
    constexpr int      RETARGET_WINDOW  = 60;           // demo display only
    constexpr int64_t  MAX_FUTURE_DRIFT = 2 * 60 * 60;  // 2h clock tolerance

    uint64_t block_reward(uint64_t height);

    constexpr size_t MAX_BLOCK_SIZE   = 1000000; // 1 MB consensus cap on a serialized block
    constexpr size_t MAX_MEMPOOL_TXS  = 5000;    // policy cap on pooled transactions
    // Bytes held back from the block-size budget when a miner selects mempool txs, to
    // leave room for the header + coinbase + tx-count varints. A coinbase is tiny (no
    // inputs, one output ~40 B) and the header is ~112 B, so 4 KB is a safe margin that
    // still keeps the assembled block comfortably under MAX_BLOCK_SIZE.
    constexpr size_t COINBASE_RESERVE = 4096;

    // --- Relay / mempool policy (NOT a consensus rule) ---
    // The minimum fee a loose transaction must pay to be admitted to the mempool and relayed,
    // as a per-byte rate with a per-tx floor. This shapes only what a node *relays*: a block
    // that includes a cheaper tx is still fully valid, so the rule can never fork the chain.
    // Sized far below the pool's payout fee so on-chain payouts always relay. `inline` so the
    // daemon and the pool both compute it without a shared translation unit.
    constexpr uint64_t MIN_RELAY_FEE_PER_BYTE = 100;    // 1e-6 coin per byte
    constexpr uint64_t MIN_RELAY_FEE_FLOOR    = 10000;  // 1e-4 coin minimum per tx
    inline uint64_t min_relay_fee(size_t tx_size) {
        uint64_t f = (uint64_t)tx_size * MIN_RELAY_FEE_PER_BYTE;
        return f < MIN_RELAY_FEE_FLOOR ? MIN_RELAY_FEE_FLOOR : f;
    }
}

// One known block (active or side-branch), indexed by its header hash.
struct BlockRec {
    Block    block;
    uint256  prev;
    uint64_t height = 0;
    double   cumwork = 0; // cumulative work from genesis to this block
};

struct ChainState {
    std::vector<Block>   blocks;   // active chain, index == height (0 = genesis)
    std::vector<uint256> hashes;   // cached header hash per height
    UTXOSet              utxo;     // unspent outputs after the active tip
    std::map<uint256, BlockRec> index; // ALL known blocks (incl. side branches)

    uint64_t     height() const { return blocks.empty() ? 0 : blocks.size() - 1; }
    const Block& tip()    const { return blocks.back(); }
    uint256      tip_hash() const { return hashes.back(); }

    static ChainState with_genesis();

    // Rebuild the block index + cumulative work from the loaded active chain.
    void rebuild_index();

    // Required compact target for the block following the active tip.
    uint32_t next_bits() const;
    // Required compact target for a block whose parent has hash `prev` (branch-aware).
    uint32_t next_bits_for(const uint256& prev) const;
    // Difficulty relative to genesis (genesis == 1.0).
    double   difficulty_of(uint32_t bits) const;

    // Validate a candidate block (PoW, link, bits, timestamp, merkle, coinbase) and add it
    // to the index. If it makes the heaviest chain, switch the active chain to it (reorg),
    // fully re-validating transactions/UTXO along the way. Returns true if the block is
    // valid and stored (whether or not it became the new tip).
    bool connect(const Block& b, ch::CoreHashCtx& ctx, std::string& err);
};

// Pending unconfirmed transactions waiting to be mined.
struct Mempool {
    std::vector<Transaction> txs;
    std::set<OutPoint>       claimed; // inputs already spent by a pooled tx

    // Validate against the confirmed UTXO set and admit if no conflict.
    bool accept(const Transaction& tx, const UTXOSet& utxo, uint64_t next_height,
                std::string& err);
    // Drop transactions that a newly-connected block confirmed.
    void remove_confirmed(const std::vector<Transaction>& block_txs);
    // Sum of fees for the pooled txs, evaluated against `utxo`.
    uint64_t total_fees(const UTXOSet& utxo, uint64_t next_height) const;
    // Choose a fee-maximizing, size-bounded set of pooled txs for a new block template at
    // `next_height`. At most `size_budget` serialized bytes of transactions are selected,
    // highest fee-per-byte first; stale/invalid txs are skipped. `out_fees` receives the
    // exact total fee of the chosen set, so a coinbase of block_reward(next_height)+out_fees
    // always matches the block that connect() will re-validate. The returned txs are pairwise
    // independent (the mempool only admits spends of confirmed outputs), so any block order
    // is valid.
    std::vector<Transaction> select_for_block(const UTXOSet& utxo, uint64_t next_height,
                                              size_t size_budget, uint64_t& out_fees) const;
};

// Expected number of hashes to find a block at the given compact target (~2^256/target).
double expected_hashes_per_block(uint32_t bits);

// Search nonces until header.pow_hash <= target(bits). Returns number of hashes tried
// (0 if not found within max_tries). On success header.nonce holds the winning value.
uint64_t mine(Block& b, ch::CoreHashCtx& ctx, uint64_t max_tries = ~0ULL);
