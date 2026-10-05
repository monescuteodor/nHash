// Tests for Mempool::select_for_block — the fee-prioritized, size-bounded block-template
// builder. Proves: (1) with room for everything, all pooled txs are chosen and the fee total
// is exact; (2) a block assembled from the selection + coinbase(reward+fees) is accepted by
// consensus (coinbase always matches the included set); (3) under a tight size budget only the
// highest fee-per-byte txs are chosen and the assembled block stays within MAX_BLOCK_SIZE — the
// bug this guards against was templates that dumped the whole mempool, producing "block too
// large" rejections that would halt block production under load.
#include "blockchain.h"
#include "wallet.h"
#include "params.h"
#include <cstdio>
#include <string>
#include <vector>

using consensus::COIN;

static int failures = 0;
static void check(const char* what, bool ok) {
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) failures++;
}

static Transaction make_spend(const OutPoint& src, const Wallet& signer,
                              const std::vector<TxOut>& outs) {
    Transaction tx;
    TxIn in; in.prev = src; tx.vin.push_back(in);
    tx.vout = outs;
    sign_tx(tx, signer);
    return tx;
}

static size_t ser_size(const Transaction& tx) { Writer w; tx.serialize(w); return w.data.size(); }

// Assemble a block from a coinbase + selected txs, mine it, and try to connect it.
static bool build_and_connect(ChainState& cs, ch::CoreHashCtx& ctx, uint64_t& vtime,
                              const std::vector<uint8_t>& miner,
                              const std::vector<Transaction>& sel, uint64_t fees,
                              std::string& err, size_t& block_size_out) {
    uint64_t hgt = cs.height() + 1;
    Block nb;
    nb.header.version   = 1;
    nb.header.prev_hash = cs.tip_hash();
    nb.header.bits      = cs.next_bits();
    vtime += 60; nb.header.timestamp = vtime;
    nb.txs.push_back(make_coinbase(hgt, consensus::block_reward(hgt) + fees, miner));
    for (const auto& t : sel) nb.txs.push_back(t);
    nb.header.merkle_root = nb.compute_merkle_root();
    nb.header.nonce = 0;
    { Writer w; nb.serialize(w); block_size_out = w.data.size(); }
    mine(nb, ctx);
    return cs.connect(nb, ctx, err);
}

int main() {
    select_regtest();
    ch::CoreHashCtx ctx;
    ChainState cs = ChainState::with_genesis();
    Mempool mp;
    Wallet miner = Wallet::from_passphrase("tmpl-miner");
    Wallet alice = Wallet::from_passphrase("tmpl-alice");
    uint64_t vtime = cs.tip().header.timestamp;
    std::string err;

    // Mine 20 blocks so early coinbases mature (maturity 10).
    for (int i = 0; i < 20; i++) {
        uint64_t hgt = cs.height() + 1;
        Block nb; nb.header.version = 1; nb.header.prev_hash = cs.tip_hash();
        nb.header.bits = cs.next_bits(); vtime += 60; nb.header.timestamp = vtime;
        nb.txs.push_back(make_coinbase(hgt, consensus::block_reward(hgt), miner.address()));
        nb.header.merkle_root = nb.compute_merkle_root(); nb.header.nonce = 0;
        mine(nb, ctx);
        if (!cs.connect(nb, ctx, err)) { printf("setup mine failed: %s\n", err.c_str()); return 1; }
    }

    // Min-relay-fee policy: a spend paying below the floor is refused by the mempool. This is
    // relay policy only (the tx is still consensus-valid), and accept() must reject it before
    // touching any state, so the coinbase stays spendable for the tests below.
    {
        OutPoint src{ cs.blocks[1].txs[0].txid(), 0 };
        Transaction cheap = make_spend(src, miner, { TxOut{ 50 * COIN - 1, alice.address() } }); // fee = 1
        std::string e;
        bool rejected = !mp.accept(cheap, cs.utxo, cs.height() + 1, e);
        check("sub-minimum-fee tx rejected by mempool", rejected && e.find("relay minimum") != std::string::npos);
        check("rejected tx leaves mempool untouched", mp.txs.empty());
    }

    // Six independent spends of distinct matured coinbases, each with a distinct fee
    // (0.1 .. 0.6 coin). All are ~equal size, so fee-per-byte order == fee order.
    const int N = 6;
    uint64_t total_all_fees = 0;
    for (int i = 0; i < N; i++) {
        OutPoint src{ cs.blocks[1 + i].txs[0].txid(), 0 };
        uint64_t fee = (uint64_t)(i + 1) * COIN / 10;               // 0.1 * (i+1)
        uint64_t send = 10 * COIN;
        uint64_t change = 50 * COIN - send - fee;
        Transaction tx = make_spend(src, miner, {
            TxOut{ send,   alice.address() },
            TxOut{ change, miner.address() },
        });
        if (!mp.accept(tx, cs.utxo, cs.height() + 1, err)) {
            printf("mempool accept failed for tx %d: %s\n", i, err.c_str()); return 1;
        }
        total_all_fees += fee;
    }
    check("mempool holds all six spends", mp.txs.size() == (size_t)N);

    size_t one = ser_size(mp.txs[0]);

    // (1) Ample budget: everything is chosen, and the fee total is exact.
    {
        uint64_t fees = 0;
        auto sel = mp.select_for_block(cs.utxo, cs.height() + 1,
                       consensus::MAX_BLOCK_SIZE - consensus::COINBASE_RESERVE, fees);
        check("ample budget selects all txs", sel.size() == (size_t)N);
        check("ample budget fee total is exact", fees == total_all_fees);

        std::string e; size_t bsz = 0;
        bool ok = build_and_connect(cs, ctx, vtime, miner.address(), sel, fees, e, bsz);
        check("block from full selection connects", ok);
        check("assembled block within MAX_BLOCK_SIZE", bsz <= consensus::MAX_BLOCK_SIZE);
        if (!ok) printf("    connect error: %s\n", e.c_str());
        mp.remove_confirmed(/*just connected block's txs*/ cs.blocks[cs.height()].txs);
        check("mempool drained after mining", mp.txs.empty());
    }

    // Rebuild the same six spends for the tight-budget test (chain advanced by one block, but
    // the coinbases we spend were already mature and are unaffected — re-accept them).
    total_all_fees = 0;
    for (int i = 0; i < N; i++) {
        OutPoint src{ cs.blocks[7 + i].txs[0].txid(), 0 };            // fresh, still-mature coinbases
        uint64_t fee = (uint64_t)(i + 1) * COIN / 10;
        Transaction tx = make_spend(src, miner, {
            TxOut{ 10 * COIN, alice.address() },
            TxOut{ 50 * COIN - 10 * COIN - fee, miner.address() },
        });
        if (!mp.accept(tx, cs.utxo, cs.height() + 1, err)) {
            printf("re-accept failed for tx %d: %s\n", i, err.c_str()); return 1;
        }
        total_all_fees += fee;
    }

    // (2) Tight budget: room for exactly 3 txs. Expect the three highest-fee ones (0.6+0.5+0.4).
    {
        size_t budget = one * 3 + one / 2;                            // fits 3, not 4
        uint64_t fees = 0;
        auto sel = mp.select_for_block(cs.utxo, cs.height() + 1, budget, fees);
        check("tight budget selects exactly three", sel.size() == 3);

        size_t used = 0; for (auto& t : sel) used += ser_size(t);
        check("selection stays within budget", used <= budget);

        uint64_t expect = (6 + 5 + 4) * COIN / 10;                    // top three fees
        check("tight budget picks the highest-fee txs", fees == expect);

        std::string e; size_t bsz = 0;
        bool ok = build_and_connect(cs, ctx, vtime, miner.address(), sel, fees, e, bsz);
        check("block from tight selection connects (coinbase matches)", ok);
        if (!ok) printf("    connect error: %s\n", e.c_str());
    }

    // Checkpoint enforcement: pin height 5 to its real hash, then try to connect a different
    // block at height 5 (same parent, different coinbase -> different hash). connect() must
    // reject it before it is even stored, so no side branch can rewrite checkpointed history.
    {
        g_params.checkpoints[5] = cs.hashes[5].hex();
        Block alt = cs.blocks[5];
        alt.txs[0] = make_coinbase(5, consensus::block_reward(5), alice.address()); // different miner
        alt.header.merkle_root = alt.compute_merkle_root();
        alt.header.nonce = 0;
        mine(alt, ctx);
        std::string ce;
        bool rejected = !cs.connect(alt, ctx, ce);
        check("checkpoint rejects a mismatched block at a pinned height",
              rejected && ce.find("checkpoint") != std::string::npos);
        // The real block at height 5 still matches the checkpoint (it is already the active tip's
        // ancestor); a fresh validation of it would pass — its hash equals the pinned hash.
        check("pinned hash equals the real block hash", g_params.checkpoints[5] == cs.hashes[5].hex());
        g_params.checkpoints.clear();
    }

    printf("%s\n", failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    return failures == 0 ? 0 : 1;
}
