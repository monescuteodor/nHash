// CoreHash UTXO/transaction/wallet demo: mine coinbases, sign & spend them, run a
// mempool, and prove double-spend, immature-coinbase, wrong-owner and bad-signature rejection.
#include "blockchain.h"
#include "wallet.h"
#include "params.h"
#include <cstdio>
#include <string>

using consensus::COIN;

static void fmt(const char* label, uint64_t amt) {
    printf("  %-22s %llu.%08llu\n", label,
           (unsigned long long)(amt / COIN), (unsigned long long)(amt % COIN));
}

static bool mine_block(ChainState& cs, Mempool& mp, ch::CoreHashCtx& ctx, uint64_t& vtime,
                       const std::vector<uint8_t>& miner, std::string& err) {
    uint64_t hgt = cs.height() + 1;
    Block nb;
    nb.header.version   = 1;
    nb.header.prev_hash = cs.tip_hash();
    nb.header.bits      = cs.next_bits();
    vtime += 60; nb.header.timestamp = vtime;
    uint64_t fees = 0;
    auto pooled = mp.select_for_block(cs.utxo, hgt,
                      consensus::MAX_BLOCK_SIZE - consensus::COINBASE_RESERVE, fees);
    nb.txs.push_back(make_coinbase(hgt, consensus::block_reward(hgt) + fees, miner));
    for (const auto& t : pooled) nb.txs.push_back(t);
    nb.header.merkle_root = nb.compute_merkle_root();
    nb.header.nonce = 0;
    mine(nb, ctx);
    if (!cs.connect(nb, ctx, err)) return false;
    mp.remove_confirmed(nb.txs);
    return true;
}

// Build a signed spend of one output owned by `signer`.
static Transaction make_spend(const OutPoint& src, const Wallet& signer,
                              const std::vector<TxOut>& outs) {
    Transaction tx;
    TxIn in; in.prev = src; tx.vin.push_back(in);
    tx.vout = outs;
    sign_tx(tx, signer);
    return tx;
}

int main() {
    select_regtest();
    ch::CoreHashCtx ctx;
    ChainState cs = ChainState::with_genesis();
    Mempool mp;
    Wallet miner = Wallet::from_passphrase("teo-miner");
    Wallet alice = Wallet::from_passphrase("alice");
    uint64_t vtime = cs.tip().header.timestamp;
    std::string err;

    // 1) Mine 12 blocks to the miner.
    for (int i = 0; i < 12; i++)
        if (!mine_block(cs, mp, ctx, vtime, miner.address(), err)) { printf("mine failed: %s\n", err.c_str()); return 1; }
    printf("Mined to height %llu. Balances:\n", (unsigned long long)cs.height());
    fmt("miner:", cs.utxo.balance_of(miner.address()));
    fmt("alice:", cs.utxo.balance_of(alice.address()));
    printf("  UTXO set size: %zu\n\n", cs.utxo.map.size());

    // 2) Signed spend of block #1 coinbase (matured): 30 -> alice, 19.9 change, 0.1 fee.
    OutPoint src{ cs.blocks[1].txs[0].txid(), 0 };
    Transaction spend = make_spend(src, miner, {
        TxOut{ 30 * COIN, alice.address() },
        TxOut{ 50 * COIN - 30 * COIN - COIN / 10, miner.address() },
    });
    printf("Signed spend of block#1 coinbase -> alice 30, change 19.9, fee 0.1\n");
    printf("  mempool: %s\n", mp.accept(spend, cs.utxo, cs.height() + 1, err)
           ? "accepted" : ("REJECTED: " + err).c_str());

    // 3) Double-spend: validly-signed tx spending the SAME output.
    Transaction dbl = make_spend(src, miner, { TxOut{ 40 * COIN, alice.address() } });
    printf("Double-spend attempt (same output, valid signature):\n");
    printf("  mempool: %s\n", mp.accept(dbl, cs.utxo, cs.height() + 1, err)
           ? "ACCEPTED (bad!)" : ("rejected -> \"" + err + "\" (good)").c_str());

    // 4) Immature coinbase: spend block #12's coinbase (age 1 < maturity 10).
    Transaction imm = make_spend(OutPoint{ cs.blocks[12].txs[0].txid(), 0 }, miner,
                                 { TxOut{ 10 * COIN, alice.address() } });
    printf("Immature-coinbase spend attempt (block #12):\n");
    printf("  mempool: %s\n", mp.accept(imm, cs.utxo, cs.height() + 1, err)
           ? "ACCEPTED (bad!)" : ("rejected -> \"" + err + "\" (good)").c_str());

    // 5) Wrong owner: alice tries to spend block #2's coinbase (owned by miner).
    Transaction wrong = make_spend(OutPoint{ cs.blocks[2].txs[0].txid(), 0 }, alice,
                                   { TxOut{ 10 * COIN, alice.address() } });
    printf("Wrong-owner spend attempt (alice signs miner's coinbase):\n");
    printf("  mempool: %s\n", mp.accept(wrong, cs.utxo, cs.height() + 1, err)
           ? "ACCEPTED (bad!)" : ("rejected -> \"" + err + "\" (good)").c_str());

    // 6) Corrupted signature: valid spend of block #3 with one signature byte flipped.
    Transaction bad = make_spend(OutPoint{ cs.blocks[3].txs[0].txid(), 0 }, miner,
                                 { TxOut{ 10 * COIN, alice.address() } });
    bad.vin[0].sig[5] ^= 1;
    printf("Corrupted-signature spend attempt (block #3):\n");
    printf("  mempool: %s\n\n", mp.accept(bad, cs.utxo, cs.height() + 1, err)
           ? "ACCEPTED (bad!)" : ("rejected -> \"" + err + "\" (good)").c_str());

    // 7) Mine the block; it includes only the one valid spend and pays its fee to the miner.
    if (!mine_block(cs, mp, ctx, vtime, miner.address(), err)) { printf("mine failed: %s\n", err.c_str()); return 1; }
    printf("Mined block %llu. Balances now:\n", (unsigned long long)cs.height());
    fmt("miner:", cs.utxo.balance_of(miner.address()));
    fmt("alice:", cs.utxo.balance_of(alice.address()));
    printf("  mempool size: %zu\n\n", mp.txs.size());

    // 8) Re-validate the whole chain from genesis (rebuild UTXO independently).
    {
        ChainState v = ChainState::with_genesis();
        bool ok = true;
        for (uint64_t h = 1; h <= cs.height(); h++)
            if (!v.connect(cs.blocks[h], ctx, err)) {
                printf("re-validation FAILED at height %llu: %s\n", (unsigned long long)h, err.c_str());
                ok = false; break;
            }
        if (ok) printf("re-validation: OK (all %llu blocks, signatures + UTXO verified)\n",
                       (unsigned long long)cs.height());
    }
    return 0;
}
