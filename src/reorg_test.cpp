// Consensus stress test for the reorg path: build a chain, then a heavier competing branch
// from an earlier fork point, and verify the node switches to it correctly, keeps the UTXO
// set consistent, and rejects invalid blocks without corrupting state. The fuzzer can't
// reach this path (it needs valid competing PoW), so this complements it.
#include "blockchain.h"
#include "wallet.h"
#include "params.h"
#include <cstdio>
#include <cstdint>
#include <string>

using namespace std;
static int fails = 0;
static void check(bool ok, const char* what) {
    printf("  [%s] %s\n", ok ? "OK" : "FAIL", what); if (!ok) fails++;
}

int main() {
    select_regtest();
    ch::CoreHashCtx ctx;
    ChainState cs = ChainState::with_genesis();
    uint8_t s[32]; for (int i = 0; i < 32; i++) s[i] = (uint8_t)(i + 3);
    Wallet w = Wallet::from_seed(s);

    auto build = [&](const uint256& prev, uint64_t height, uint64_t ts) {
        Block nb;
        nb.header.version = 1; nb.header.prev_hash = prev; nb.header.bits = cs.next_bits_for(prev);
        nb.header.timestamp = ts;
        nb.txs.push_back(make_coinbase(height, consensus::block_reward(height), w.address()));
        nb.header.merkle_root = nb.compute_merkle_root(); nb.header.nonce = 0;
        mine(nb, ctx);
        return nb;
    };

    printf("== building chain A to height 4 ==\n");
    uint64_t ts = cs.tip().header.timestamp;
    for (uint64_t hgt = 1; hgt <= 4; hgt++) {
        Block b = build(cs.tip_hash(), hgt, ++ts);
        string e; bool ok = cs.connect(b, ctx, e);
        if (!ok) printf("   A block %llu rejected: %s\n", (unsigned long long)hgt, e.c_str());
    }
    check(cs.height() == 4, "chain A at height 4");
    uint256 tipA = cs.tip_hash();
    uint64_t supplyA = 0; for (auto& kv : cs.utxo.map) supplyA += kv.second.amount;

    printf("== building heavier branch B from the height-2 fork, to height 7 ==\n");
    uint256 fork = cs.hashes[2];
    uint64_t bts = cs.blocks[2].header.timestamp + 50;
    uint256 prev = fork;
    bool reorged = false;
    for (uint64_t hgt = 3; hgt <= 7; hgt++) {
        Block b = build(prev, hgt, bts += 5);
        string e; bool ok = cs.connect(b, ctx, e);
        if (!ok) printf("   B block %llu: %s\n", (unsigned long long)hgt, e.c_str());
        prev = b.header.pow_hash(ctx);   // block id = pow hash
    }
    reorged = (cs.height() == 7 && cs.tip_hash() == prev);
    check(reorged, "reorged to heavier branch B (height 7, tip == B tip)");
    check(cs.tip_hash() != tipA, "active tip changed away from A");

    // UTXO must reflect B only (7 coinbases: heights 1,2 shared + B's 3..7 = 7 blocks after genesis)
    uint64_t supplyB = 0; for (auto& kv : cs.utxo.map) supplyB += kv.second.amount;
    printf("   supply A=%llu  supply B=%llu\n", (unsigned long long)supplyA, (unsigned long long)supplyB);
    check(supplyB > supplyA, "supply grew with the longer branch");

    printf("== full re-validation of the active chain ==\n");
    { ChainState v = ChainState::with_genesis(); ch::CoreHashCtx vc; bool ok = true; string e;
      for (uint64_t i = 1; i < cs.blocks.size(); i++) if (!v.connect(cs.blocks[i], vc, e)) { ok = false; printf("   reval fail at %llu: %s\n", (unsigned long long)i, e.c_str()); break; }
      check(ok && v.tip_hash() == cs.tip_hash(), "active chain fully re-validates from genesis"); }

    printf("== reject an over-pay block; active chain must stay intact ==\n");
    uint256 before = cs.tip_hash(); uint64_t beforeH = cs.height();
    { Block bad; bad.header.version = 1; bad.header.prev_hash = cs.tip_hash();
      bad.header.bits = cs.next_bits_for(cs.tip_hash()); bad.header.timestamp = bts += 5;
      bad.txs.push_back(make_coinbase(cs.height() + 1, consensus::block_reward(cs.height() + 1) + 1000ULL * 100000000ULL, w.address()));
      bad.header.merkle_root = bad.compute_merkle_root(); bad.header.nonce = 0; mine(bad, ctx);
      string e; bool ok = cs.connect(bad, ctx, e);
      check(!ok, "over-pay coinbase rejected");
      check(cs.tip_hash() == before && cs.height() == beforeH, "active chain unchanged after rejection"); }

    printf("== duplicate block rejected ==\n");
    { Block dup = cs.blocks[3]; string e; bool ok = cs.connect(dup, ctx, e); check(!ok, "duplicate block rejected"); }

    printf("\n%s (%d failure%s)\n", fails == 0 ? "ALL REORG TESTS PASSED" : "SOME TESTS FAILED",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
