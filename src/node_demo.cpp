// CoreHash node demo: mine a real PoW chain, exercise difficulty retarget,
// then re-validate the chain and prove tamper-detection.
#include "blockchain.h"
#include "params.h"
#include <cstdio>
#include <string>
#include <chrono>

static std::vector<uint8_t> pkh_from(const std::string& who) {
    uint8_t h[32];
    ch::blake2b(h, 32, (const uint8_t*)who.data(), who.size());
    return std::vector<uint8_t>(h, h + 32);
}

// Simulated solvetime schedule (seconds): steady, then a fast burst, then slow.
// Lets us watch the retarget respond without waiting real minutes.
static int64_t sim_solvetime(uint64_t h) {
    if (h <= 8)  return 60;   // on target
    if (h <= 16) return 20;   // hashers pile in -> difficulty should climb
    return 150;               // hashers leave  -> difficulty should fall
}

int main() {
    select_regtest();
    ch::CoreHashCtx ctx;
    ChainState cs = ChainState::with_genesis();
    auto miner = pkh_from("teo-miner");

    printf("CoreHash node demo  |  block_time=%llds  window=%d  genesis_diff=%.3f\n",
           (long long)consensus::BLOCK_TIME, consensus::RETARGET_WINDOW,
           cs.difficulty_of(cs.tip().header.bits));
    printf("genesis id: %s\n\n", cs.tip_hash().hex().substr(0, 24).c_str());
    printf("%-4s %-9s %-8s %-11s %-8s %-18s %s\n",
           "hgt", "diff", "solve", "nonce", "tries", "block id (prefix)", "reward");

    const uint64_t N = 24;
    uint64_t virtual_time = cs.tip().header.timestamp;
    double total_hash_ms = 0; uint64_t total_tries = 0;

    for (uint64_t i = 1; i <= N; i++) {
        uint64_t hgt = cs.height() + 1;
        Block nb;
        nb.header.version    = 1;
        nb.header.prev_hash  = cs.tip_hash();
        nb.header.bits       = cs.next_bits();
        int64_t st           = sim_solvetime(hgt);
        virtual_time        += st;
        nb.header.timestamp  = virtual_time;

        uint64_t reward = consensus::block_reward(hgt);
        nb.txs.push_back(make_coinbase(hgt, reward, miner));
        nb.header.merkle_root = nb.compute_merkle_root();
        nb.header.nonce       = 0;

        auto t0 = std::chrono::steady_clock::now();
        uint64_t tries = mine(nb, ctx);
        auto t1 = std::chrono::steady_clock::now();
        total_hash_ms += std::chrono::duration<double, std::milli>(t1 - t0).count();
        total_tries   += tries;

        std::string err;
        if (!cs.connect(nb, ctx, err)) {
            printf("  !! block %llu rejected: %s\n", (unsigned long long)hgt, err.c_str());
            return 1;
        }
        printf("%-4llu %-9.3f %-8lld %-11llu %-8llu %-18s %llu.%08llu\n",
               (unsigned long long)hgt,
               cs.difficulty_of(nb.header.bits),
               (long long)st,
               (unsigned long long)nb.header.nonce,
               (unsigned long long)tries,
               cs.tip_hash().hex().substr(0, 16).c_str(),
               (unsigned long long)(reward / consensus::COIN),
               (unsigned long long)(reward % consensus::COIN));
    }

    // ---- Chain summary ----
    uint64_t supply = 0;
    for (uint64_t h = 0; h <= cs.height(); h++)
        for (const auto& o : cs.blocks[h].txs[0].vout) supply += o.amount;
    printf("\nchain height: %llu   circulating supply: %llu.%08llu coins\n",
           (unsigned long long)cs.height(),
           (unsigned long long)(supply / consensus::COIN),
           (unsigned long long)(supply % consensus::COIN));
    printf("avg %.2f ms/block mined, %.1f hashes/block avg\n",
           total_hash_ms / N, (double)total_tries / N);

    // ---- Re-validate the whole chain from genesis in a fresh state ----
    {
        ChainState v = ChainState::with_genesis();
        std::string err; bool ok = true;
        for (uint64_t h = 1; h <= cs.height(); h++)
            if (!v.connect(cs.blocks[h], ctx, err)) { ok = false;
                printf("re-validation FAILED at height %llu: %s\n", (unsigned long long)h, err.c_str());
                break; }
        if (ok) printf("re-validation: OK (all %llu blocks accepted)\n", (unsigned long long)cs.height());
    }

    // ---- Tamper test: forge extra coins in block 5's coinbase, expect rejection ----
    {
        ChainState v = ChainState::with_genesis();
        std::string err; bool caught = false;
        for (uint64_t h = 1; h <= cs.height(); h++) {
            Block b = cs.blocks[h];
            if (h == 5) b.txs[0].vout[0].amount += 999 * consensus::COIN; // steal 999 coins
            if (!v.connect(b, ctx, err)) {
                printf("tamper test: rejected forged block %llu -> \"%s\"  (good)\n",
                       (unsigned long long)h, err.c_str());
                caught = true; break;
            }
        }
        if (!caught) printf("tamper test: FORGERY NOT CAUGHT (bad!)\n");
    }
    return 0;
}
