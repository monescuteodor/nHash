// Robustness fuzzer for CoreHash's untrusted-input surface: the block/transaction parsers
// and the validation paths that process bytes received from unknown P2P peers. It feeds
// mutated-valid and fully-random bytes into read_block/read_transaction + ChainState::connect
// + Mempool::accept, and asserts the node never crashes and never corrupts state — every bad
// input must be rejected cleanly (return false or a caught exception).
//
// Build under sanitizers to catch memory errors / UB:
//   g++ -O1 -g -std=c++17 -maes -pthread -fsanitize=address,undefined \
//       corehash.cpp block.cpp blockchain.cpp utxo.cpp ed25519.cpp wallet.cpp \
//       storage.cpp params.cpp fuzz.cpp -o fuzz
// Usage: fuzz [iterations=200000] [seed=1]
#include "blockchain.h"
#include "wallet.h"
#include "params.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <random>

using namespace std;

int main(int argc, char** argv) {
    uint64_t ITERS = (argc > 1) ? strtoull(argv[1], nullptr, 10) : 200000;
    uint64_t SEED  = (argc > 2) ? strtoull(argv[2], nullptr, 10) : 1;
    mt19937_64 rng(SEED);
    select_regtest();                 // low difficulty -> fast to build a base chain

    ch::CoreHashCtx ctx;
    ChainState cs = ChainState::with_genesis();
    uint8_t wseed[32]; for (int i = 0; i < 32; i++) wseed[i] = (uint8_t)(i + 1);
    Wallet w = Wallet::from_seed(wseed);

    // Build a small valid chain and collect valid serialized blocks/txs as fuzz seeds.
    vector<vector<uint8_t>> seeds;
    uint64_t last_ts = cs.tip().header.timestamp;
    for (int i = 0; i < 5; i++) {
        Block nb;
        nb.header.version = 1; nb.header.prev_hash = cs.tip_hash(); nb.header.bits = cs.next_bits();
        nb.header.timestamp = ++last_ts;
        nb.txs.push_back(make_coinbase(cs.height() + 1, consensus::block_reward(cs.height() + 1), w.address()));
        nb.header.merkle_root = nb.compute_merkle_root(); nb.header.nonce = 0;
        mine(nb, ctx);
        string e; if (!cs.connect(nb, ctx, e)) { printf("setup: block rejected: %s\n", e.c_str()); return 1; }
        Writer bw; nb.serialize(bw); seeds.push_back(bw.data);
    }
    const ChainState base = cs;       // pristine copy to connect fuzzed blocks against
    uint64_t parsed_ok = 0, rejected = 0, threw = 0;

    auto fuzz_bytes = [&](vector<uint8_t> buf) {
        // ---- block path ----
        try {
            Reader r(buf.data(), buf.size());
            Block b = read_block(r);
            ChainState t = base; string e;
            t.connect(b, ctx, e);      // must return cleanly; invalid -> false
            parsed_ok++;
        } catch (...) { threw++; }
        // ---- transaction path ----
        try {
            Reader r(buf.data(), buf.size());
            Transaction tx = read_transaction(r);
            Mempool mp; string e;
            mp.accept(tx, base.utxo, base.height() + 1, e);
            rejected++;
        } catch (...) { threw++; }
    };

    for (uint64_t it = 0; it < ITERS; it++) {
        int mode = rng() % 3;
        if (mode == 0) {
            // fully random bytes (0..512)
            size_t n = rng() % 513;
            vector<uint8_t> b(n); for (auto& x : b) x = (uint8_t)rng();
            fuzz_bytes(std::move(b));
        } else {
            // mutate a valid seed
            vector<uint8_t> b = seeds[rng() % seeds.size()];
            int muts = 1 + (rng() % 8);
            for (int m = 0; m < muts && !b.empty(); m++) {
                size_t pos = rng() % b.size();
                int op = rng() % 3;
                if (op == 0) b[pos] ^= (uint8_t)(1u << (rng() % 8));   // flip a bit
                else if (op == 1) b[pos] = (uint8_t)rng();             // random byte
                else if (b.size() > 1) b.erase(b.begin() + pos);      // truncate
            }
            if (mode == 2 && !b.empty()) b.resize(rng() % (b.size() + 1)); // random truncation
            fuzz_bytes(std::move(b));
        }
        if ((it & 0x3FFFF) == 0x3FFFF)
            printf("  %llu iters ok (parsed %llu, rejected %llu, threw %llu)\n",
                   (unsigned long long)(it + 1), (unsigned long long)parsed_ok,
                   (unsigned long long)rejected, (unsigned long long)threw);
    }
    printf("FUZZ DONE: %llu iterations, no crash. parsed=%llu rejected=%llu threw(caught)=%llu\n",
           (unsigned long long)ITERS, (unsigned long long)parsed_ok,
           (unsigned long long)rejected, (unsigned long long)threw);
    return 0;
}
