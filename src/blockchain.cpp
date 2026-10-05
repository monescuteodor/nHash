#include "blockchain.h"
#include "params.h"
#include <cmath>
#include <algorithm>
#include <ctime>

namespace consensus {
    uint64_t block_reward(uint64_t height) {
        uint64_t halvings = height / HALVING_INTERVAL;
        if (halvings >= 64) return 0;
        return INITIAL_REWARD >> halvings;
    }
}

// Difficulty-1 target for the active network (also the retarget floor).
static uint256 genesis_target() { return g_params.genesis_target; }

// ---- Approximate target <-> double (difficulty math; ~52 bits precision like nBits' 24) ----
static double target_to_double(const uint256& t) {
    double r = 0;
    for (int i = 31; i >= 0; --i) r = r * 256.0 + (double)t.b[i];
    return r;
}
static uint256 double_to_target(double v) {
    uint256 t;
    if (v < 1.0) v = 1.0;
    for (int i = 0; i < 32 && v >= 1.0; i++) {
        t.b[i] = (uint8_t)std::fmod(v, 256.0);
        v = std::floor(v / 256.0);
    }
    return t;
}

// Work contributed by a block, proportional to 1/target (== difficulty here).
static double work_of(uint32_t bits) {
    double t = target_to_double(bits_to_target(bits));
    if (t < 1.0) t = 1.0;
    return target_to_double(genesis_target()) / t;
}

// Validate a block's transactions against `view` and apply them (coinbase last).
static bool validate_and_apply(UTXOSet& view, const Block& b, uint64_t height, std::string& err) {
    uint64_t total_fees = 0;
    for (size_t i = 1; i < b.txs.size(); i++) {
        uint64_t fee = 0;
        if (!check_tx(b.txs[i], view, height, fee, err)) return false;
        total_fees += fee;
        if (total_fees > consensus::MAX_MONEY) { err = "fee overflow"; return false; }
        apply_tx(view, b.txs[i], height);
    }
    uint64_t cb = 0; for (const auto& o : b.txs[0].vout) cb += o.amount;
    if (cb > consensus::block_reward(height) + total_fees) { err = "coinbase over-pays subsidy+fees"; return false; }
    apply_tx(view, b.txs[0], height);
    return true;
}

ChainState ChainState::with_genesis() {
    ChainState cs;
    Block g;
    g.header.version = 1;
    g.header.prev_hash = uint256{};
    g.header.timestamp = g_params.genesis_time;
    g.header.bits = target_to_bits(genesis_target());
    g.header.nonce = 0;
    std::vector<uint8_t> gpkh(32, 0);
    g.txs.push_back(make_coinbase(0, consensus::block_reward(0), gpkh));
    g.header.merkle_root = g.compute_merkle_root();
    ch::CoreHashCtx ctx;
    uint256 gh = g.header.pow_hash(ctx);
    cs.blocks.push_back(g);
    cs.hashes.push_back(gh);
    apply_tx(cs.utxo, g.txs[0], 0);
    cs.index[gh] = BlockRec{ g, uint256{}, 0, 0.0 };
    return cs;
}

// Rebuild the block index (used after loading the active chain from disk).
void ChainState::rebuild_index() {
    index.clear();
    double cw = 0;
    for (size_t i = 0; i < blocks.size(); i++) {
        if (i > 0) cw += work_of(blocks[i].header.bits);
        index[hashes[i]] = BlockRec{ blocks[i], blocks[i].header.prev_hash, i, cw };
    }
}

// ---- Deterministic integer uint256 helpers (little-endian, 8 x uint32 limbs) ----
static void to_l32(const uint256& t, uint32_t l[8]) { for (int i = 0; i < 8; i++) memcpy(&l[i], &t.b[i * 4], 4); }
static uint256 from_l32(const uint32_t l[8]) { uint256 t; for (int i = 0; i < 8; i++) memcpy(&t.b[i * 4], &l[i], 4); return t; }
static uint256 u256_div_u32(const uint256& a, uint32_t d) {
    uint32_t l[8]; to_l32(a, l); uint64_t rem = 0;
    for (int i = 7; i >= 0; --i) { uint64_t cur = (rem << 32) | l[i]; l[i] = (uint32_t)(cur / d); rem = cur % d; }
    return from_l32(l);
}
static uint256 u256_mul_u32(const uint256& a, uint32_t m) { // caller ensures the result fits 256 bits
    uint32_t l[8]; to_l32(a, l); uint64_t carry = 0;
    for (int i = 0; i < 8; i++) { uint64_t cur = (uint64_t)l[i] * m + carry; l[i] = (uint32_t)cur; carry = cur >> 32; }
    return from_l32(l);
}
static uint256 u256_add(const uint256& a, const uint256& b) {
    uint32_t la[8], lb[8], r[8]; to_l32(a, la); to_l32(b, lb); uint64_t carry = 0;
    for (int i = 0; i < 8; i++) { uint64_t cur = (uint64_t)la[i] + lb[i] + carry; r[i] = (uint32_t)cur; carry = cur >> 32; }
    return from_l32(r);
}

// LWMA-1 (Zawy): linearly-weighted moving average of solvetimes, in exact integer math.
// next_target = (sum of last N targets) * WS / (N * weight_sum * T), where WS weights the
// newest solvetime most. Deterministic on every platform (no floating point).
uint32_t ChainState::next_bits_for(const uint256& prev) const {
    auto it = index.find(prev);
    if (it == index.end()) return target_to_bits(genesis_target());
    const BlockRec& P = it->second;
    const int N = g_params.retarget_window;
    const int64_t T = g_params.block_time;
    if ((int64_t)P.height < N) return P.block.header.bits; // warmup: hold genesis difficulty

    std::vector<int64_t> ts; std::vector<uint256> tgt;
    uint256 cur = prev;
    for (int k = 0; k <= N; k++) {
        const BlockRec& r = index.at(cur);
        ts.push_back((int64_t)r.block.header.timestamp);
        tgt.push_back(bits_to_target(r.block.header.bits));
        if (k < N) cur = r.prev;
    }
    uint64_t weight_sum = (uint64_t)N * (N + 1) / 2;
    uint64_t WS = 0;
    uint256 sum_target{};
    for (int k = 0; k < N; k++) {
        int64_t st = ts[k] - ts[k + 1];
        if (st < 1) st = 1; if (st > 6 * T) st = 6 * T; // clamp each solvetime to [1, 6T]
        WS += (uint64_t)(N - k) * (uint64_t)st;         // newest (k=0) weighted N, oldest weighted 1
        sum_target = u256_add(sum_target, tgt[k]);
    }
    if (WS < 1) WS = 1;
    uint256 nt = u256_div_u32(sum_target, (uint32_t)N);
    nt = u256_div_u32(nt, (uint32_t)(weight_sum * (uint64_t)T));
    nt = u256_mul_u32(nt, (uint32_t)WS);
    uint256 gt = genesis_target();
    if (nt.is_zero()) nt.b[0] = 1;
    if (gt < nt) nt = gt;                                // never easier than genesis
    return target_to_bits(nt);
}

uint32_t ChainState::next_bits() const { return next_bits_for(tip_hash()); }

double ChainState::difficulty_of(uint32_t bits) const {
    double cur = target_to_double(bits_to_target(bits));
    if (cur < 1.0) cur = 1.0;
    return target_to_double(genesis_target()) / cur;
}

bool ChainState::connect(const Block& b, ch::CoreHashCtx& ctx, std::string& err) {
    { Writer wsz; b.serialize(wsz); if (wsz.data.size() > consensus::MAX_BLOCK_SIZE) { err = "block too large"; return false; } }
    uint256 h = b.header.pow_hash(ctx);
    if (index.count(h)) { err = "duplicate block"; return false; }
    auto pit = index.find(b.header.prev_hash);
    if (pit == index.end()) { err = "unknown prev (orphan)"; return false; }
    uint64_t new_height = pit->second.height + 1;
    double   cw = pit->second.cumwork + work_of(b.header.bits);

    // Checkpoint: a block at a checkpointed height must have exactly the checkpointed hash.
    // A side branch that diverges before the last checkpoint can never present the right hash
    // here, so it can never overtake the main chain — deep history rewrites are impossible.
    { auto cp = g_params.checkpoints.find(new_height);
      if (cp != g_params.checkpoints.end() && h.hex() != cp->second) {
          err = "rejected: checkpoint mismatch at height " + std::to_string(new_height); return false; } }

    // Context-free + parent-relative validation (tx/UTXO checks happen at activation).
    if (b.header.bits != next_bits_for(b.header.prev_hash)) { err = "incorrect difficulty bits"; return false; }

    // Timestamp: must exceed the median of the last mtp_window ancestors (prevents
    // difficulty manipulation), and must not lead wall-clock by more than future_drift.
    {
        std::vector<int64_t> times; uint256 c = b.header.prev_hash;
        for (int i = 0; i < g_params.mtp_window; i++) {
            auto it = index.find(c); if (it == index.end()) break;
            times.push_back((int64_t)it->second.block.header.timestamp);
            if (it->second.height == 0) break;
            c = it->second.prev;
        }
        std::sort(times.begin(), times.end());
        int64_t mtp = times[times.size() / 2];
        if ((int64_t)b.header.timestamp <= mtp) { err = "timestamp <= median-time-past"; return false; }
        int64_t now = (int64_t)time(nullptr);
        if ((int64_t)b.header.timestamp > now + g_params.future_drift) { err = "timestamp too far in future"; return false; }
    }
    if (b.txs.empty() || !b.txs[0].is_coinbase()) { err = "missing coinbase"; return false; }
    for (size_t i = 1; i < b.txs.size(); i++)
        if (b.txs[i].is_coinbase()) { err = "multiple coinbase txs"; return false; }
    if (b.header.merkle_root != b.compute_merkle_root()) { err = "merkle root mismatch"; return false; }
    if (!(h <= bits_to_target(b.header.bits))) { err = "PoW target not met"; return false; }

    index[h] = BlockRec{ b, b.header.prev_hash, new_height, cw };

    if (cw <= index[tip_hash()].cumwork) return true; // valid, but not the heaviest chain

    if (b.header.prev_hash == tip_hash()) {
        // Fast path: extends the active tip.
        UTXOSet view = utxo;
        if (!validate_and_apply(view, b, new_height, err)) { index.erase(h); return false; }
        utxo.map.swap(view.map);
        blocks.push_back(b);
        hashes.push_back(h);
        return true;
    }

    // Reorg: rebuild the active chain from genesis along the heaviest branch.
    std::vector<uint256> path; uint256 cur = h;
    while (true) { path.push_back(cur); if (index[cur].height == 0) break; cur = index[cur].prev; }
    std::reverse(path.begin(), path.end());
    UTXOSet nu; std::vector<Block> nb; std::vector<uint256> nh;
    for (size_t i = 0; i < path.size(); i++) {
        BlockRec& r = index[path[i]];
        if (i == 0) apply_tx(nu, r.block.txs[0], 0);
        else if (!validate_and_apply(nu, r.block, r.height, err)) { index.erase(h); return false; }
        nb.push_back(r.block); nh.push_back(path[i]);
    }
    blocks.swap(nb); hashes.swap(nh); utxo.map.swap(nu.map);
    return true;
}

double expected_hashes_per_block(uint32_t bits) {
    double t = target_to_double(bits_to_target(bits));
    if (t < 1.0) t = 1.0;
    return 1.157920892373162e77 / t; // 2^256 / target
}

uint64_t mine(Block& b, ch::CoreHashCtx& ctx, uint64_t max_tries) {
    uint256 target = bits_to_target(b.header.bits);
    uint64_t tries = 0;
    while (tries < max_tries) {
        tries++;
        if (b.header.pow_hash(ctx) <= target) return tries;
        b.header.nonce++;
    }
    return 0;
}

// ============================ Mempool ============================
bool Mempool::accept(const Transaction& tx, const UTXOSet& utxo, uint64_t next_height,
                     std::string& err) {
    if (txs.size() >= consensus::MAX_MEMPOOL_TXS) { err = "mempool full"; return false; }
    uint64_t fee = 0;
    if (!check_tx(tx, utxo, next_height, fee, err)) return false;
    { Writer wsz; tx.serialize(wsz);
      uint64_t minf = consensus::min_relay_fee(wsz.data.size());
      if (fee < minf) { err = "fee below relay minimum"; return false; } }
    for (const auto& in : tx.vin)
        if (claimed.count(in.prev)) { err = "input already spent by a pooled tx"; return false; }
    for (const auto& in : tx.vin) claimed.insert(in.prev);
    txs.push_back(tx);
    return true;
}

void Mempool::remove_confirmed(const std::vector<Transaction>& block_txs) {
    std::set<uint256> confirmed;
    for (const auto& t : block_txs) confirmed.insert(t.txid());

    std::vector<Transaction> keep;
    for (auto& t : txs)
        if (!confirmed.count(t.txid())) keep.push_back(t);
    txs.swap(keep);

    // Rebuild the claimed-inputs set from whatever remains.
    claimed.clear();
    for (const auto& t : txs)
        for (const auto& in : t.vin) claimed.insert(in.prev);
}

uint64_t Mempool::total_fees(const UTXOSet& utxo, uint64_t next_height) const {
    // Evaluate fees against a working view so chained pooled txs validate in order.
    UTXOSet view = utxo;
    uint64_t sum = 0;
    for (const auto& t : txs) {
        uint64_t fee = 0; std::string err;
        if (check_tx(t, view, next_height, fee, err)) { sum += fee; apply_tx(view, t, next_height); }
    }
    return sum;
}

std::vector<Transaction> Mempool::select_for_block(const UTXOSet& utxo, uint64_t next_height,
                                                   size_t size_budget, uint64_t& out_fees) const {
    // Score every pooled tx once against the confirmed UTXO set: fee, serialized size, and
    // fee-per-byte. Pooled txs are pairwise independent (accept() only admits spends of
    // confirmed outputs and rejects double-claims), so a single pass over the confirmed view
    // is enough — no O(n^2) dependency re-scan, which would be far too slow for a full mempool
    // (each check_tx verifies signatures).
    struct Cand { size_t idx; uint64_t fee; size_t sz; double rate; };
    std::vector<Cand> cands;
    cands.reserve(txs.size());
    for (size_t i = 0; i < txs.size(); i++) {
        uint64_t fee = 0; std::string err;
        if (!check_tx(txs[i], utxo, next_height, fee, err)) continue; // drop stale/now-invalid
        Writer w; txs[i].serialize(w);
        size_t sz = w.data.size();
        cands.push_back({ i, fee, sz, (double)fee / (double)(sz ? sz : 1) });
    }
    // Highest fee-per-byte first; break ties toward larger absolute fee, then smaller size.
    std::sort(cands.begin(), cands.end(), [](const Cand& a, const Cand& b) {
        if (a.rate != b.rate) return a.rate > b.rate;
        if (a.fee  != b.fee)  return a.fee  > b.fee;
        return a.sz < b.sz;
    });
    std::vector<Transaction> chosen;
    out_fees = 0;
    size_t used = 0;
    for (const auto& c : cands) {
        if (used + c.sz > size_budget) continue; // keep packing: a later smaller tx may still fit
        chosen.push_back(txs[c.idx]);
        used += c.sz;
        out_fees += c.fee;
    }
    return chosen;
}
