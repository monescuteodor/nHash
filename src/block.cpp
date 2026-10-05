#include "block.h"

// ============================ Transaction ============================
void Transaction::serialize(Writer& w) const {
    w.u32(version);
    w.varint(vin.size());
    for (const auto& in : vin) {
        w.h256(in.prev.txid);
        w.u32(in.prev.index);
        w.bytes(in.sig);
        w.u32(in.sequence);
    }
    w.varint(vout.size());
    for (const auto& out : vout) {
        w.u64(out.amount);
        w.bytes(out.pubkey_hash);
    }
    w.u64(lock_time);
}

uint256 Transaction::txid() const {
    Writer w; serialize(w);
    uint8_t h[32];
    ch::blake2b(h, 32, w.data.data(), w.data.size());
    return uint256::from_bytes(h);
}

uint256 Transaction::sighash() const {
    Transaction t = *this;
    for (auto& in : t.vin) in.sig.clear(); // sign over the tx with empty unlocking data
    Writer w; t.serialize(w);
    uint8_t h[32];
    ch::blake2b(h, 32, w.data.data(), w.data.size());
    return uint256::from_bytes(h);
}

bool Transaction::is_coinbase() const {
    return vin.size() == 1 && vin[0].prev.txid.is_zero() && vin[0].prev.index == 0xffffffff;
}

Transaction make_coinbase(uint64_t height, uint64_t reward,
                          const std::vector<uint8_t>& miner_pubkey_hash) {
    Transaction tx;
    TxIn in;
    in.prev.txid = uint256{};          // null
    in.prev.index = 0xffffffff;
    Writer cb; cb.u64(height);          // height in coinbase -> unique txid per height
    in.sig = cb.data;
    tx.vin.push_back(in);
    TxOut o; o.amount = reward; o.pubkey_hash = miner_pubkey_hash;
    tx.vout.push_back(o);
    return tx;
}

Transaction read_transaction(Reader& r) {
    Transaction t;
    t.version = r.u32();
    uint64_t nin = r.varint();
    for (uint64_t i = 0; i < nin; i++) {
        TxIn in;
        in.prev.txid = r.h256();
        in.prev.index = r.u32();
        in.sig = r.bytes();
        in.sequence = r.u32();
        t.vin.push_back(std::move(in));
    }
    uint64_t nout = r.varint();
    for (uint64_t i = 0; i < nout; i++) {
        TxOut o;
        o.amount = r.u64();
        o.pubkey_hash = r.bytes();
        t.vout.push_back(std::move(o));
    }
    t.lock_time = r.u64();
    return t;
}

BlockHeader read_block_header(Reader& r) {
    BlockHeader h;
    h.version = r.u32();
    h.prev_hash = r.h256();
    h.merkle_root = r.h256();
    h.timestamp = r.u64();
    h.bits = r.u32();
    h.nonce = r.u64();
    return h;
}

Block read_block(Reader& r) {
    Block b;
    b.header = read_block_header(r);
    uint64_t ntx = r.varint();
    for (uint64_t i = 0; i < ntx; i++) b.txs.push_back(read_transaction(r));
    return b;
}

// ============================ BlockHeader ============================
void BlockHeader::serialize(Writer& w) const {
    w.u32(version);
    w.h256(prev_hash);
    w.h256(merkle_root);
    w.u64(timestamp);
    w.u32(bits);
    w.u64(nonce);
}

uint256 BlockHeader::pow_hash(ch::CoreHashCtx& ctx) const {
    Writer w; serialize(w);
    uint8_t h[32];
    ch::corehash(w.data.data(), w.data.size(), h, ctx);
    return uint256::from_bytes(h);
}

// ============================ Merkle ============================
uint256 merkle_root(const std::vector<uint256>& leaves) {
    if (leaves.empty()) return uint256{};
    std::vector<uint256> cur = leaves;
    while (cur.size() > 1) {
        if (cur.size() & 1) cur.push_back(cur.back()); // duplicate last if odd
        std::vector<uint256> next;
        next.reserve(cur.size() / 2);
        for (size_t i = 0; i < cur.size(); i += 2) {
            uint8_t buf[64];
            memcpy(buf, cur[i].b.data(), 32);
            memcpy(buf + 32, cur[i + 1].b.data(), 32);
            uint8_t h[32];
            ch::blake2b(h, 32, buf, 64);
            next.push_back(uint256::from_bytes(h));
        }
        cur.swap(next);
    }
    return cur[0];
}

void Block::serialize(Writer& w) const {
    header.serialize(w);
    w.varint(txs.size());
    for (const auto& t : txs) t.serialize(w);
}

uint256 Block::compute_merkle_root() const {
    std::vector<uint256> ids;
    ids.reserve(txs.size());
    for (const auto& t : txs) ids.push_back(t.txid());
    return merkle_root(ids);
}

// ============================ Compact difficulty (nBits) ============================
uint256 bits_to_target(uint32_t bits) {
    uint256 t;
    int exp = (int)(bits >> 24);
    uint32_t mant = bits & 0x007fffff;
    if (exp <= 3) {
        mant >>= 8 * (3 - exp);
        t.b[0] = (uint8_t)(mant);
        t.b[1] = (uint8_t)(mant >> 8);
        t.b[2] = (uint8_t)(mant >> 16);
    } else {
        int off = exp - 3;
        for (int i = 0; i < 3; i++) {
            int idx = off + i;
            if (idx >= 0 && idx < 32) t.b[idx] = (uint8_t)(mant >> (8 * i));
        }
    }
    return t;
}

uint32_t target_to_bits(const uint256& t) {
    int msb = 31;
    while (msb > 0 && t.b[msb] == 0) msb--;
    int exp = msb + 1;
    uint32_t mant = 0;
    for (int i = 0; i < 3; i++) {
        int idx = msb - i;
        mant <<= 8;
        if (idx >= 0) mant |= t.b[idx];
    }
    if (mant & 0x00800000) { mant >>= 8; exp += 1; } // avoid sign bit (nBits convention)
    return (uint32_t)((exp << 24) | (mant & 0x007fffff));
}
