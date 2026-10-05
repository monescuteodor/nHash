#include "storage.h"
#include <fstream>
#include <cstdio>
#ifdef _WIN32
  #include <windows.h>
  #include <io.h>
#else
  #include <unistd.h>
#endif

// Crash-safe write: write to <path>.tmp, flush to disk (fsync), then ATOMICALLY rename
// over the target. A crash or power loss can never leave a half-written <path> — it is
// always either the previous complete file or the new complete file. This is what keeps
// the chain from being corrupted on an unclean shutdown.
static bool write_file(const std::string& path, const std::vector<uint8_t>& data) {
    std::string tmp = path + ".tmp";
    FILE* f = fopen(tmp.c_str(), "wb");
    if (!f) return false;
    if (!data.empty() && fwrite(data.data(), 1, data.size(), f) != data.size()) {
        fclose(f); remove(tmp.c_str()); return false;
    }
    fflush(f);
#ifdef _WIN32
    _commit(_fileno(f));                 // flush OS cache to disk
#else
    fsync(fileno(f));
#endif
    fclose(f);
#ifdef _WIN32
    // MoveFileEx with REPLACE_EXISTING is the atomic replace on Windows.
    if (!MoveFileExA(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        remove(tmp.c_str()); return false;
    }
#else
    if (rename(tmp.c_str(), path.c_str()) != 0) { remove(tmp.c_str()); return false; }
#endif
    return true;
}
static bool read_file(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return false;
    std::streamsize n = f.tellg();
    f.seekg(0);
    out.resize((size_t)n);
    if (n > 0) f.read((char*)out.data(), n);
    return (bool)f || n == 0;
}

bool save_chain(const std::string& path, const ChainState& cs) {
    Writer w;
    w.u32(1); // format version
    w.varint(cs.blocks.size());
    for (size_t i = 0; i < cs.blocks.size(); i++) {
        cs.blocks[i].serialize(w);
        w.h256(cs.hashes[i]);
    }
    return write_file(path, w.data);
}

bool load_chain(const std::string& path, ChainState& cs) {
    std::vector<uint8_t> buf;
    if (!read_file(path, buf) || buf.empty()) return false;
    // Tolerate a corrupt/truncated file: never crash on load — report failure so the
    // caller can start from genesis (or restore a backup) instead of aborting.
    try {
        Reader r(buf.data(), buf.size());
        r.u32(); // version
        uint64_t n = r.varint();
        ChainState tmp;                       // build into a scratch state; only commit if fully parsed
        for (uint64_t i = 0; i < n; i++) {
            Block b = read_block(r);
            uint256 h = r.h256();
            for (const auto& tx : b.txs) apply_tx(tmp.utxo, tx, i); // rebuild UTXO (trusted file)
            tmp.blocks.push_back(std::move(b));
            tmp.hashes.push_back(h);
        }
        tmp.rebuild_index();                  // reconstruct by-hash index + cumulative work
        cs = std::move(tmp);
        return true;
    } catch (...) {
        return false;   // corrupt file -> graceful failure, no crash
    }
}

bool save_mempool(const std::string& path, const Mempool& mp) {
    Writer w;
    w.varint(mp.txs.size());
    for (const auto& t : mp.txs) t.serialize(w);
    return write_file(path, w.data);
}

bool load_mempool(const std::string& path, Mempool& mp, const UTXOSet& utxo, uint64_t next_height) {
    std::vector<uint8_t> buf;
    if (!read_file(path, buf) || buf.empty()) return false;
    try {
        Reader r(buf.data(), buf.size());
        uint64_t n = r.varint();
        std::string err;
        for (uint64_t i = 0; i < n; i++) {
            Transaction t = read_transaction(r);
            mp.accept(t, utxo, next_height, err); // re-admit those still valid
        }
        return true;
    } catch (...) {
        return false;   // corrupt mempool file is harmless -> just skip it
    }
}
