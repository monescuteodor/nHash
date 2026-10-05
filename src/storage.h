// On-disk persistence for the chain and mempool (trusted local files).
#pragma once
#include "blockchain.h"
#include <string>

// Save the full chain (blocks + cached header hashes) to `path`.
bool save_chain(const std::string& path, const ChainState& cs);
// Load a chain saved by save_chain, rebuilding the UTXO set. Returns false if absent.
bool load_chain(const std::string& path, ChainState& cs);

bool save_mempool(const std::string& path, const Mempool& mp);
bool load_mempool(const std::string& path, Mempool& mp, const UTXOSet& utxo, uint64_t next_height);
