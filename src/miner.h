// Standalone miner entry point, shared by corehash-miner and coremine's pool mode.
#pragma once
#include <cstdint>
#include <string>

// Connect to a node/pool RPC at host:port, mine to payout_addr_hex with `threads`
// threads (getwork/submit loop). Blocks forever.
int run_miner(const std::string& host, uint16_t port, const std::string& payout_addr_hex, int threads);

// When true, run_miner suppresses its line logging so a caller can render a live
// dashboard instead. Set before calling run_miner.
extern bool g_miner_quiet;

// Live stats for a dashboard. hashes is cumulative; shares/blocks are counts accepted
// by the pool; owed/paid are this miner's pending and paid earnings in base units
// (reported by the pool via "stats", 0 when talking to a plain node); connected is 1
// while the miner has a live link to the pool/node.
void miner_stats(uint64_t& hashes, uint64_t& shares, uint64_t& blocks,
                 uint64_t& owed, uint64_t& paid, int& connected);
