// The full-node entry point, shared by corehashd (standalone) and coremine (all-in-one).
#pragma once
#include <cstdint>
#include <string>
#include <vector>

// Run a full node forever: listen on listen_port, discover/relay peers, sync the chain,
// serve RPC on listen_port+1, and — if mine_wallet is non-empty — mine with mine_threads
// threads to that wallet (unlocked with wallet_pass). The caller must select the network
// (select_mainnet/select_regtest) before calling.
int run_node(uint16_t listen_port, const std::string& peers, const std::string& mine_wallet,
             const std::string& wallet_pass, int mine_threads);

// When true, the node suppresses its routine line logging so a caller can render a
// live dashboard instead. Set before calling run_node.
extern bool g_quiet;

// Snapshot live stats for a dashboard.
void node_stats(uint64_t& height, double& difficulty, double& est_net_hs, int& peers,
                uint64_t& hashes, uint64_t& blocks);

// Balance of an address from the local synced chain: mature (spendable) and immature
// (coinbase not yet matured), in base units.
void node_balance(const std::vector<uint8_t>& addr, uint64_t& mature, uint64_t& immature);
