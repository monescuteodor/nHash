// Network / consensus parameters, selectable per network (mainnet vs regtest-demo).
// A single global g_params is read across the node; select it once at startup.
#pragma once
#include "primitives.h"
#include <cstdint>
#include <vector>
#include <string>
#include <map>

struct NetParams {
    const char* name;
    uint32_t    magic;             // network id in the P2P handshake
    uint16_t    default_port;
    uint256     genesis_target;    // difficulty-1 target (also the retarget floor)
    uint64_t    genesis_time;
    uint64_t    coinbase_maturity; // blocks before a coinbase output is spendable
    int64_t     block_time;        // seconds
    int         retarget_window;   // blocks averaged for difficulty
    int         mtp_window;        // median-time-past window (odd, e.g. 11)
    int64_t     future_drift;      // max seconds a block timestamp may lead wall-clock
    std::vector<std::string> seeds; // bootstrap "host:port" addresses for peer discovery
    std::map<uint64_t, std::string> checkpoints; // height -> required block hash (hex). A block
                                    // at a checkpointed height must have this hash, so history
                                    // at or below the last checkpoint cannot be rewritten by a
                                    // reorg. Empty on regtest. See ChainState::connect.
};

extern NetParams g_params;

void select_mainnet();  // hard genesis, maturity 100 — for a real network
void select_regtest();  // easy genesis, maturity 10 — for local demos/tests
