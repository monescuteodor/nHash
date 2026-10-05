#include "params.h"

// Default to mainnet; demos call select_regtest() at startup.
NetParams g_params = {
    "mainnet", 0x43483031 /*"CH01"*/, 9333,
    uint256{}, 1735689600ULL, 100, 60, 60, 11, 2 * 60 * 60, {}
};

static uint256 target_top(int byte_index, uint8_t val) {
    uint256 t; t.b[byte_index] = val; return t;
}

void select_mainnet() {
    g_params.name = "mainnet";
    g_params.magic = 0x43483031;   // "CH01"
    g_params.default_port = 9333;
    // ~2^247 => ~512 expected hashes/block (~5-6s on one core), so a small group can
    // bootstrap the chain quickly; the retarget raises difficulty toward 60s as miners join.
    g_params.genesis_target = target_top(30, 0x80);
    g_params.genesis_time = 1735689600ULL; // 2025-01-01
    g_params.coinbase_maturity = 100;
    g_params.block_time = 300;   // 5 minutes between blocks
    g_params.retarget_window = 60;
    g_params.mtp_window = 11;
    g_params.future_drift = 2 * 60 * 60;
    // Seed node(s) every binary auto-connects to. The i5-2500K host on the LAN:
    g_params.seeds = { "192.168.50.220:9333" };
    // Checkpoints: real hashes of the live chain. A block at one of these heights must match,
    // so no reorg can rewrite history at or below the last checkpoint. Extend as the chain grows.
    g_params.checkpoints = {
        { 50,  "006d9f7261e2f9aa0aa89b9881ff43c4a3e9f754d965b2af35c0be64835f713c" },
        { 100, "000c638c596be4ba014d329a362347a4de2bc5bde340985378e5691d1e6c0d20" },
    };
}

void select_regtest() {
    g_params.name = "regtest";
    g_params.magic = 0x43485254;   // "CHRT"
    g_params.default_port = 19333;
    g_params.genesis_target = target_top(31, 0x0F); // ~2^252, ~16 hashes/block (fast)
    g_params.genesis_time = 1735689600ULL;
    g_params.coinbase_maturity = 10;
    g_params.block_time = 60;
    g_params.retarget_window = 12;
    g_params.mtp_window = 11;
    g_params.future_drift = 2 * 60 * 60;
    g_params.checkpoints.clear();   // never checkpoint the throwaway regtest chain
}
