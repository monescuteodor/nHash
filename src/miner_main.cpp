// Standalone miner entry point.
// Usage: corehash-miner <host:rpcport> <payout_address_hex> [threads]
#include "miner.h"
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>

int main(int argc, char** argv) {
    if (argc < 3) { printf("usage: corehash-miner <host:rpcport> <payout_address_hex> [threads]\n"); return 1; }
    std::string hp = argv[1]; auto pos = hp.rfind(':');
    std::string host = hp.substr(0, pos);
    uint16_t port = (uint16_t)atoi(hp.substr(pos + 1).c_str());
    std::string addr = argv[2];
    int threads = (argc >= 4) ? atoi(argv[3]) : (int)std::thread::hardware_concurrency();
    return run_miner(host, port, addr, threads);
}
