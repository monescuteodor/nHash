// Standalone node daemon entry point.
// Usage: corehashd <listen_port> [peer_host:port,...|-] [mine_wallet] [threads]
#include "node.h"
#include "params.h"
#include <cstdio>
#include <cstdlib>
#include <string>

int main(int argc, char** argv) {
    if (argc < 2) { printf("usage: corehashd <listen_port> [peer_host:port,...|-] [mine_wallet] [threads]\n"); return 1; }
    // Network selection: mainnet by default; COREHASH_NET=regtest gives an isolated network
    // (different magic, easy genesis, no seeds) for local multi-node tests.
    const char* netsel = std::getenv("COREHASH_NET");
    if (netsel && std::string(netsel) == "regtest") select_regtest(); else select_mainnet();
    uint16_t port = (uint16_t)atoi(argv[1]);
    std::string peers  = (argc >= 3) ? argv[2] : "-";
    std::string wallet = (argc >= 4) ? argv[3] : "";
    int threads = (argc >= 5) ? atoi(argv[4]) : 1;
    const char* env = std::getenv("COREHASH_PASS");
    std::string pw = env ? std::string(env) : "";
    return run_node(port, peers, wallet, pw, threads);
}
