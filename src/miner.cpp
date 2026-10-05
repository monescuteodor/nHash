// CoreHash standalone miner. Talks to a node's RPC (getwork/submit) so you can mine
// without running a full node, and is the basis a mining pool builds on.
//
// Usage: corehash-miner <node_host:rpcport> <payout_address_hex> [threads]
//   The RPC port is the node's P2P port + 1 (RPC listens on 127.0.0.1 only, so run this
//   on the same machine as the node, or forward the port over SSH).
#include "block.h"
#include "corehash.h"
#include "net.h"
#include "miner.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdarg>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <sstream>

bool g_miner_quiet = false;

// ---- live dashboard stats ----
static std::atomic<uint64_t> g_m_hashes{0}, g_m_shares{0}, g_m_blocks{0};
static std::atomic<uint64_t> g_m_owed{0}, g_m_paid{0};
static std::atomic<int>      g_m_connected{0};

void miner_stats(uint64_t& hashes, uint64_t& shares, uint64_t& blocks,
                 uint64_t& owed, uint64_t& paid, int& connected) {
    hashes = g_m_hashes.load(); shares = g_m_shares.load(); blocks = g_m_blocks.load();
    owed = g_m_owed.load(); paid = g_m_paid.load(); connected = g_m_connected.load();
}
static void mlog(const char* fmt, ...) {
    if (g_miner_quiet) return;
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap); fflush(stdout);
}

static std::string to_hex(const std::vector<uint8_t>& b) {
    static const char* d = "0123456789abcdef"; std::string s; s.reserve(b.size() * 2);
    for (auto x : b) { s += d[x >> 4]; s += d[x & 15]; } return s;
}
static bool from_hex(const std::string& s, std::vector<uint8_t>& out) {
    if (s.size() % 2) return false; out.clear();
    auto nib = [](char c)->int { if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; };
    for (size_t i = 0; i < s.size(); i += 2) { int h = nib(s[i]), l = nib(s[i+1]); if (h<0||l<0) return false; out.push_back((uint8_t)((h<<4)|l)); }
    return true;
}
static uint256 target_from_hex(const std::string& h) { // big-endian hex (uint256::hex form)
    uint256 t; std::vector<uint8_t> b;
    if (!from_hex(h, b) || b.size() != 32) return t;
    for (int i = 0; i < 32; i++) t.b[31 - i] = b[i];
    return t;
}
static bool rpc_call(sock_t s, const std::string& req, std::string& resp) {
    std::vector<uint8_t> out(req.begin(), req.end());
    if (!net::send_msg(s, 1, out)) return false;
    uint8_t type; std::vector<uint8_t> pl;
    if (!net::recv_msg(s, type, pl)) return false;
    resp.assign((char*)pl.data(), pl.size());
    return true;
}
// Ask the pool for this miner's pending/paid earnings ("stats <addr>"). A plain node
// answers "ERR unknown command", which we simply ignore.
static void poll_earnings(sock_t s, const std::string& addr) {
    std::string resp;
    if (!rpc_call(s, "stats " + addr, resp)) return;
    if (resp.rfind("OK ", 0) != 0) return;
    std::istringstream is(resp.substr(3));
    uint64_t round = 0, owed = 0, paid = 0; is >> round >> owed >> paid;
    g_m_owed.store(owed); g_m_paid.store(paid);
}

int run_miner(const std::string& host, uint16_t port, const std::string& addr, int threads) {
    if (threads < 1) threads = 1;
    setvbuf(stdout, nullptr, _IONBF, 0); // unbuffered so progress shows live
    net::init();
    mlog("CoreHash miner: %s:%u, %d threads, payout %s\n", host.c_str(), port, threads, addr.c_str());

    while (true) {
        sock_t s = net::connect_to(host, port);
        if (s == CH_BADSOCK) { g_m_connected.store(0); mlog("cannot reach pool/node, retrying...\n"); std::this_thread::sleep_for(std::chrono::seconds(2)); continue; }
        g_m_connected.store(1);

        while (true) {
            poll_earnings(s, addr);
            std::string resp;
            if (!rpc_call(s, "getwork " + addr, resp)) break;
            if (resp.rfind("OK ", 0) != 0) { mlog("getwork: %s\n", resp.c_str()); std::this_thread::sleep_for(std::chrono::seconds(1)); continue; }
            std::string rest = resp.substr(3);
            auto sp = rest.find(' ');
            uint256 target = target_from_hex(rest.substr(0, sp));
            std::vector<uint8_t> blk;
            if (!from_hex(rest.substr(sp + 1), blk)) { mlog("bad block hex\n"); break; }
            Block b;
            try { Reader r(blk.data(), blk.size()); b = read_block(r); } catch (...) { mlog("parse fail\n"); break; }

            std::atomic<bool> stop{false};
            std::atomic<uint64_t> sol{0}; std::atomic<bool> got{false};
            std::atomic<uint64_t> hashes{0};
            std::vector<std::thread> pool;
            for (int t = 0; t < threads; t++) {
                pool.emplace_back([&, t]() {
                    ch::CoreHashCtx ctx; BlockHeader hdr = b.header; uint64_t n = t; uint64_t local = 0;
                    while (!stop.load(std::memory_order_relaxed)) {
                        hdr.nonce = n;
                        if (hdr.pow_hash(ctx) <= target) { sol.store(n); got.store(true); stop.store(true); break; }
                        n += threads; if ((++local & 15) == 0) { hashes.fetch_add(16, std::memory_order_relaxed); g_m_hashes.fetch_add(16, std::memory_order_relaxed); }
                    }
                });
            }
            // Mine for up to ~10s, then refresh work (the tip may have advanced).
            auto t0 = std::chrono::steady_clock::now();
            while (!got.load() && std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count() < 10.0)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            stop.store(true);
            for (auto& th : pool) th.join();

            if (got.load()) {
                b.header.nonce = sol.load();
                Writer bw; b.serialize(bw);
                std::string sr;
                if (!rpc_call(s, "submit " + to_hex(bw.data), sr)) break;
                if (sr.rfind("OK", 0) == 0) {
                    // A pool answers "OK share" / "OK block"; a solo node answers "OK <height>".
                    if (sr.find("block") != std::string::npos || sr.find("share") == std::string::npos) {
                        g_m_blocks.fetch_add(1);
                        mlog("block FOUND & accepted (%s) | blocks: %llu\n", sr.c_str(), (unsigned long long)g_m_blocks.load());
                    } else {
                        g_m_shares.fetch_add(1);
                        mlog("share accepted (%s) | shares: %llu\n", sr.c_str(), (unsigned long long)g_m_shares.load());
                    }
                }
                else mlog("submit rejected: %s\n", sr.c_str());
            }
        }
        net::close_sock(s);
        g_m_connected.store(0);
        mlog("disconnected, reconnecting...\n");
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
    return 0;
}
