// CoreHash mining pool. Sits between miners and a node: hands miners an easier
// "share" target, counts shares, relays real blocks to the node, credits each miner
// proportionally, and pays out on-chain via the node's sendtx RPC.
//
// Usage: corehash-pool <node_host:rpcport> <pool_wallet> <pool_listen_port> [share_shift]
//   Miners connect to <pool_listen_port> with the normal `corehash-miner` (getwork/submit).
//   Set $COREHASH_PASS if the pool wallet is encrypted.
#include "block.h"
#include "blockchain.h"   // consensus::min_relay_fee (inline relay-fee policy)
#include "corehash.h"
#include "net.h"
#include "wallet.h"
#include "params.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <sstream>
#include <thread>
#include <mutex>
#include <chrono>

static const uint64_t COIN = 100000000ULL;
static const uint64_t FEE_CEIL = COIN / 50;   // fee ceiling reserved while gathering inputs;
                                              // the actual fee is sized to the tx's bytes (see
                                              // consensus::min_relay_fee) and the rest returns
                                              // to the pool wallet as change.
static const uint64_t MIN_PAYOUT = COIN / 10; // pay out once ~0.1 coin is owed (fractions)

// ---- hex ----
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
static uint256 u256_from_hex_be(const std::string& h) {
    uint256 t; std::vector<uint8_t> b; if (!from_hex(h, b) || b.size() != 32) return t;
    for (int i = 0; i < 32; i++) t.b[31 - i] = b[i]; return t;
}
static uint256 shl_capped(const uint256& t, int bits, const uint256& cap) {
    int bs = bits / 8, br = bits % 8; uint256 r{};
    for (int i = 31; i >= 0; --i) { int src = i - bs; if (src >= 0) r.b[i] = t.b[src]; }
    if (br) { uint16_t carry = 0; for (int i = 0; i < 32; i++) { uint16_t v = ((uint16_t)r.b[i] << br) | carry; r.b[i] = (uint8_t)v; carry = v >> 8; } }
    bool overflow = false; for (int i = 32 - bs; i < 32; i++) if (i >= 0 && t.b[i]) overflow = true;
    if (overflow || cap < r) return cap; // never easier than difficulty-1
    return r;
}

// ---- node RPC connection ----
static std::string g_node_host; static uint16_t g_node_port;
static sock_t g_node = CH_BADSOCK; static std::mutex g_node_mtx;
static bool node_call(const std::string& req, std::string& resp) {
    std::lock_guard<std::mutex> lk(g_node_mtx);
    if (g_node == CH_BADSOCK) { g_node = net::connect_to(g_node_host, g_node_port); if (g_node == CH_BADSOCK) return false; }
    std::vector<uint8_t> out(req.begin(), req.end()); uint8_t type; std::vector<uint8_t> pl;
    if (!net::send_msg(g_node, 1, out) || !net::recv_msg(g_node, type, pl)) { net::close_sock(g_node); g_node = CH_BADSOCK; return false; }
    resp.assign((char*)pl.data(), pl.size()); return true;
}

// ---- job + accounting ----
static std::mutex g_job_mtx;
static std::string g_block_hex; static uint256 g_net_target, g_share_target; static uint64_t g_block_reward = 0;
static int g_shift = 12;
static Wallet g_pool_wallet; static std::string g_pool_addr_hex;

static std::mutex g_acct_mtx;
static std::map<std::string, uint64_t> g_shares; // addr_hex -> shares this round
static std::map<std::string, uint64_t> g_owed;   // addr_hex -> owed base units (pending)
static std::map<std::string, uint64_t> g_paid;   // addr_hex -> total paid out on-chain
static uint64_t g_blocks_found = 0;              // blocks the pool relayed to the network

static void log_line(const std::string& s) {
    time_t t = time(nullptr); struct tm tmv; char ts[32];
#ifdef _WIN32
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);          // thread-safe (pool handles each miner in its own thread)
#endif
    strftime(ts, sizeof(ts), "%H:%M:%S", &tmv);
    printf("[%s] %s\n", ts, s.c_str()); fflush(stdout);
}

static bool refresh_job() {
    std::string resp; if (!node_call("getwork " + g_pool_addr_hex, resp)) return false;
    if (resp.rfind("OK ", 0) != 0) return false;
    std::string rest = resp.substr(3); auto sp = rest.find(' ');
    uint256 nt = u256_from_hex_be(rest.substr(0, sp));
    std::string bhex = rest.substr(sp + 1);
    uint256 st = shl_capped(nt, g_shift, g_params.genesis_target);
    uint64_t reward = 0;
    std::vector<uint8_t> bb; if (from_hex(bhex, bb)) { try { Reader r(bb.data(), bb.size()); Block b = read_block(r); for (auto& o : b.txs[0].vout) reward += o.amount; } catch (...) {} }
    std::lock_guard<std::mutex> lk(g_job_mtx);
    g_net_target = nt; g_share_target = st; g_block_hex = bhex; g_block_reward = reward;
    return true;
}

// Split a solved block's reward across this round's shares, then reset the round.
static void allocate_block(uint64_t reward) {
    std::lock_guard<std::mutex> lk(g_acct_mtx);
    g_blocks_found++;
    uint64_t total = 0; for (auto& kv : g_shares) total += kv.second;
    if (total == 0) return;
    for (auto& kv : g_shares) g_owed[kv.first] += reward / total * kv.second + (reward % total) * kv.second / total;
    g_shares.clear();
}

static void handle_miner(sock_t c) {
    std::string conn_addr; uint8_t type; std::vector<uint8_t> pl;
    ch::CoreHashCtx ctx;
    while (net::recv_msg(c, type, pl)) {
        std::string req((char*)pl.data(), pl.size());
        auto sp = req.find(' ');
        std::string cmd = sp == std::string::npos ? req : req.substr(0, sp);
        std::string arg = sp == std::string::npos ? "" : req.substr(sp + 1);
        std::string resp;
        if (cmd == "getwork") {
            conn_addr = arg;
            std::lock_guard<std::mutex> lk(g_job_mtx);
            resp = "OK " + g_share_target.hex() + " " + g_block_hex;
        } else if (cmd == "stats") {
            // "stats <addr>" -> "OK <shares_this_round> <owed> <paid>" for the dashboard.
            std::lock_guard<std::mutex> lk(g_acct_mtx);
            uint64_t sh = g_shares.count(arg) ? g_shares[arg] : 0;
            uint64_t ow = g_owed.count(arg) ? g_owed[arg] : 0;
            uint64_t pd = g_paid.count(arg) ? g_paid[arg] : 0;
            resp = "OK " + std::to_string(sh) + " " + std::to_string(ow) + " " + std::to_string(pd);
        } else if (cmd == "poolstats") {
            // aggregate pool status as JSON, for the web explorer.
            std::lock_guard<std::mutex> lk(g_acct_mtx);
            std::set<std::string> addrs;
            for (auto& kv : g_shares) addrs.insert(kv.first);
            for (auto& kv : g_owed) addrs.insert(kv.first);
            for (auto& kv : g_paid) addrs.insert(kv.first);
            uint64_t round = 0, tot_owed = 0, tot_paid = 0;
            std::string miners = "["; bool first = true;
            for (const auto& a : addrs) {
                uint64_t sh = g_shares.count(a) ? g_shares[a] : 0;
                uint64_t ow = g_owed.count(a) ? g_owed[a] : 0;
                uint64_t pd = g_paid.count(a) ? g_paid[a] : 0;
                round += sh; tot_owed += ow; tot_paid += pd;
                if (!first) miners += ","; first = false;
                miners += "{\"addr\":\"" + a + "\",\"shares\":" + std::to_string(sh) +
                          ",\"owed\":" + std::to_string(ow) + ",\"paid\":" + std::to_string(pd) + "}";
            }
            miners += "]";
            resp = "{\"blocks_found\":" + std::to_string(g_blocks_found) +
                   ",\"round_shares\":" + std::to_string(round) +
                   ",\"miners_count\":" + std::to_string(addrs.size()) +
                   ",\"total_owed\":" + std::to_string(tot_owed) +
                   ",\"total_paid\":" + std::to_string(tot_paid) +
                   ",\"miners\":" + miners + "}";
        } else if (cmd == "submit") {
            std::vector<uint8_t> bytes; Block b; bool parsed = from_hex(arg, bytes);
            if (parsed) { try { Reader r(bytes.data(), bytes.size()); b = read_block(r); } catch (...) { parsed = false; } }
            if (!parsed) { resp = "ERR parse"; }
            else {
                uint256 pow = b.header.pow_hash(ctx);
                uint256 st, nt; uint64_t reward;
                { std::lock_guard<std::mutex> lk(g_job_mtx); st = g_share_target; nt = g_net_target; reward = g_block_reward; }
                if (!(pow <= st)) resp = "ERR high share";
                else {
                    { std::lock_guard<std::mutex> lk(g_acct_mtx); g_shares[conn_addr]++; }
                    if (pow <= nt) { // a real network block!
                        std::string sr; bool ok = node_call("submit " + arg, sr) && sr.rfind("OK", 0) == 0;
                        if (ok) { log_line("BLOCK found by " + conn_addr.substr(0,12) + "... -> node " + sr); allocate_block(reward); refresh_job(); resp = "OK block"; }
                        else resp = "OK share (relay failed: " + sr + ")";
                    } else resp = "OK share";
                }
            }
        } else resp = "ERR unknown";
        std::vector<uint8_t> out(resp.begin(), resp.end());
        if (!net::send_msg(c, 1, out)) break;
    }
    net::close_sock(c);
}

// Periodically push new jobs (tip may have advanced) and report share stats.
static void job_refresh_thread() {
    while (true) {
        refresh_job();
        std::lock_guard<std::mutex> lk(g_acct_mtx);
        uint64_t tot = 0; for (auto& kv : g_shares) tot += kv.second;
        if (tot) log_line("round shares: " + std::to_string(tot) + " from " + std::to_string(g_shares.size()) + " miner(s)");
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

// Pay owed miners from the pool's mature UTXOs (one batched transaction).
static void payout_thread() {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        // Who is owed enough?
        std::vector<std::pair<std::string, uint64_t>> pay;
        { std::lock_guard<std::mutex> lk(g_acct_mtx);
          for (auto& kv : g_owed) if (kv.second >= MIN_PAYOUT) pay.push_back(kv); }
        if (pay.empty()) continue;

        std::string resp; if (!node_call("getutxos " + g_pool_addr_hex, resp) || resp.rfind("OK ", 0) != 0) continue;
        std::istringstream is(resp.substr(3)); uint64_t tip = 0, n = 0; is >> tip >> n;
        uint64_t next_h = tip + 1;
        std::vector<std::pair<OutPoint, uint64_t>> mature; uint64_t avail = 0;
        for (uint64_t i = 0; i < n; i++) {
            std::string item; if (!(is >> item)) break;
            // txid:index:amount:height:cb
            std::vector<std::string> f; size_t p = 0; for (int k = 0; k < 4; k++) { auto q = item.find(':', p); f.push_back(item.substr(p, q - p)); p = q + 1; } f.push_back(item.substr(p));
            OutPoint op; op.txid = u256_from_hex_be(f[0]); op.index = (uint32_t)strtoul(f[1].c_str(), nullptr, 10);
            uint64_t amount = strtoull(f[2].c_str(), nullptr, 10); uint64_t h = strtoull(f[3].c_str(), nullptr, 10); bool cb = f[4] == "1";
            if (cb && next_h < h + g_params.coinbase_maturity) continue; // immature
            mature.push_back({ op, amount }); avail += amount;
        }
        uint64_t payout_sum = 0; for (auto& pr : pay) payout_sum += pr.second;
        uint64_t need = payout_sum + FEE_CEIL;   // reserve a generous ceiling; the real fee is smaller
        if (avail < need) { log_line("payout deferred: mature funds " + std::to_string(avail / COIN) + " < needed " + std::to_string(need / COIN)); continue; }

        Transaction tx; uint64_t gathered = 0;
        for (auto& m : mature) { TxIn in; in.prev = m.first; tx.vin.push_back(in); gathered += m.second; if (gathered >= need) break; }
        for (auto& pr : pay) { std::vector<uint8_t> a; from_hex(pr.first, a); if (a.size() == 32) tx.vout.push_back(TxOut{ pr.second, a }); }
        // Change output (placeholder). Its amount is a fixed-width field, so setting the exact
        // value below does not change the serialized size — meaning the fee we size to that size
        // stays correct after the adjustment. We sign once to measure the real (signed) size,
        // size the fee to it, set the change, then re-sign the final outputs.
        size_t chg = tx.vout.size();
        tx.vout.push_back(TxOut{ gathered - need, g_pool_wallet.address() });
        sign_tx(tx, g_pool_wallet);
        uint64_t fee, change;
        { Writer wm; tx.serialize(wm);
          fee = consensus::min_relay_fee(wm.data.size());
          if (gathered < payout_sum + fee) { log_line("payout deferred: gathered < payouts + fee"); continue; }
          change = gathered - payout_sum - fee; }
        if (change == 0) { tx.vout.erase(tx.vout.begin() + chg); } else { tx.vout[chg].amount = change; }
        sign_tx(tx, g_pool_wallet);   // re-sign: outputs changed
        Writer w; tx.serialize(w);
        std::string sr; if (node_call("sendtx " + to_hex(w.data), sr) && sr.rfind("OK", 0) == 0) {
            std::lock_guard<std::mutex> lk(g_acct_mtx);
            for (auto& pr : pay) { g_owed[pr.first] -= pr.second; g_paid[pr.first] += pr.second; }
            log_line("paid " + std::to_string(pay.size()) + " miner(s), tx " + sr.substr(3, 16));
        } else log_line("payout sendtx failed: " + sr);
    }
}

int main(int argc, char** argv) {
    if (argc < 4) { printf("usage: corehash-pool <node_host:rpcport> <pool_wallet> <pool_port> [share_shift]\n"); return 1; }
    select_mainnet();
    std::string hp = argv[1]; auto pos = hp.rfind(':');
    g_node_host = hp.substr(0, pos); g_node_port = (uint16_t)atoi(hp.substr(pos + 1).c_str());
    std::string walletname = argv[2];
    uint16_t pool_port = (uint16_t)atoi(argv[3]);
    if (argc >= 5) g_shift = atoi(argv[4]);
    setvbuf(stdout, nullptr, _IONBF, 0);
    net::init();

    const char* env = std::getenv("COREHASH_PASS"); std::string pw = env ? env : "";
    uint8_t seed[32];
    if (!wallet_read_seed(walletname + ".wallet", pw, seed)) { printf("cannot open pool wallet '%s' (set COREHASH_PASS if encrypted)\n", walletname.c_str()); return 1; }
    g_pool_wallet = Wallet::from_seed(seed);
    g_pool_addr_hex = to_hex(g_pool_wallet.address());
    log_line("pool wallet " + g_pool_addr_hex);

    if (!refresh_job()) { printf("cannot reach node RPC at %s:%u\n", g_node_host.c_str(), g_node_port); return 1; }
    log_line("connected to node, share_shift=" + std::to_string(g_shift));

    std::thread(job_refresh_thread).detach();
    std::thread(payout_thread).detach();

    sock_t ls = net::listen_on(pool_port);
    if (ls == CH_BADSOCK) { printf("cannot listen on pool port %u\n", pool_port); return 1; }
    log_line("pool listening for miners on port " + std::to_string(pool_port));
    while (true) { std::string ip; sock_t c = net::accept_one(ls, ip); if (c == CH_BADSOCK) break; log_line("miner connected from " + ip); std::thread(handle_miner, c).detach(); }
    return 0;
}
