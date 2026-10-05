// CoreHash P2P node daemon. Listens for peers, discovers more peers automatically,
// syncs the chain, relays blocks/txs, and optionally mines. Shares chain.dat /
// mempool.dat / peers.dat / <wallet>.wallet with the CLI.
//
// Usage: corehashd <listen_port> [peer_host:port,...|-] [mine_wallet]
//
// Protocol messages (framed by net.h):
//   HELLO(1):     magic u32, version u32, listen_port u16, node_nonce u64, height u64, genesis h256
//   GETBLOCKS(2): u64 start_height  -> peer streams BLOCK for start..tip
//   BLOCK(3):     serialized Block
//   TX(4):        serialized Transaction
//   GETADDR(5):   (empty) -> peer replies with ADDR
//   ADDR(6):      varint count, then {string ip, u16 port} each  (known dialable peers)
#include "blockchain.h"
#include "wallet.h"
#include "storage.h"
#include "net.h"
#include "params.h"
#include "node.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <memory>
#include <atomic>
#include <chrono>
#include <ctime>
#include <fstream>
#include <set>
#include <map>
#include <random>
#include <cstdlib>

enum { HELLO = 1, GETBLOCKS = 2, BLOCK = 3, TX = 4, GETADDR = 5, ADDR = 6 };
static const uint32_t PROTO_VERSION = 1;
static const std::string CHAIN = "chain.dat", MEMP = "mempool.dat", PEERS = "peers.dat";
static const size_t TARGET_OUTBOUND = 8;   // desired peer connections
static const size_t MAX_ADDRS = 2000;      // cap on the known-address set

static ChainState        g_chain;
static Mempool           g_mempool;
static std::mutex        g_mtx;          // guards g_chain and g_mempool
static ch::CoreHashCtx   g_verify_ctx;   // used only under g_mtx

static uint16_t          g_listen_port = 0;
static uint64_t          g_node_nonce = 0;

struct Peer {
    sock_t s; std::mutex send_mtx; std::string ip; std::string advertised;
    // Per-peer message-frequency limiter (token bucket). Touched only by this peer's own
    // handler thread, so it needs no lock. Lazily initialised on the first message.
    double rl_tokens = -1.0; std::chrono::steady_clock::time_point rl_last{};
    // Flow-controlled sync state (also handler-thread-only): the peer's advertised height
    // and the highest height we have requested so far, so we pull the chain in batches.
    uint64_t their_height = 0; uint64_t sync_target = 0;
    std::string dialed;   // for outbound connections: the address we dialed (used to detect self)
};
static std::vector<std::shared_ptr<Peer>> g_peers;
static std::mutex g_peers_mtx;

// Address manager: known dialable "ip:port", currently-connected set, retry cooldowns.
static std::set<std::string>            g_known;
static std::set<std::string>            g_self;      // our own addresses (found via self-connection): never dial these
static std::set<std::string>            g_connected;
static std::map<std::string, int64_t>   g_cooldown; // addr -> earliest next dial time
static std::mutex g_addr_mtx;

static std::atomic<bool> g_running{true};

static std::atomic<uint64_t> g_hashes{0};       // cumulative hashes by our miner threads
static std::atomic<uint64_t> g_blocks_mined{0}; // blocks this node has mined
static int64_t g_start_time = 0;                // node start (unix seconds), for uptime
bool g_quiet = false;                            // when true, suppress routine logs (dashboard mode)

static const size_t  MAX_PEERS   = 64;   // cap on simultaneous connections
static const int64_t BAN_SECONDS = 3600; // ban duration for misbehaving peers
static const int     BAN_THRESHOLD = 100; // ban once a peer's misbehavior score reaches this
static std::map<std::string, int64_t> g_banned;   // ip -> unban time
static std::map<std::string, int>     g_banscore; // ip -> accumulated misbehavior points
static std::mutex g_ban_mtx;

// Per-peer message-rate limit. Legitimate traffic is far below this even during a burst
// sync (each message costs real processing time, which self-throttles the stream); the
// limit exists to stop a tight flood of cheap messages (e.g. GETADDR/GETBLOCKS spam).
static const double RL_BURST  = 512.0; // tokens (messages) a peer may burst
static const double RL_REFILL = 128.0; // sustained messages/sec before it is treated as a flood

// Max blocks served (and pulled) per GETBLOCKS, so one request can never force serializing
// the whole chain under the lock. Override with COREHASH_SYNC_BATCH (used by tests).
static uint64_t sync_batch() {
    static uint64_t v = []() {
        const char* e = std::getenv("COREHASH_SYNC_BATCH");
        uint64_t x = e ? strtoull(e, nullptr, 10) : 0;
        return (x >= 1 && x <= 100000) ? x : 500ULL;
    }();
    return v;
}

// Token-bucket check: returns false when the peer has exceeded its message budget.
static bool rate_ok(const std::shared_ptr<Peer>& p) {
    auto now = std::chrono::steady_clock::now();
    if (p->rl_tokens < 0.0) { p->rl_last = now; p->rl_tokens = RL_BURST; } // first message
    double dt = std::chrono::duration<double>(now - p->rl_last).count();
    p->rl_last = now;
    p->rl_tokens += dt * RL_REFILL;
    if (p->rl_tokens > RL_BURST) p->rl_tokens = RL_BURST;
    if (p->rl_tokens < 1.0) return false;
    p->rl_tokens -= 1.0;
    return true;
}

static void log_line(const std::string& s) {
    if (g_quiet) return; // dashboard mode: the caller renders its own live panel
    time_t t = time(nullptr); struct tm tmv; char ts[32];
#ifdef _WIN32
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);          // thread-safe: plain localtime() races across threads
#endif
    strftime(ts, sizeof(ts), "%H:%M:%S", &tmv);
    printf("[%s] %s\n", ts, s.c_str()); fflush(stdout);
}

// ---- address persistence ----
static void save_peers() {
    std::lock_guard<std::mutex> lk(g_addr_mtx);
    std::ofstream f(PEERS, std::ios::trunc);
    for (const auto& a : g_known) f << a << "\n";
}
static void load_peers() {
    std::ifstream f(PEERS);
    std::string line;
    std::lock_guard<std::mutex> lk(g_addr_mtx);
    while (std::getline(f, line)) if (line.find(':') != std::string::npos) g_known.insert(line);
}
static void add_known(const std::string& addr) {
    if (addr.empty() || addr.find(':') == std::string::npos) return;
    std::lock_guard<std::mutex> lk(g_addr_mtx);
    if (g_self.count(addr)) return;                 // never re-add one of our own addresses
    if (g_known.size() < MAX_ADDRS) g_known.insert(addr);
}

static bool is_banned(const std::string& ip) {
    std::lock_guard<std::mutex> lk(g_ban_mtx);
    auto it = g_banned.find(ip);
    return it != g_banned.end() && it->second > (int64_t)time(nullptr);
}
static void ban_peer(const std::string& ip, const std::string& why) {
    if (ip.empty()) return;
    { std::lock_guard<std::mutex> lk(g_ban_mtx); g_banned[ip] = (int64_t)time(nullptr) + BAN_SECONDS; g_banscore.erase(ip); }
    log_line("banned " + ip + " (" + why + ")");
}
// Accumulate a misbehavior score for a peer and ban it only once the score crosses the
// threshold. Minor faults (a flood trip, one corrupted frame) cost less than a full ban, so a
// single hiccup on a flaky link no longer earns an hour-long ban; repeated abuse still does.
static void misbehave(const std::string& ip, int points, const std::string& why) {
    if (ip.empty()) return;
    int total;
    { std::lock_guard<std::mutex> lk(g_ban_mtx); total = (g_banscore[ip] += points); }
    if (total >= BAN_THRESHOLD) ban_peer(ip, why + ", score " + std::to_string(total));
    else log_line("misbehaving " + ip + " +" + std::to_string(points) + " (" + why
                  + ", score " + std::to_string(total) + "/" + std::to_string(BAN_THRESHOLD) + ")");
}

// ---- messaging ----
static void send_to(std::shared_ptr<Peer> p, uint8_t type, const std::vector<uint8_t>& pl) {
    std::lock_guard<std::mutex> lk(p->send_mtx);
    net::send_msg(p->s, type, pl);
}
static void broadcast(uint8_t type, const std::vector<uint8_t>& pl, Peer* except) {
    std::vector<std::shared_ptr<Peer>> snapshot;
    { std::lock_guard<std::mutex> lk(g_peers_mtx); snapshot = g_peers; }
    for (auto& p : snapshot) if (p.get() != except) send_to(p, type, pl);
}

static std::vector<uint8_t> hello_payload() {
    Writer w;
    w.u32(g_params.magic); w.u32(PROTO_VERSION); w.u16(g_listen_port); w.u64(g_node_nonce);
    std::lock_guard<std::mutex> lk(g_mtx);
    w.u64(g_chain.height()); w.h256(g_chain.hashes[0]);
    return w.data;
}
static std::vector<uint8_t> addr_payload() {
    std::vector<std::string> addrs;
    { std::lock_guard<std::mutex> lk(g_addr_mtx); for (const auto& a : g_known) { addrs.push_back(a); if (addrs.size() >= 50) break; } }
    Writer w; w.varint(addrs.size());
    for (const auto& a : addrs) {
        auto pos = a.rfind(':');
        std::string ip = a.substr(0, pos); uint16_t port = (uint16_t)atoi(a.substr(pos + 1).c_str());
        std::vector<uint8_t> ipb(ip.begin(), ip.end());
        w.bytes(ipb); w.u16(port);
    }
    return w.data;
}

static void remove_peer(std::shared_ptr<Peer> peer) {
    { std::lock_guard<std::mutex> lk(g_peers_mtx);
      for (size_t i = 0; i < g_peers.size(); i++) if (g_peers[i].get() == peer.get()) { g_peers.erase(g_peers.begin() + i); break; } }
    if (!peer->advertised.empty()) {
        std::lock_guard<std::mutex> lk(g_addr_mtx);
        g_connected.erase(peer->advertised);
        g_cooldown[peer->advertised] = (int64_t)time(nullptr) + 30; // brief backoff
    }
}

static void handle_peer(std::shared_ptr<Peer> peer) {
    send_to(peer, HELLO, hello_payload());
    uint8_t type; std::vector<uint8_t> pl;
    while (g_running && net::recv_msg(peer->s, type, pl)) {
        // Frequency limit applies to cheap control messages that can be flooded or
        // amplified (GETBLOCKS/GETADDR/HELLO/ADDR). BLOCK and TX are self-throttling —
        // each costs a full PoW/signature validation and an invalid one is banned
        // outright — so they are exempt to avoid false-banning a long bulk sync.
        if (type != BLOCK && type != TX && !rate_ok(peer)) { misbehave(peer->ip, 50, "message flood"); break; }
        try {
            if (type == HELLO) {
                Reader r(pl.data(), pl.size());
                uint32_t their_magic = r.u32(); r.u32();
                uint16_t their_port = r.u16(); uint64_t their_nonce = r.u64();
                uint64_t their_h = r.u64(); uint256 their_gen = r.h256();
                if (their_magic != g_params.magic) { ban_peer(peer->ip, "wrong network magic"); break; }
                if (their_nonce == g_node_nonce) {
                    // We dialed ourselves (baked-in seed == our own address, or gossiped self).
                    // Remember it so auto-connect stops retrying it every cycle.
                    if (!peer->dialed.empty()) {
                        { std::lock_guard<std::mutex> lk(g_addr_mtx);
                          g_self.insert(peer->dialed); g_known.erase(peer->dialed); g_cooldown.erase(peer->dialed); }
                        save_peers();
                    }
                    log_line("self-connection -> drop"); break;
                }
                uint64_t our_h; uint256 our_gen;
                { std::lock_guard<std::mutex> lk(g_mtx); our_h = g_chain.height(); our_gen = g_chain.hashes[0]; }
                if (their_gen != our_gen) { log_line("genesis mismatch -> drop"); break; }
                // Record a dialable address for this peer (its listen port + our view of its IP).
                if (their_port != 0 && !peer->ip.empty()) {
                    peer->advertised = peer->ip + ":" + std::to_string(their_port);
                    add_known(peer->advertised);
                    { std::lock_guard<std::mutex> lk(g_addr_mtx); g_connected.insert(peer->advertised); }
                    save_peers();
                }
                log_line("peer " + (peer->advertised.empty() ? peer->ip : peer->advertised) + " at height " + std::to_string(their_h));
                send_to(peer, GETADDR, {});
                peer->their_height = their_h;
                if (their_h > our_h) { Writer w; w.u64(our_h + 1); send_to(peer, GETBLOCKS, w.data);
                                       peer->sync_target = our_h + sync_batch(); }
            } else if (type == GETADDR) {
                send_to(peer, ADDR, addr_payload());
            } else if (type == ADDR) {
                Reader r(pl.data(), pl.size());
                uint64_t n = r.varint(); if (n > 500) n = 500;
                int added = 0;
                for (uint64_t i = 0; i < n; i++) {
                    auto ipb = r.bytes(); uint16_t port = r.u16();
                    std::string ip(ipb.begin(), ipb.end());
                    if (ip.empty() || port == 0) continue;
                    std::string a = ip + ":" + std::to_string(port);
                    { std::lock_guard<std::mutex> lk(g_addr_mtx); if (!g_known.count(a) && g_known.size() < MAX_ADDRS) { g_known.insert(a); added++; } }
                }
                if (added) { save_peers(); log_line("learned " + std::to_string(added) + " new peer address(es)"); }
            } else if (type == GETBLOCKS) {
                Reader r(pl.data(), pl.size());
                uint64_t start = r.u64();
                std::vector<std::vector<uint8_t>> out;
                { std::lock_guard<std::mutex> lk(g_mtx);
                  uint64_t tip = g_chain.height();
                  uint64_t last = start + sync_batch() - 1; if (last > tip) last = tip;   // cap: one batch, bounded lock hold
                  for (uint64_t h = start; h <= last; h++) { Writer w; g_chain.blocks[h].serialize(w); out.push_back(w.data); } }
                for (auto& b : out) send_to(peer, BLOCK, b);
            } else if (type == BLOCK) {
                Reader r(pl.data(), pl.size());
                Block b = read_block(r);
                bool ok; std::string err, tiphex; uint64_t newh = 0, oh = 0; bool orphan = false;
                { std::lock_guard<std::mutex> lk(g_mtx);
                  ok = g_chain.connect(b, g_verify_ctx, err); oh = g_chain.height();
                  if (ok) { newh = oh; tiphex = g_chain.tip_hash().hex().substr(0,16);
                            g_mempool.remove_confirmed(b.txs); save_chain(CHAIN, g_chain); save_mempool(MEMP, g_mempool); }
                  else if (err.find("orphan") != std::string::npos) orphan = true; }
                if (ok) { log_line("accepted block, tip now " + std::to_string(newh) + " " + tiphex);
                          broadcast(BLOCK, pl, peer.get());
                          // Flow control: once we've consumed the batch we asked for and are still
                          // behind this peer, request the next batch. One GETBLOCKS per batch.
                          if (peer->sync_target && newh >= peer->sync_target && newh < peer->their_height) {
                              Writer w; w.u64(newh + 1); send_to(peer, GETBLOCKS, w.data);
                              peer->sync_target = newh + sync_batch();
                          } }
                else if (orphan) { uint64_t start = oh > 25 ? oh - 25 : 1; Writer w; w.u64(start); send_to(peer, GETBLOCKS, w.data); }
                else if (err != "duplicate block") { misbehave(peer->ip, 100, "invalid block: " + err); break; }
            } else if (type == TX) {
                Reader r(pl.data(), pl.size());
                Transaction tx = read_transaction(r);
                bool ok; std::string terr;
                { std::lock_guard<std::mutex> lk(g_mtx);
                  ok = g_mempool.accept(tx, g_chain.utxo, g_chain.height() + 1, terr);
                  if (ok) save_mempool(MEMP, g_mempool); }
                if (ok) { log_line("relayed tx " + tx.txid().hex().substr(0,16)); broadcast(TX, pl, peer.get()); }
            }
        } catch (...) { misbehave(peer->ip, 50, "malformed message"); break; }
    }
    net::close_sock(peer->s);
    remove_peer(peer);
    log_line("peer disconnected");
}

static void listener_thread(uint16_t port) {
    sock_t ls = net::listen_on(port);
    if (ls == CH_BADSOCK) { log_line("FATAL: cannot listen on port " + std::to_string(port)); g_running = false; return; }
    log_line("listening on port " + std::to_string(port));
    while (g_running) {
        std::string ip; sock_t c = net::accept_one(ls, ip);
        if (c == CH_BADSOCK) break;
        size_t np; { std::lock_guard<std::mutex> lk(g_peers_mtx); np = g_peers.size(); }
        if (np >= MAX_PEERS || is_banned(ip)) { net::close_sock(c); continue; }
        auto p = std::make_shared<Peer>(); p->s = c; p->ip = ip;
        { std::lock_guard<std::mutex> lk(g_peers_mtx); g_peers.push_back(p); }
        log_line("inbound peer from " + ip);
        std::thread(handle_peer, p).detach();
    }
    net::close_sock(ls);
}

static void dial(const std::string& host, uint16_t port) {
    std::string addr = host + ":" + std::to_string(port);
    sock_t c = net::connect_to(host, port);
    if (c == CH_BADSOCK) { std::lock_guard<std::mutex> lk(g_addr_mtx); g_cooldown[addr] = (int64_t)time(nullptr) + 60; return; }
    auto p = std::make_shared<Peer>(); p->s = c; p->ip = host; p->dialed = addr;
    { std::lock_guard<std::mutex> lk(g_peers_mtx); g_peers.push_back(p); }
    log_line("connected to " + addr);
    handle_peer(p); // blocks until this peer disconnects
}

// Maintain up to TARGET_OUTBOUND connections by dialing known addresses.
static void auto_connect_thread() {
    while (g_running) {
        size_t npeers; { std::lock_guard<std::mutex> lk(g_peers_mtx); npeers = g_peers.size(); }
        if (npeers < TARGET_OUTBOUND) {
            std::string pick; int64_t now = (int64_t)time(nullptr);
            { std::lock_guard<std::mutex> lk(g_addr_mtx);
              for (const auto& a : g_known) {
                  if (g_connected.count(a)) continue;
                  if (g_self.count(a)) continue;                 // skip our own address
                  auto it = g_cooldown.find(a); if (it != g_cooldown.end() && it->second > now) continue;
                  pick = a; break;
              }
              if (!pick.empty()) { g_cooldown[pick] = now + 20; g_connected.insert(pick); } // reserve while dialing
            }
            if (!pick.empty()) {
                auto pos = pick.rfind(':');
                std::string host = pick.substr(0, pos); uint16_t port = (uint16_t)atoi(pick.substr(pos + 1).c_str());
                std::thread([host, port, pick]() {
                    dial(host, port);
                    std::lock_guard<std::mutex> lk(g_addr_mtx); g_connected.erase(pick); // free reservation on disconnect
                }).detach();
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }
}

static std::string hex32(const std::vector<uint8_t>& b) {
    static const char* d = "0123456789abcdef"; std::string s;
    for (auto x : b) { s += d[x >> 4]; s += d[x & 15]; } return s;
}
static void mining_thread(Wallet w, int id, int nthreads) {
    ch::CoreHashCtx ctx;
    if (id == 0) log_line("mining to address " + hex32(w.address()) + " with " + std::to_string(nthreads) + " thread(s)");
    while (g_running) {
        uint256 prev; uint32_t bits; uint64_t hgt, fees = 0; uint64_t last_ts;
        std::vector<Transaction> pooled;
        { std::lock_guard<std::mutex> lk(g_mtx);
          prev = g_chain.tip_hash(); hgt = g_chain.height() + 1; bits = g_chain.next_bits();
          pooled = g_mempool.select_for_block(g_chain.utxo, hgt,
                       consensus::MAX_BLOCK_SIZE - consensus::COINBASE_RESERVE, fees);
          last_ts = g_chain.tip().header.timestamp; }

        Block nb;
        nb.header.version = 1; nb.header.prev_hash = prev; nb.header.bits = bits;
        uint64_t now = (uint64_t)time(nullptr);
        nb.header.timestamp = now > last_ts ? now : last_ts + 1;
        nb.txs.push_back(make_coinbase(hgt, consensus::block_reward(hgt) + fees, w.address()));
        for (auto& t : pooled) nb.txs.push_back(t);
        nb.header.merkle_root = nb.compute_merkle_root();
        nb.header.nonce = (uint64_t)id;   // each thread walks a disjoint nonce lane

        uint256 target = bits_to_target(bits);
        bool found = false, stale = false;
        for (uint64_t i = 0; g_running; i++) {
            if (nb.header.pow_hash(ctx) <= target) { found = true; break; }
            nb.header.nonce += (uint64_t)nthreads;
            if ((i & 63) == 0) { g_hashes.fetch_add(64, std::memory_order_relaxed);
                std::lock_guard<std::mutex> lk(g_mtx); if (g_chain.tip_hash() != prev) { stale = true; break; } }
        }
        if (stale || !found) continue;

        std::string err; bool ok = false; uint64_t newh = 0;
        { std::lock_guard<std::mutex> lk(g_mtx);
          if (g_chain.tip_hash() == prev) { ok = g_chain.connect(nb, ctx, err);
            if (ok) { newh = g_chain.height(); g_mempool.remove_confirmed(nb.txs); save_chain(CHAIN, g_chain); save_mempool(MEMP, g_mempool); } } }
        if (ok) {
            g_blocks_mined.fetch_add(1, std::memory_order_relaxed);
            log_line("MINED block " + std::to_string(newh) + " " + nb.header.pow_hash(ctx).hex().substr(0,16)
                     + " (diff " + std::to_string(g_chain.difficulty_of(bits)) + ")");
            Writer bw; nb.serialize(bw); broadcast(BLOCK, bw.data, nullptr);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

// ============================ RPC (localhost) for external miners / pools ============================
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
// Build a fresh block template paying the coinbase to `addrhex` (32-byte pubkey hash).
static std::string rpc_getwork(const std::string& addrhex) {
    std::vector<uint8_t> addr;
    if (!from_hex(addrhex, addr) || addr.size() != 32) return "ERR bad address";
    Block nb; uint32_t bits;
    { std::lock_guard<std::mutex> lk(g_mtx);
      nb.header.version = 1; nb.header.prev_hash = g_chain.tip_hash();
      bits = g_chain.next_bits(); nb.header.bits = bits;
      uint64_t hgt = g_chain.height() + 1, last_ts = g_chain.tip().header.timestamp;
      uint64_t now = (uint64_t)time(nullptr); nb.header.timestamp = now > last_ts ? now : last_ts + 1;
      uint64_t fees = 0;
      auto pooled = g_mempool.select_for_block(g_chain.utxo, hgt,
                        consensus::MAX_BLOCK_SIZE - consensus::COINBASE_RESERVE, fees);
      nb.txs.push_back(make_coinbase(hgt, consensus::block_reward(hgt) + fees, addr));
      for (auto& t : pooled) nb.txs.push_back(t);
    }
    nb.header.merkle_root = nb.compute_merkle_root(); nb.header.nonce = 0;
    Writer w; nb.serialize(w);
    return "OK " + bits_to_target(bits).hex() + " " + to_hex(w.data);
}
static std::string rpc_submit(const std::string& blockhex) {
    std::vector<uint8_t> bytes; if (!from_hex(blockhex, bytes)) return "ERR bad hex";
    Block b;
    try { Reader r(bytes.data(), bytes.size()); b = read_block(r); } catch (...) { return "ERR parse"; }
    std::string err; bool ok = false; uint64_t h = 0;
    { std::lock_guard<std::mutex> lk(g_mtx);
      ok = g_chain.connect(b, g_verify_ctx, err);
      if (ok) { h = g_chain.height(); g_mempool.remove_confirmed(b.txs); save_chain(CHAIN, g_chain); save_mempool(MEMP, g_mempool); } }
    if (ok) { log_line("RPC submit accepted, tip now " + std::to_string(h)); broadcast(BLOCK, bytes, nullptr); return "OK " + std::to_string(h); }
    return "ERR " + err;
}
// Relay a transaction (hex) into the mempool + network. Used by pools for payouts.
static std::string rpc_sendtx(const std::string& txhex) {
    std::vector<uint8_t> bytes; if (!from_hex(txhex, bytes)) return "ERR bad hex";
    Transaction tx;
    try { Reader r(bytes.data(), bytes.size()); tx = read_transaction(r); } catch (...) { return "ERR parse"; }
    bool ok = false; std::string err;
    { std::lock_guard<std::mutex> lk(g_mtx);
      ok = g_mempool.accept(tx, g_chain.utxo, g_chain.height() + 1, err);
      if (ok) save_mempool(MEMP, g_mempool); }
    if (ok) { broadcast(TX, bytes, nullptr); return "OK " + tx.txid().hex(); }
    return "ERR " + err;
}
// List unspent outputs for an address: "OK <tipheight> <n> <txid:index:amount:height:cb> ...".
static std::string rpc_getutxos(const std::string& addrhex) {
    std::vector<uint8_t> addr; if (!from_hex(addrhex, addr) || addr.size() != 32) return "ERR bad address";
    std::lock_guard<std::mutex> lk(g_mtx);
    std::vector<std::string> items;
    for (const auto& kv : g_chain.utxo.map) {
        if (kv.second.pubkey_hash != addr) continue;
        items.push_back(kv.first.txid.hex() + ":" + std::to_string(kv.first.index) + ":" +
                        std::to_string(kv.second.amount) + ":" + std::to_string(kv.second.height) + ":" +
                        (kv.second.is_coinbase ? "1" : "0"));
    }
    std::string out = "OK " + std::to_string(g_chain.height()) + " " + std::to_string(items.size());
    for (const auto& s : items) out += " " + s;
    return out;
}
// Rich chain overview as JSON, for the web explorer.
static std::string rpc_chaininfo() {
    uint64_t height = 0, supply = 0, reward = 0, blocktime = g_params.block_time; double diff = 0, est = 0;
    std::string tip; size_t mempool = 0;
    { std::lock_guard<std::mutex> lk(g_mtx);
      height = g_chain.height();
      uint32_t bits = g_chain.next_bits();
      diff = g_chain.difficulty_of(bits);
      est = expected_hashes_per_block(bits) / (double)g_params.block_time;
      tip = g_chain.tip_hash().hex();
      for (const auto& kv : g_chain.utxo.map) supply += kv.second.amount;
      reward = consensus::block_reward(height + 1);
      mempool = g_mempool.txs.size();
    }
    int peers = 0; { std::lock_guard<std::mutex> lk(g_peers_mtx); peers = (int)g_peers.size(); }
    uint64_t uptime = g_start_time ? (uint64_t)((int64_t)time(nullptr) - g_start_time) : 0;
    char buf[820];
    snprintf(buf, sizeof(buf),
      "{\"height\":%llu,\"difficulty\":%.3f,\"net_hashrate\":%.2f,\"supply\":%llu,"
      "\"peers\":%d,\"block_time\":%llu,\"reward\":%llu,\"tip\":\"%s\","
      "\"version\":%u,\"net\":\"%s\",\"uptime\":%llu,\"mempool\":%zu}",
      (unsigned long long)height, diff, est, (unsigned long long)supply,
      peers, (unsigned long long)blocktime, (unsigned long long)reward, tip.c_str(),
      PROTO_VERSION, g_params.name, (unsigned long long)uptime, mempool);
    return buf;
}
// Last N block summaries as JSON, newest first.
static std::string rpc_recentblocks(const std::string& arg) {
    int n = atoi(arg.c_str()); if (n <= 0) n = 12; if (n > 50) n = 50;
    std::string out = "{\"blocks\":[";
    std::lock_guard<std::mutex> lk(g_mtx);
    uint64_t h = g_chain.height();
    uint64_t start = ((uint64_t)n <= h) ? (h - (uint64_t)n + 1) : 0;
    bool first = true;
    for (uint64_t i = h; ; --i) {
        const Block& b = g_chain.blocks[i];
        uint64_t reward = 0; if (!b.txs.empty()) for (const auto& o : b.txs[0].vout) reward += o.amount;
        std::string miner = (!b.txs.empty() && !b.txs[0].vout.empty()) ? to_hex(b.txs[0].vout[0].pubkey_hash) : "";
        double bdiff = g_chain.difficulty_of(b.header.bits);
        char buf[460];
        snprintf(buf, sizeof(buf),
          "%s{\"height\":%llu,\"hash\":\"%s\",\"time\":%llu,\"txs\":%zu,\"reward\":%llu,\"diff\":%.3f,\"miner\":\"%s\"}",
          first ? "" : ",", (unsigned long long)i, g_chain.hashes[i].hex().c_str(),
          (unsigned long long)b.header.timestamp, b.txs.size(), (unsigned long long)reward, bdiff, miner.c_str());
        out += buf; first = false;
        if (i == start) break;
    }
    out += "]}";
    return out;
}
// Parse a 64-char big-endian hex string into a uint256 (as displayed by .hex()).
static bool parse_hash256(const std::string& s, uint256& out) {
    if (s.size() != 64) return false;
    auto nib = [](char c)->int { if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; };
    uint256 h;
    for (int i = 0; i < 32; i++) {
        int hi = nib(s[2*i]), lo = nib(s[2*i+1]);
        if (hi < 0 || lo < 0) return false;
        h.b[31 - i] = (uint8_t)((hi << 4) | lo);
    }
    out = h; return true;
}
// Full detail for one block, by height (decimal) or by block hash (64 hex). For the explorer.
static std::string rpc_getblock(const std::string& arg) {
    std::lock_guard<std::mutex> lk(g_mtx);
    const Block* bp = nullptr; uint64_t height = 0; uint256 hash, hp;
    if (arg.size() == 64 && parse_hash256(arg, hp)) {
        auto it = g_chain.index.find(hp);
        if (it == g_chain.index.end()) return "{\"error\":\"block not found\"}";
        bp = &it->second.block; height = it->second.height; hash = hp;
    } else {
        char* end = nullptr; unsigned long long hh = strtoull(arg.c_str(), &end, 10);
        if (arg.empty() || !end || *end != '\0') return "{\"error\":\"bad block id\"}";
        if (hh > g_chain.height()) return "{\"error\":\"height out of range\"}";
        bp = &g_chain.blocks[(size_t)hh]; height = hh; hash = g_chain.hashes[(size_t)hh];
    }
    const Block& b = *bp;
    Writer wsz; b.serialize(wsz); size_t sz = wsz.data.size();
    double diff = g_chain.difficulty_of(b.header.bits);
    char head[560];
    snprintf(head, sizeof(head),
      "{\"height\":%llu,\"hash\":\"%s\",\"prev\":\"%s\",\"merkle\":\"%s\",\"time\":%llu,"
      "\"bits\":%u,\"diff\":%.3f,\"nonce\":%llu,\"size\":%zu,\"txs\":[",
      (unsigned long long)height, hash.hex().c_str(), b.header.prev_hash.hex().c_str(),
      b.header.merkle_root.hex().c_str(), (unsigned long long)b.header.timestamp,
      b.header.bits, diff, (unsigned long long)b.header.nonce, sz);
    std::string js = head;
    for (size_t i = 0; i < b.txs.size(); i++) {
        const Transaction& t = b.txs[i];
        if (i) js += ",";
        js += "{\"txid\":\"" + t.txid().hex() + "\",\"coinbase\":" + (t.is_coinbase() ? "true" : "false") + ",\"vin\":[";
        for (size_t k = 0; k < t.vin.size(); k++) {
            if (k) js += ",";
            if (t.is_coinbase()) js += "{\"coinbase\":true}";
            else js += "{\"txid\":\"" + t.vin[k].prev.txid.hex() + "\",\"index\":" + std::to_string(t.vin[k].prev.index) + "}";
        }
        js += "],\"vout\":[";
        for (size_t k = 0; k < t.vout.size(); k++) {
            if (k) js += ",";
            js += "{\"amount\":" + std::to_string(t.vout[k].amount) + ",\"addr\":\"" + to_hex(t.vout[k].pubkey_hash) + "\"}";
        }
        js += "]}";
    }
    js += "]}";
    return js;
}
// Look up one transaction by txid (scans the active chain, newest first). For the explorer.
static std::string rpc_gettx(const std::string& arg) {
    uint256 want;
    if (!parse_hash256(arg, want)) return "{\"error\":\"bad txid\"}";
    std::lock_guard<std::mutex> lk(g_mtx);
    uint64_t tip = g_chain.height();
    for (uint64_t h = tip; ; --h) {
        const Block& b = g_chain.blocks[(size_t)h];
        for (const auto& t : b.txs) {
            if (t.txid() == want) {
                std::string js = "{\"txid\":\"" + want.hex() + "\",\"block\":" + std::to_string(h)
                    + ",\"blockhash\":\"" + g_chain.hashes[(size_t)h].hex() + "\",\"confirmations\":"
                    + std::to_string(tip - h + 1) + ",\"time\":" + std::to_string(b.header.timestamp)
                    + ",\"coinbase\":" + (t.is_coinbase() ? "true" : "false") + ",\"vin\":[";
                for (size_t k = 0; k < t.vin.size(); k++) { if (k) js += ",";
                    if (t.is_coinbase()) js += "{\"coinbase\":true}";
                    else js += "{\"txid\":\"" + t.vin[k].prev.txid.hex() + "\",\"index\":" + std::to_string(t.vin[k].prev.index) + "}"; }
                js += "],\"vout\":[";
                uint64_t tot = 0;
                for (size_t k = 0; k < t.vout.size(); k++) { if (k) js += ","; tot += t.vout[k].amount;
                    js += "{\"amount\":" + std::to_string(t.vout[k].amount) + ",\"addr\":\"" + to_hex(t.vout[k].pubkey_hash) + "\"}"; }
                js += "],\"total_out\":" + std::to_string(tot) + "}";
                return js;
            }
        }
        if (h == 0) break;
    }
    return "{\"error\":\"tx not found\"}";
}
// Every transaction that touches an address, newest first, with the amount received and spent
// in each. Received = outputs paying the address; spent = inputs whose prior output the address
// owned (resolved from a one-pass index of every output ever created, since spent outputs are
// gone from the live UTXO set). For the explorer's address history. Capped at CAP entries.
static std::string rpc_getaddrtxs(const std::string& addrhex) {
    std::vector<uint8_t> addr; if (!from_hex(addrhex, addr) || addr.size() != 32) return "{\"error\":\"bad address\"}";
    std::lock_guard<std::mutex> lk(g_mtx);
    uint64_t tip = g_chain.height();
    // Resolve any input's prior output: outpoint -> (owner pubkey_hash, amount).
    std::map<OutPoint, std::pair<std::vector<uint8_t>, uint64_t>> outs;
    for (uint64_t h = 0; h <= tip; h++) {
        const Block& b = g_chain.blocks[(size_t)h];
        for (const auto& t : b.txs) {
            uint256 id = t.txid();
            for (uint32_t k = 0; k < t.vout.size(); k++)
                outs[OutPoint{ id, k }] = { t.vout[k].pubkey_hash, t.vout[k].amount };
        }
    }
    struct Ent { uint64_t h, time, recv, sent; std::string txid; bool cb; };
    std::vector<Ent> ents;
    for (uint64_t h = 0; h <= tip; h++) {
        const Block& b = g_chain.blocks[(size_t)h];
        for (const auto& t : b.txs) {
            uint64_t recv = 0, sent = 0;
            for (const auto& o : t.vout) if (o.pubkey_hash == addr) recv += o.amount;
            if (!t.is_coinbase())
                for (const auto& in : t.vin) {
                    auto it = outs.find(in.prev);
                    if (it != outs.end() && it->second.first == addr) sent += it->second.second;
                }
            if (recv == 0 && sent == 0) continue;
            ents.push_back({ h, b.header.timestamp, recv, sent, t.txid().hex(), t.is_coinbase() });
        }
    }
    const size_t CAP = 200;
    std::string js = "{\"address\":\"" + addrhex + "\",\"tip\":" + std::to_string(tip)
                   + ",\"txcount\":" + std::to_string(ents.size()) + ",\"txs\":[";
    size_t shown = 0; bool first = true;
    for (size_t i = ents.size(); i-- > 0 && shown < CAP; ) {
        const Ent& e = ents[i];
        if (!first) js += ","; first = false;
        char buf[400];
        snprintf(buf, sizeof(buf),
          "{\"txid\":\"%s\",\"height\":%llu,\"time\":%llu,\"received\":%llu,\"sent\":%llu,\"coinbase\":%s}",
          e.txid.c_str(), (unsigned long long)e.h, (unsigned long long)e.time,
          (unsigned long long)e.recv, (unsigned long long)e.sent, e.cb ? "true" : "false");
        js += buf; shown++;
    }
    js += "]}";
    return js;
}
// Pending (unconfirmed) transactions waiting to be mined, with each tx's size and fee. For the
// explorer's mempool panel.
static std::string rpc_getmempool() {
    std::lock_guard<std::mutex> lk(g_mtx);
    uint64_t next_h = g_chain.height() + 1;
    std::string js = "{\"count\":" + std::to_string(g_mempool.txs.size()) + ",\"txs\":[";
    bool first = true;
    for (const auto& t : g_mempool.txs) {
        uint64_t fee = 0; std::string e; check_tx(t, g_chain.utxo, next_h, fee, e);
        Writer w; t.serialize(w);
        uint64_t tot = 0; for (const auto& o : t.vout) tot += o.amount;
        if (!first) js += ","; first = false;
        char buf[340];
        snprintf(buf, sizeof(buf),
          "{\"txid\":\"%s\",\"size\":%zu,\"fee\":%llu,\"vin\":%zu,\"vout\":%zu,\"total_out\":%llu}",
          t.txid().hex().c_str(), w.data.size(), (unsigned long long)fee,
          t.vin.size(), t.vout.size(), (unsigned long long)tot);
        js += buf;
    }
    js += "]}";
    return js;
}
static std::string rpc_dispatch(const std::string& req) {
    auto sp = req.find(' ');
    std::string cmd = (sp == std::string::npos) ? req : req.substr(0, sp);
    std::string arg = (sp == std::string::npos) ? "" : req.substr(sp + 1);
    if (cmd == "getwork") return rpc_getwork(arg);
    if (cmd == "submit")  return rpc_submit(arg);
    if (cmd == "sendtx")  return rpc_sendtx(arg);
    if (cmd == "getutxos") return rpc_getutxos(arg);
    if (cmd == "chaininfo") return rpc_chaininfo();
    if (cmd == "recentblocks") return rpc_recentblocks(arg);
    if (cmd == "getblock") return rpc_getblock(arg);
    if (cmd == "gettx") return rpc_gettx(arg);
    if (cmd == "getaddrtxs") return rpc_getaddrtxs(arg);
    if (cmd == "getmempool") return rpc_getmempool();
    if (cmd == "info") { std::lock_guard<std::mutex> lk(g_mtx);
        char buf[64]; snprintf(buf, sizeof(buf), "OK %llu %.3f", (unsigned long long)g_chain.height(), g_chain.difficulty_of(g_chain.next_bits())); return buf; }
    return "ERR unknown command";
}
static void rpc_conn(sock_t c) {
    uint8_t type; std::vector<uint8_t> pl;
    while (g_running && net::recv_msg(c, type, pl)) {
        std::string resp = rpc_dispatch(std::string((char*)pl.data(), pl.size()));
        std::vector<uint8_t> out(resp.begin(), resp.end());
        if (!net::send_msg(c, 1, out)) break;
    }
    net::close_sock(c);
}
static void rpc_listener_thread(uint16_t port) {
    sock_t ls = net::listen_local(port);
    if (ls == CH_BADSOCK) { log_line("RPC: cannot bind 127.0.0.1:" + std::to_string(port)); return; }
    log_line("RPC on 127.0.0.1:" + std::to_string(port) + " (getwork/submit/info)");
    while (g_running) { std::string ip; sock_t c = net::accept_one(ls, ip); if (c == CH_BADSOCK) break; std::thread(rpc_conn, c).detach(); }
    net::close_sock(ls);
}

// Live stats for a dashboard: chain height, difficulty, estimated network hashrate,
// connected peers, cumulative local hashes, and blocks this node mined.
void node_stats(uint64_t& height, double& diff, double& est_net_hs, int& peers,
                uint64_t& hashes, uint64_t& blocks) {
    { std::lock_guard<std::mutex> lk(g_mtx);
      height = g_chain.height();
      uint32_t bits = g_chain.next_bits();
      diff = g_chain.difficulty_of(bits);
      est_net_hs = expected_hashes_per_block(bits) / (double)g_params.block_time;
    }
    { std::lock_guard<std::mutex> lk(g_peers_mtx); peers = (int)g_peers.size(); }
    hashes = g_hashes.load(); blocks = g_blocks_mined.load();
}

// Balance of `addr` from the local synced chain: spendable (mature) and pending
// (immature coinbase). Lets the all-in-one dashboard show on-chain earnings live.
void node_balance(const std::vector<uint8_t>& addr, uint64_t& mature, uint64_t& immature) {
    mature = 0; immature = 0;
    std::lock_guard<std::mutex> lk(g_mtx);
    uint64_t next_h = g_chain.height() + 1;
    for (const auto& kv : g_chain.utxo.map) {
        if (kv.second.pubkey_hash != addr) continue;
        if (kv.second.is_coinbase && next_h < kv.second.height + g_params.coinbase_maturity)
            immature += kv.second.amount;
        else
            mature += kv.second.amount;
    }
}

// Run a full node: listen, discover peers, sync, relay, RPC, and (if mine_wallet is set)
// mine with `mine_threads` threads. Assumes the caller already selected the network.
// Blocks forever. This is the one entry point both corehashd and coremine use.
int run_node(uint16_t listen_port, const std::string& peers, const std::string& minew,
             const std::string& wallet_pass, int mine_threads) {
    g_listen_port = listen_port;
    g_start_time = (int64_t)time(nullptr);

    std::mt19937_64 rng(std::random_device{}());
    g_node_nonce = rng();

    net::init();
    log_line(std::string("network: ") + g_params.name);

    if (!load_chain(CHAIN, g_chain)) { g_chain = ChainState::with_genesis(); save_chain(CHAIN, g_chain); }
    load_mempool(MEMP, g_mempool, g_chain.utxo, g_chain.height() + 1);
    load_peers();
    log_line("node up at height " + std::to_string(g_chain.height()) + ", genesis " + g_chain.hashes[0].hex().substr(0,16));

    // Seed the address book: hardcoded seeds + any peers passed in.
    for (const auto& s : g_params.seeds) add_known(s);
    if (peers != "-" && !peers.empty()) {
        size_t start = 0;
        while (start < peers.size()) {
            size_t comma = peers.find(',', start);
            std::string one = peers.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
            start = (comma == std::string::npos) ? peers.size() : comma + 1;
            if (one.find(':') != std::string::npos) add_known(one);
        }
    }

    std::thread(listener_thread, g_listen_port).detach();
    std::thread(auto_connect_thread).detach();
    std::thread(rpc_listener_thread, (uint16_t)(g_listen_port + 1)).detach();

    if (!minew.empty()) {
        uint8_t seed[32];
        if (wallet_read_seed(minew + ".wallet", wallet_pass, seed)) {
            Wallet w = Wallet::from_seed(seed);
            if (mine_threads < 1) mine_threads = 1;
            for (int i = 0; i < mine_threads; i++) std::thread(mining_thread, w, i, mine_threads).detach();
        } else {
            log_line("cannot unlock wallet '" + minew + "' (wrong passphrase?) -> not mining");
        }
    }

    while (g_running) std::this_thread::sleep_for(std::chrono::milliseconds(500));
    return 0;
}
