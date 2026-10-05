// nHash all-in-one miner with a live dashboard. ONE program: type a username +
// password, it creates/unlocks your encrypted wallet, auto-detects your CPU, uses every
// core, and mines to the shared POOL so you earn a proportional fraction of every block
// (like Monero). A lightweight local node syncs the chain in the background so your
// wallet balance is live and spendable. No other program needed.
//
// Zero config: it auto-connects to the pool + seed baked into the binary. Optional
// override via a network.txt whose first line is one of:
//   pool:host:port     mine to a specific pool
//   solo               run a solo full node that mines whole blocks itself (old mode)
//   solo:host:port     solo, and also connect to that peer
#include "wallet.h"
#include "node.h"
#include "miner.h"
#include "params.h"
#include "corehash.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <random>
#include <thread>
#include <chrono>
#include <atomic>
#ifdef _WIN32
  #include <windows.h>
  #include <intrin.h>
#else
  #include <termios.h>
  #include <unistd.h>
#endif

// The shared pool + seed this binary auto-connects to (the always-on i5-2500K host).
static const char* DEFAULT_POOL = "192.168.50.220:9350";

static std::string ask(const std::string& prompt) {
    std::cout << prompt << std::flush; std::string s; std::getline(std::cin, s); return s;
}
static std::string ask_secret(const std::string& prompt) {
    std::cout << prompt << std::flush; std::string s;
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE); DWORD m = 0; GetConsoleMode(h, &m);
    SetConsoleMode(h, m & ~ENABLE_ECHO_INPUT); std::getline(std::cin, s); SetConsoleMode(h, m);
#else
    termios t{}; tcgetattr(STDIN_FILENO, &t); termios n = t; n.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &n); std::getline(std::cin, s); tcsetattr(STDIN_FILENO, TCSANOW, &t);
#endif
    std::cout << "\n"; return s;
}
static bool file_exists(const std::string& p) { std::ifstream f(p); return (bool)f; }
static std::string tohex(const std::vector<uint8_t>& b) {
    static const char* d = "0123456789abcdef"; std::string s; for (auto x : b) { s += d[x>>4]; s += d[x&15]; } return s;
}
static std::string cpu_name() {
#ifdef _WIN32
    int r[4]; char b[49] = {0}; __cpuid(r, 0x80000000); unsigned m = (unsigned)r[0];
    if (m >= 0x80000004) { for (unsigned i = 0; i < 3; i++) __cpuid((int*)(b + 16 * i), 0x80000002 + i); return std::string(b); }
    return "CPU";
#else
    std::ifstream f("/proc/cpuinfo"); std::string line;
    while (std::getline(f, line)) { if (line.find("model name") != std::string::npos) { auto c = line.find(':'); if (c != std::string::npos) return line.substr(c + 2); } }
    return "CPU";
#endif
}
static std::string fmt_hs(double h) {
    char b[40];
    if (h >= 1e6) snprintf(b, sizeof(b), "%.2f MH/s", h / 1e6);
    else if (h >= 1e3) snprintf(b, sizeof(b), "%.2f kH/s", h / 1e3);
    else snprintf(b, sizeof(b), "%.1f H/s", h);
    return b;
}
static const uint64_t COINU = 100000000ULL;
static std::string amt(uint64_t a) { // base units -> "12.3456" (trim trailing zeros, keep >=2 dp)
    char buf[48]; snprintf(buf, sizeof(buf), "%llu.%08llu",
        (unsigned long long)(a / COINU), (unsigned long long)(a % COINU));
    std::string s = buf; size_t dot = s.find('.');
    size_t last = s.find_last_not_of('0');
    if (last > dot + 2) s.erase(last + 1); else s.erase(dot + 3);
    return s;
}
static void enable_vt() {
#ifdef _WIN32
    HANDLE ho = GetStdHandle(STD_OUTPUT_HANDLE); DWORD md = 0;
    if (GetConsoleMode(ho, &md)) SetConsoleMode(ho, md | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
#endif
}

// Measure raw hashrate with `threads` worker threads for `secs` seconds.
static double measure_hs(int threads, double secs) {
    std::atomic<bool> stop{false};
    std::atomic<uint64_t> total{0};
    std::vector<std::thread> pool;
    for (int t = 0; t < threads; t++) {
        pool.emplace_back([&, t]{
            ch::CoreHashCtx ctx;
            uint8_t in[80]; for (int i = 0; i < 80; i++) in[i] = (uint8_t)(i * 3 + t);
            uint8_t out[32]; uint64_t n = 0, local = 0;
            while (!stop.load(std::memory_order_relaxed)) {
                std::memcpy(in + 72, &n, sizeof(n)); n++;
                ch::corehash(in, 80, out, ctx);
                if ((++local & 3) == 0) { total.fetch_add(4, std::memory_order_relaxed); local = 0; }
            }
            total.fetch_add(local, std::memory_order_relaxed);
        });
    }
    auto t0 = std::chrono::steady_clock::now();
    std::this_thread::sleep_for(std::chrono::duration<double>(secs));
    stop.store(true);
    for (auto& th : pool) th.join();
    double dt = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    return dt > 0 ? (double)total.load() / dt : 0;
}
// Pick the thread count with the HIGHEST hashrate (= most earnings). On cache-limited or
// hybrid (P+E core / hyper-threaded) CPUs, all logical threads is not always the fastest.
// Prefers more threads unless fewer is clearly (>3%) faster, to avoid measurement noise.
static int calibrate_threads(int maxt) {
    if (maxt <= 2) return maxt < 1 ? 1 : maxt;
    std::vector<int> cands = { maxt, (maxt * 3) / 4, maxt / 2 };
    int best = maxt; double best_hs = 0; bool first = true;
    for (int c : cands) {
        if (c < 1) c = 1;
        double hs = measure_hs(c, 2.5);
        printf("   %2d threads -> %s\n", c, fmt_hs(hs).c_str());
        if (first) { best = c; best_hs = hs; first = false; }
        else if (hs > best_hs * 1.03) { best = c; best_hs = hs; }
    }
    return best;
}

static const int PANEL_LINES = 9;
// Pool-mode dashboard: your hashrate + earnings (from the pool) + network + your live
// on-chain balance (from the local sync node).
static void dashboard_pool(const std::string& user, const std::string& addrhex,
                           const std::vector<uint8_t>& addr, const std::string& cpu,
                           int threads, const std::string& poolhp) {
    enable_vt();
    uint64_t prevH = 0; auto prevT = std::chrono::steady_clock::now(); bool first = true;
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        uint64_t height = 0, nhashes = 0, nblocks = 0; double diff = 0, est = 0; int peers = 0;
        node_stats(height, diff, est, peers, nhashes, nblocks);
        uint64_t mhashes = 0, shares = 0, blocks = 0, owed = 0, paid = 0; int conn = 0;
        miner_stats(mhashes, shares, blocks, owed, paid, conn);
        uint64_t mature = 0, immature = 0; node_balance(addr, mature, immature);

        auto now = std::chrono::steady_clock::now();
        double dt = std::chrono::duration<double>(now - prevT).count();
        double hs = dt > 0 ? (double)(mhashes - prevH) / dt : 0;
        prevH = mhashes; prevT = now;

        uint64_t total = mature + immature + owed;

        if (!first) printf("\x1b[%dA", PANEL_LINES);
        first = false;
        auto line = [](const std::string& s){ printf("\x1b[2K%s\n", s.c_str()); };
        std::string status = conn ? "\x1b[32mconnected to pool\x1b[0m" : "\x1b[33mreconnecting...\x1b[0m";
        line("\x1b[1m  nHash  \x1b[0m\x1b[2mpool " + poolhp + "\x1b[0m   " + status);
        line("  ------------------------------------------------");
        line("  miner    : " + user + "   (" + addrhex.substr(0, 16) + "...)");
        line("  cpu      : " + cpu.substr(0, 42));
        line("  hashrate : \x1b[1m" + fmt_hs(hs) + "\x1b[0m   (" + std::to_string(threads) + " threads)   shares: " + std::to_string(shares));
        line("  network  : height " + std::to_string(height) + "   diff " + [&]{char b[24];snprintf(b,24,"%.2f",diff);return std::string(b);}()
             + "   ~" + fmt_hs(est));
        line("  peers    : " + std::to_string(peers) + "      blocks (pool) via you: \x1b[1m" + std::to_string(blocks) + "\x1b[0m");
        line("  earnings : \x1b[1m" + amt(total) + " nHash\x1b[0m   (available " + amt(mature) + " | pending " + amt(immature + owed) + ")");
        line("  ------------------------------------------------");
        fflush(stdout);
    }
}

// Solo-mode dashboard (old behaviour: this node mines whole blocks for itself).
static const int PANEL_LINES_SOLO = 8;
static void dashboard_solo(const std::string& user, const std::string& addr, const std::string& cpu,
                           int threads, const std::string& netlabel) {
    enable_vt();
    uint64_t prevH = 0; auto prevT = std::chrono::steady_clock::now(); bool first = true;
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        uint64_t height = 0, hashes = 0, blocks = 0; double diff = 0, est = 0; int peers = 0;
        node_stats(height, diff, est, peers, hashes, blocks);
        auto now = std::chrono::steady_clock::now();
        double dt = std::chrono::duration<double>(now - prevT).count();
        double hs = dt > 0 ? (double)(hashes - prevH) / dt : 0;
        prevH = hashes; prevT = now;
        if (!first) printf("\x1b[%dA", PANEL_LINES_SOLO);
        first = false;
        auto line = [](const std::string& s){ printf("\x1b[2K%s\n", s.c_str()); };
        line("\x1b[1m  nHash  \x1b[0m\x1b[2m" + netlabel + "\x1b[0m");
        line("  ------------------------------------------------");
        line("  miner    : " + user + "   (" + addr.substr(0, 16) + "...)");
        line("  cpu      : " + cpu.substr(0, 42));
        line("  mining   : " + std::to_string(threads) + " thread(s)   \x1b[1m" + fmt_hs(hs) + "\x1b[0m");
        line("  network  : height " + std::to_string(height) + "   diff " + [&]{char b[24];snprintf(b,24,"%.2f",diff);return std::string(b);}()
             + "   ~" + fmt_hs(est));
        line("  peers    : " + std::to_string(peers) + "      blocks found by you: \x1b[1m" + std::to_string(blocks) + "\x1b[0m");
        line("  ------------------------------------------------");
        fflush(stdout);
    }
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    std::cout << "======================================\n"
                 "   nHash - mining (all in one exe)\n"
                 "======================================\n\n";

    std::string user;
    while (user.empty()) user = ask("Username (no spaces): ");
    for (auto& c : user) if (c == ' ') c = '_';
    std::string wfile = user + ".wallet";

    uint8_t seed[32]; std::string pw;
    if (file_exists(wfile)) {
        pw = ask_secret("Password for '" + user + "': ");
        if (!wallet_read_seed(wfile, pw, seed)) { std::cout << "Wrong password. Exiting.\n"; return 1; }
        std::cout << "Wallet unlocked.\n";
    } else {
        std::cout << "New wallet for '" << user << "'.\n";
        pw = ask_secret("Choose a password: ");
        std::string pw2 = ask_secret("Confirm password: ");
        if (pw != pw2 || pw.empty()) { std::cout << "Passwords do not match (or empty). Exiting.\n"; return 1; }
        std::random_device rd; for (int i = 0; i < 32; i++) seed[i] = (uint8_t)rd();
        if (!wallet_write(wfile, seed, pw)) { std::cout << "Could not write the wallet.\n"; return 1; }
        std::cout << "Wallet created (encrypted).\n";
    }
    Wallet w = Wallet::from_seed(seed);
    std::vector<uint8_t> addrb = w.address();
    std::string addr = tohex(addrb);
    std::string cpu = cpu_name();
    int threads = (int)std::thread::hardware_concurrency(); if (threads < 1) threads = 1;
    std::cout << "Your address: " << addr << "\n";
    std::cout << "Detected CPU: " << cpu << " (" << threads << " threads)\n";
    std::cout << "Calibrating for max hashrate (a few seconds)...\n";
    threads = calibrate_threads(threads);
    std::cout << "Mining with " << threads << " threads (best hashrate).\n";
    if (ch::corehash_using_huge_pages())
        std::cout << "Huge pages: ON (max efficiency).\n\n";
    else
        std::cout << "Huge pages: off  (enable 'Lock pages in memory' for ~15-30% more hashrate/watt).\n\n";

    select_mainnet();

    // Mode selection (default = shared pool, zero config).
    std::string net;
    { std::ifstream f("network.txt"); std::string line; if (f && std::getline(f, line) && !line.empty()) net = line; }

    if (net.rfind("solo", 0) == 0) {
        // Solo full node that mines whole blocks itself.
        std::string peer = "-";
        if (net.size() > 5 && net[4] == ':') peer = net.substr(5);
        std::string netlabel = (peer == "-") ? "  nHash network (solo)" : ("  solo -> " + peer);
        g_quiet = true;
        std::thread node([&]{ run_node(9333, peer, user, pw, threads); });
        dashboard_solo(user, addr, cpu, threads, netlabel);
        node.join();
        return 0;
    }

    // Pool mode (default). Resolve pool host:port.
    std::string poolhp = DEFAULT_POOL;
    if (net.rfind("pool:", 0) == 0) poolhp = net.substr(5);
    auto pos = poolhp.rfind(':');
    std::string pool_host = poolhp.substr(0, pos);
    uint16_t pool_port = (uint16_t)atoi(poolhp.substr(pos + 1).c_str());

    std::cout << "Connecting to pool " << poolhp << " and syncing the chain...\n\n";

    // Background: a sync-only node (no solo mining) keeps the chain + your balance live.
    g_quiet = true;
    std::thread node([&]{ run_node(9333, "-", "", "", 0); });
    std::this_thread::sleep_for(std::chrono::milliseconds(600));
    // Background: full-power mining to the pool (proportional fractions).
    g_miner_quiet = true;
    std::thread miner([&]{ run_miner(pool_host, pool_port, addr, threads); });

    dashboard_pool(user, addr, addrb, cpu, threads, poolhp);
    miner.join();
    node.join();
    return 0;
}
