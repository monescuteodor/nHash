// CoreHash CLI wallet + single-node miner. Persists chain.dat, mempool.dat, <name>.wallet.
// Commands: init | newwallet <name> | address <name> | balance <name> |
//           send <from> <to> <amount> | mine <name> [count] | info
#include "blockchain.h"
#include "wallet.h"
#include "bip39.h"
#include "storage.h"
#include "params.h"
#include "net.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <random>
#include <ctime>
#include <cstdlib>
#include <thread>
#include <chrono>
#ifdef _WIN32
  #include <windows.h>
#else
  #include <termios.h>
  #include <unistd.h>
#endif

using consensus::COIN;

// Read a line from the terminal without echoing (for passphrases).
static std::string read_line_noecho() {
    std::string s;
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE); DWORD mode = 0; GetConsoleMode(h, &mode);
    SetConsoleMode(h, mode & ~ENABLE_ECHO_INPUT);
    std::getline(std::cin, s);
    SetConsoleMode(h, mode);
#else
    termios t{}; tcgetattr(STDIN_FILENO, &t); termios n = t; n.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &n);
    std::getline(std::cin, s);
    tcsetattr(STDIN_FILENO, TCSANOW, &t);
#endif
    return s;
}

// Get a passphrase: from $COREHASH_PASS if set (for scripts), else a no-echo prompt.
static std::string read_password(const std::string& prompt, bool confirm) {
    const char* env = std::getenv("COREHASH_PASS");
    if (env) return std::string(env);
    fputs(prompt.c_str(), stdout); fflush(stdout);
    std::string pw = read_line_noecho(); fputs("\n", stdout);
    if (confirm) {
        fputs("Confirm passphrase: ", stdout); fflush(stdout);
        std::string pw2 = read_line_noecho(); fputs("\n", stdout);
        if (pw != pw2) { printf("passphrases do not match\n"); std::exit(1); }
    }
    return pw;
}
static const std::string CHAIN = "chain.dat";
static const std::string MEMP  = "mempool.dat";
static const uint64_t    FEE   = COIN / 1000; // 0.001 flat fee

// ---- small helpers ----
static bool file_exists(const std::string& p) { std::ifstream f(p); return (bool)f; }

static std::string tohex(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s; for (size_t i = 0; i < n; i++) { s += d[p[i]>>4]; s += d[p[i]&15]; }
    return s;
}
static bool from_hex(const std::string& h, std::vector<uint8_t>& out) {
    if (h.size() % 2) return false;
    out.clear();
    for (size_t i = 0; i < h.size(); i += 2) {
        auto nib = [](char c)->int { if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; };
        int hi = nib(h[i]), lo = nib(h[i+1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back((uint8_t)((hi<<4)|lo));
    }
    return true;
}
// Parse a decimal amount (e.g. "12.5") into base units (1 coin = 1e8).
static bool parse_amount(const std::string& s, uint64_t& out) {
    size_t dot = s.find('.');
    std::string ip = (dot==std::string::npos) ? s : s.substr(0,dot);
    std::string fp = (dot==std::string::npos) ? "" : s.substr(dot+1);
    if (ip.empty() && fp.empty()) return false;
    fp.resize(8, '0'); if (fp.size() > 8) fp = fp.substr(0,8);
    try {
        uint64_t whole = ip.empty() ? 0 : std::stoull(ip);
        uint64_t frac  = fp.empty() ? 0 : std::stoull(fp);
        out = whole * COIN + frac;
        return true;
    } catch (...) { return false; }
}
static std::string amt(uint64_t a) {
    char buf[64]; snprintf(buf, sizeof(buf), "%llu.%08llu",
        (unsigned long long)(a/COIN), (unsigned long long)(a%COIN)); return buf;
}

// Load a wallet's secret (prompts for the passphrase if the file is encrypted).
static bool load_wallet(const std::string& name, Wallet& w) {
    std::string path = name + ".wallet";
    uint8_t pub[32]; bool enc;
    if (!wallet_read_pubkey(path, pub, enc)) return false;
    std::string pw = enc ? read_password("Passphrase for '" + name + "': ", false) : "";
    uint8_t seed[32];
    if (!wallet_read_seed(path, pw, seed)) { printf("wrong passphrase or corrupt wallet\n"); return false; }
    w = Wallet::from_seed(seed);
    return true;
}
// Resolve a "to" argument: a 64-hex address, or a wallet name (public key only, no passphrase).
static bool resolve_address(const std::string& s, std::vector<uint8_t>& addr) {
    if (s.size() == 64 && from_hex(s, addr) && addr.size() == 32) return true;
    uint8_t pub[32]; bool enc;
    if (wallet_read_pubkey(s + ".wallet", pub, enc)) { addr = pubkey_hash(pub); return true; }
    return false;
}

// ---- commands ----
static int cmd_init(bool force) {
    if (file_exists(CHAIN) && !force) { printf("chain.dat already exists (use: init force)\n"); return 1; }
    ChainState cs = ChainState::with_genesis();
    if (!save_chain(CHAIN, cs)) { printf("failed to write chain.dat\n"); return 1; }
    printf("Chain initialized. Genesis id: %s\n", cs.tip_hash().hex().c_str());
    return 0;
}
static int cmd_newwallet(const std::string& name) {
    if (file_exists(name + ".wallet")) { printf("wallet '%s' already exists\n", name.c_str()); return 1; }
    uint8_t seed[32];
    std::random_device rd;
    for (int i = 0; i < 32; i++) seed[i] = (uint8_t)rd();
    std::string pw = read_password("Set a passphrase for '" + name + "' (empty = unencrypted): ", true);
    if (!wallet_write(name + ".wallet", seed, pw)) { printf("failed to write wallet\n"); return 1; }
    Wallet w = Wallet::from_seed(seed);
    auto a = w.address();
    printf("Wallet '%s' created%s.\n  address: %s\n", name.c_str(),
           pw.empty() ? " (UNENCRYPTED - anyone with the file can spend it)" : " (encrypted)",
           tohex(a.data(), 32).c_str());
    return 0;
}
static int cmd_address(const std::string& name) {
    uint8_t pub[32]; bool enc;
    if (!wallet_read_pubkey(name + ".wallet", pub, enc)) { printf("no wallet '%s'\n", name.c_str()); return 1; }
    auto a = pubkey_hash(pub);
    printf("%s\n", tohex(a.data(), 32).c_str());
    return 0;
}
static int cmd_balance(const std::string& name) {
    ChainState cs; if (!load_chain(CHAIN, cs)) { printf("no chain (run: init)\n"); return 1; }
    uint8_t pub[32]; bool enc;
    if (!wallet_read_pubkey(name + ".wallet", pub, enc)) { printf("no wallet '%s'\n", name.c_str()); return 1; }
    printf("%s coins\n", amt(cs.utxo.balance_of(pubkey_hash(pub))).c_str());
    return 0;
}
static int cmd_info() {
    ChainState cs; if (!load_chain(CHAIN, cs)) { printf("no chain (run: init)\n"); return 1; }
    uint64_t supply = 0; for (auto& kv : cs.utxo.map) supply += kv.second.amount;
    Mempool mp; load_mempool(MEMP, mp, cs.utxo, cs.height()+1);
    printf("height:      %llu\n", (unsigned long long)cs.height());
    printf("tip:         %s\n", cs.tip_hash().hex().c_str());
    printf("difficulty:  %.3f\n", cs.difficulty_of(cs.next_bits()));
    printf("next reward: %s\n", amt(consensus::block_reward(cs.height()+1)).c_str());
    printf("supply:      %s coins\n", amt(supply).c_str());
    printf("utxos:       %zu\n", cs.utxo.map.size());
    printf("mempool:     %zu tx\n", mp.txs.size());
    return 0;
}
// Gather mature, un-pooled outputs owned by `w` to fund `amount`, size the fee to the resulting
// transaction's bytes (never below the flat FEE, always at/above the relay minimum so the node's
// mempool will accept it), then build and sign the tx. Returns 0 and fills out_tx/out_fee/
// out_change on success; non-zero with out_err set on failure. Shared by both send paths so the
// fee logic can never drift between them.
static int build_send_tx(const Wallet& w, const std::vector<uint8_t>& to_addr, uint64_t amount,
                         const ChainState& cs, const Mempool& mp,
                         Transaction& out_tx, uint64_t& out_fee, uint64_t& out_change,
                         std::string& out_err) {
    uint64_t next_h = cs.height() + 1;
    auto myaddr = w.address();
    // Eligible outputs, largest first: fewer inputs -> smaller tx -> smaller fee.
    std::vector<std::pair<OutPoint, uint64_t>> pool;
    for (const auto& kv : cs.utxo.map) {
        if (kv.second.pubkey_hash != myaddr) continue;
        if (mp.claimed.count(kv.first)) continue;
        if (kv.second.is_coinbase && next_h < kv.second.height + g_params.coinbase_maturity) continue;
        pool.push_back({ kv.first, kv.second.amount });
    }
    std::sort(pool.begin(), pool.end(),
              [](const std::pair<OutPoint,uint64_t>& a, const std::pair<OutPoint,uint64_t>& b){ return a.second > b.second; });
    // Fee estimate as inputs accumulate: a signed input ~140 B (36 outpoint + 96 sig||pubkey +
    // lengths), an output ~42 B, ~16 B of header/varints; never below the flat FEE.
    auto est_fee = [](size_t nin){ size_t sz = 16 + nin * 140 + 2 * 42;
                                   uint64_t m = consensus::min_relay_fee(sz); return m < FEE ? FEE : m; };
    uint64_t gathered = 0; std::vector<OutPoint> chosen;
    for (auto& e : pool) {
        chosen.push_back(e.first); gathered += e.second;
        if (gathered >= amount + est_fee(chosen.size())) break;
    }
    if (chosen.empty() || gathered < amount + est_fee(chosen.size())) { out_err = "insufficient funds"; return 1; }

    Transaction tx;
    for (auto& op : chosen) { TxIn in; in.prev = op; tx.vin.push_back(in); }
    tx.vout.push_back(TxOut{ amount, to_addr });
    size_t chg = tx.vout.size();
    tx.vout.push_back(TxOut{ 0, myaddr });     // change placeholder (fixed-width -> size-stable)
    sign_tx(tx, w);                            // sign once to measure the real serialized size
    uint64_t fee;
    { Writer wm; tx.serialize(wm); uint64_t rf = consensus::min_relay_fee(wm.data.size()); fee = rf < FEE ? FEE : rf; }
    if (gathered < amount + fee) { out_err = "insufficient funds after fee"; return 1; }
    uint64_t change = gathered - amount - fee;
    if (change == 0) tx.vout.erase(tx.vout.begin() + chg); else tx.vout[chg].amount = change;
    sign_tx(tx, w);                            // re-sign final outputs

    out_tx = tx; out_fee = fee; out_change = change; out_err.clear();
    return 0;
}

static int cmd_send(const std::string& from, const std::string& to, const std::string& amount_s) {
    ChainState cs; if (!load_chain(CHAIN, cs)) { printf("no chain (run: init)\n"); return 1; }
    Wallet w; if (!load_wallet(from, w)) { printf("no wallet '%s'\n", from.c_str()); return 1; }
    std::vector<uint8_t> to_addr;
    if (!resolve_address(to, to_addr)) { printf("cannot resolve recipient '%s'\n", to.c_str()); return 1; }
    uint64_t amount; if (!parse_amount(amount_s, amount) || amount == 0) { printf("bad amount\n"); return 1; }

    uint64_t next_h = cs.height() + 1;
    Mempool mp; load_mempool(MEMP, mp, cs.utxo, next_h);

    Transaction tx; uint64_t fee = 0, change = 0; std::string berr;
    if (build_send_tx(w, to_addr, amount, cs, mp, tx, fee, change, berr) != 0) {
        printf("cannot build tx: %s\n", berr.c_str()); return 1;
    }

    std::string err;
    if (!mp.accept(tx, cs.utxo, next_h, err)) { printf("tx rejected: %s\n", err.c_str()); return 1; }
    save_mempool(MEMP, mp);
    printf("queued tx %s\n  send %s to %s, fee %s, change %s\n  (run 'mine' to confirm)\n",
        tx.txid().hex().c_str(), amt(amount).c_str(), tohex(to_addr.data(),32).c_str(),
        amt(fee).c_str(), amt(change).c_str());
    return 0;
}
// Broadcast a signed transaction through the local running node (nhash.exe / nhashd).
// Preview the fee for a prospective send without broadcasting: builds the tx (dry run) and
// reports the size-based fee, input count, and total debit. The recipient is irrelevant to the
// fee (two outputs either way), so the sender's own address stands in.
static int cmd_estimatefee(const std::string& from, const std::string& amount_s) {
    ChainState cs; if (!load_chain(CHAIN, cs)) { printf("no chain (run: init)\n"); return 1; }
    Wallet w; if (!load_wallet(from, w)) { printf("no wallet '%s'\n", from.c_str()); return 1; }
    uint64_t amount; if (!parse_amount(amount_s, amount) || amount == 0) { printf("bad amount\n"); return 1; }
    uint64_t next_h = cs.height() + 1;
    Mempool mp; load_mempool(MEMP, mp, cs.utxo, next_h);
    Transaction tx; uint64_t fee = 0, change = 0; std::string berr;
    if (build_send_tx(w, w.address(), amount, cs, mp, tx, fee, change, berr) != 0) {
        printf("cannot estimate: %s\n", berr.c_str()); return 1;
    }
    Writer wsz; tx.serialize(wsz);
    printf("estimate for sending %s from '%s':\n  fee %s   (%zu input(s), %zu bytes)\n  total debit %s\n",
        amt(amount).c_str(), from.c_str(), amt(fee).c_str(),
        tx.vin.size(), wsz.data.size(), amt(amount + fee).c_str());
    return 0;
}

static bool rpc_sendtx(const std::string& txhex, std::string& result) {
    net::init();
    sock_t s = net::connect_to("127.0.0.1", (uint16_t)(9333 + 1));
    if (s == CH_BADSOCK) return false;
    std::string req = "sendtx " + txhex;
    std::vector<uint8_t> out(req.begin(), req.end());
    bool ok = false; uint8_t type; std::vector<uint8_t> pl;
    if (net::send_msg(s, 1, out) && net::recv_msg(s, type, pl)) { result.assign((char*)pl.data(), pl.size()); ok = true; }
    net::close_sock(s);
    return ok;
}
// Append a local record of a transfer (incl. the memo, which is a private note).
static void log_transfer(const std::string& to_label, const std::string& to_addr,
                         uint64_t amount, const std::string& memo, const std::string& txid) {
    std::ofstream f("transfers.log", std::ios::app);
    if (!f) return;
    time_t t = time(nullptr); char ts[32]; strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M", localtime(&t));
    f << ts << " | to " << to_label << " (" << to_addr.substr(0, 12) << "...)"
      << " | " << amt(amount) << " nHash"
      << " | memo: " << (memo.empty() ? "-" : memo)
      << " | tx " << txid.substr(0, 16) << "\n";
}
// Build, sign and BROADCAST a transfer over the network (needs the node running).
// Returns 0 on success. `memo` is stored locally only.
static int do_transfer(const std::string& from, const std::string& to,
                       const std::string& amount_s, const std::string& memo) {
    ChainState cs;
    bool loaded = false;
    for (int attempt = 0; attempt < 3 && !loaded; attempt++) {   // node may be mid-write
        loaded = load_chain(CHAIN, cs);
        if (!loaded) std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    if (!loaded) { printf("Cannot find the local chain. Start nhash.exe first (to sync).\n"); return 1; }
    Wallet w; if (!load_wallet(from, w)) { printf("Cannot open wallet '%s'.\n", from.c_str()); return 1; }
    std::vector<uint8_t> to_addr;
    if (!resolve_address(to, to_addr)) { printf("Unknown recipient '%s' (wallet name or a 64-char address).\n", to.c_str()); return 1; }
    uint64_t amount; if (!parse_amount(amount_s, amount) || amount == 0) { printf("Invalid amount.\n"); return 1; }

    uint64_t next_h = cs.height() + 1;
    Mempool mp; load_mempool(MEMP, mp, cs.utxo, next_h);

    Transaction tx; uint64_t fee = 0, change = 0; std::string berr;
    if (build_send_tx(w, to_addr, amount, cs, mp, tx, fee, change, berr) != 0) {
        printf("Insufficient funds: available %s, need %s + fee.\n",
               amt(cs.utxo.balance_of(w.address())).c_str(), amt(amount).c_str()); return 1;
    }

    Writer bw; tx.serialize(bw);
    std::string txhex = tohex(bw.data.data(), bw.data.size());
    std::string resp;
    if (!rpc_sendtx(txhex, resp)) {
        printf("Cannot send: the node is not running. Open nhash.exe (leave it running) and try again.\n");
        return 1;
    }
    if (resp.rfind("OK", 0) != 0) { printf("Transfer rejected by the network: %s\n", resp.c_str()); return 1; }

    log_transfer(to, tohex(to_addr.data(), 32), amount, memo, tx.txid().hex());
    printf("\n\x1b[32mTransfer sent to the network!\x1b[0m\n");
    printf("  to     : %s (%s...)\n", to.c_str(), tohex(to_addr.data(), 32).substr(0, 16).c_str());
    printf("  amount : %s nHash   (fee %s, change %s)\n", amt(amount).c_str(), amt(fee).c_str(), amt(change).c_str());
    if (!memo.empty()) printf("  memo   : %s   (local note, saved in transfers.log)\n", memo.c_str());
    printf("  tx     : %s\n", tx.txid().hex().c_str());
    printf("  Confirms in the next block (~5 min).\n");
    return 0;
}

static int cmd_mine(const std::string& name, int count) {
    ChainState cs; if (!load_chain(CHAIN, cs)) { printf("no chain (run: init)\n"); return 1; }
    Wallet w; if (!load_wallet(name, w)) { printf("no wallet '%s'\n", name.c_str()); return 1; }
    Mempool mp; load_mempool(MEMP, mp, cs.utxo, cs.height()+1);
    ch::CoreHashCtx ctx;
    uint64_t last_ts = cs.tip().header.timestamp;

    for (int c = 0; c < count; c++) {
        uint64_t hgt = cs.height() + 1;
        uint64_t now = (uint64_t)time(nullptr);
        uint64_t ts = now > last_ts ? now : last_ts + 1; // strictly increasing

        Block nb;
        nb.header.version = 1;
        nb.header.prev_hash = cs.tip_hash();
        nb.header.bits = cs.next_bits();
        nb.header.timestamp = ts;
        uint64_t fees = 0;
        auto pooled = mp.select_for_block(cs.utxo, hgt,
                          consensus::MAX_BLOCK_SIZE - consensus::COINBASE_RESERVE, fees);
        nb.txs.push_back(make_coinbase(hgt, consensus::block_reward(hgt) + fees, w.address()));
        for (const auto& t : pooled) nb.txs.push_back(t);
        nb.header.merkle_root = nb.compute_merkle_root();
        nb.header.nonce = 0;

        uint64_t tries = mine(nb, ctx);
        std::string err;
        if (!cs.connect(nb, ctx, err)) { printf("block %llu rejected: %s\n", (unsigned long long)hgt, err.c_str()); return 1; }
        mp.remove_confirmed(nb.txs);
        last_ts = ts;
        printf("mined block %llu  id %s  (%llu hashes, diff %.3f)\n",
            (unsigned long long)hgt, cs.tip_hash().hex().substr(0,16).c_str(),
            (unsigned long long)tries, cs.difficulty_of(nb.header.bits));
    }
    save_chain(CHAIN, cs);
    save_mempool(MEMP, mp);
    printf("balance of '%s': %s coins\n", name.c_str(), amt(cs.utxo.balance_of(w.address())).c_str());
    return 0;
}

// ---- live wallet dashboard ----
static void enable_vt() {
#ifdef _WIN32
    HANDLE ho = GetStdHandle(STD_OUTPUT_HANDLE); DWORD md = 0;
    if (GetConsoleMode(ho, &md)) SetConsoleMode(ho, md | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
#endif
}
// Split "amount:height:cb" style balances from a running node's getutxos RPC (localhost).
static bool rpc_balance(const std::string& addrhex, uint64_t& tip, uint64_t& mature, uint64_t& immature) {
    net::init();
    sock_t s = net::connect_to("127.0.0.1", (uint16_t)(9333 + 1)); // node RPC = P2P port + 1
    if (s == CH_BADSOCK) return false;
    std::string req = "getutxos " + addrhex;
    std::vector<uint8_t> out(req.begin(), req.end());
    bool ok = false; uint8_t type; std::vector<uint8_t> pl;
    if (net::send_msg(s, 1, out) && net::recv_msg(s, type, pl)) {
        std::string resp((char*)pl.data(), pl.size());
        if (resp.rfind("OK ", 0) == 0) {
            std::istringstream is(resp.substr(3)); uint64_t n = 0; is >> tip >> n;
            uint64_t next_h = tip + 1; mature = 0; immature = 0;
            for (uint64_t i = 0; i < n; i++) {
                std::string item; if (!(is >> item)) break; // txid:index:amount:height:cb
                std::vector<std::string> f; size_t p = 0;
                for (int k = 0; k < 4; k++) { auto q = item.find(':', p); f.push_back(item.substr(p, q - p)); p = q + 1; }
                f.push_back(item.substr(p));
                uint64_t amount = strtoull(f[2].c_str(), nullptr, 10);
                uint64_t h = strtoull(f[3].c_str(), nullptr, 10); bool cb = f[4] == "1";
                if (cb && next_h < h + g_params.coinbase_maturity) immature += amount; else mature += amount;
            }
            ok = true;
        }
    }
    net::close_sock(s);
    return ok;
}
// Fallback: read the local chain.dat directly if no node is running.
static bool chain_balance(const std::vector<uint8_t>& addr, uint64_t& tip, uint64_t& mature, uint64_t& immature) {
    ChainState cs; if (!load_chain(CHAIN, cs)) return false;
    tip = cs.height(); uint64_t next_h = tip + 1; mature = 0; immature = 0;
    for (const auto& kv : cs.utxo.map) {
        if (kv.second.pubkey_hash != addr) continue;
        if (kv.second.is_coinbase && next_h < kv.second.height + g_params.coinbase_maturity)
            immature += kv.second.amount;
        else mature += kv.second.amount;
    }
    return true;
}
static int cmd_dashboard(const std::string& name) {
    std::vector<uint8_t> addr;
    if (!resolve_address(name, addr)) { printf("no wallet '%s'\n", name.c_str()); return 1; }
    std::string addrhex = tohex(addr.data(), 32);
    enable_vt();
    const int LINES = 6; bool first = true;
    printf("Wallet '%s' - live dashboard (Ctrl+C to exit)\n\n", name.c_str());
    while (true) {
        uint64_t tip = 0, mature = 0, immature = 0;
        bool live = rpc_balance(addrhex, tip, mature, immature);
        std::string src = live ? "\x1b[32mlive (node running)\x1b[0m" : "\x1b[33moffline (chain.dat)\x1b[0m";
        if (!live) chain_balance(addr, tip, mature, immature);
        if (!first) printf("\x1b[%dA", LINES); first = false;
        auto line = [](const std::string& s){ printf("\x1b[2K%s\n", s.c_str()); };
        line("\x1b[1m  nHash wallet: " + name + "\x1b[0m   " + src);
        line("  ------------------------------------------------");
        line("  address  : " + addrhex);
        line("  balance  : \x1b[1m" + amt(mature + immature) + " nHash\x1b[0m   (available " + amt(mature) + " | pending " + amt(immature) + ")");
        line("  height   : " + std::to_string(tip));
        line("  ------------------------------------------------");
        fflush(stdout);
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }
    return 0;
}

static void usage() {
    printf("nHash wallet\n"
           "  nhash-wallet init [force]\n"
           "  nhash-wallet newwallet <name>\n"
           "  nhash-wallet backup    <name>              (show the 24-word seed phrase)\n"
           "  nhash-wallet restore   <name> [24 words]   (recreate a wallet from its phrase)\n"
           "  nhash-wallet address   <name>\n"
           "  nhash-wallet balance   <name>\n"
           "  nhash-wallet dashboard <name>      (live panel: balance + earnings)\n"
           "  nhash-wallet transfer <from> <to-addr-or-wallet> <amount> [memo]\n"
           "  nhash-wallet send <from> <to-addr-or-wallet> <amount>\n"
           "  nhash-wallet estimatefee <from> <amount>   (preview the fee for a send)\n"
           "  nhash-wallet mine <name> [count]\n"
           "  nhash-wallet info\n");
}

static std::string ask_line(const std::string& prompt) {
    printf("%s", prompt.c_str()); fflush(stdout);
    std::string s; std::getline(std::cin, s); return s;
}
// Interactive Transfer section: enter recipient / amount / memo (with examples).
static void interactive_transfer(const std::string& name) {
    printf("\n--- Transfer nHash ---\n");
    std::string to = ask_line("  To (miner name or address)   e.g. ana : ");
    for (char& c : to) if (c == ' ') c = '_';
    if (to.empty()) { printf("  Cancelled.\n"); return; }
    std::string amount = ask_line("  Amount (in nHash)            e.g. 12.5 : ");
    if (amount.empty()) { printf("  Cancelled.\n"); return; }
    std::string memo = ask_line("  Memo (note, optional)        e.g. for GrgAI PRO : ");
    printf("\n  Sending %s nHash to '%s'%s.  Confirm? (yes/no): ",
           amount.c_str(), to.c_str(), memo.empty() ? "" : (" [memo: " + memo + "]").c_str());
    std::string yn; std::getline(std::cin, yn);
    if (yn != "yes" && yn != "y" && yn != "da" && yn != "d") { printf("  Cancelled.\n"); return; }
    do_transfer(name, to, amount, memo);
}

// Show the wallet's 24-word BIP39 seed phrase (needs the passphrase). Writing these words
// down is a full offline backup: the wallet can be recreated from them on any machine.
static int cmd_backup(const std::string& name) {
    Wallet w;
    if (!load_wallet(name, w)) return 1;
    std::string m = bip39::mnemonic_from_entropy(w.seed);
    printf("\nSeed phrase for '%s' (24 words) - WRITE THESE DOWN, KEEP THEM SECRET:\n\n", name.c_str());
    int i = 1; std::istringstream is(m); std::string wd;
    while (is >> wd) { printf("%2d. %-10s", i, wd.c_str()); if (i % 4 == 0) printf("\n"); i++; }
    if ((i - 1) % 4 != 0) printf("\n");
    printf("\nAnyone with these 24 words can spend your coins. Store them offline, never online.\n");
    printf("Recover later with:  nhash-wallet restore %s\n", name.c_str());
    return 0;
}

// Recreate a wallet file from a 24-word BIP39 seed phrase.
static int cmd_restore(const std::string& name, const std::string& phrase_arg) {
    if (file_exists(name + ".wallet")) {
        printf("wallet '%s' already exists - refusing to overwrite. Delete '%s.wallet' first if you really mean to.\n",
               name.c_str(), name.c_str());
        return 1;
    }
    std::string phrase = phrase_arg;
    if (phrase.empty()) { printf("Enter the 24-word seed phrase for '%s':\n> ", name.c_str()); fflush(stdout); std::getline(std::cin, phrase); }
    uint8_t seed[32];
    if (!bip39::entropy_from_mnemonic(phrase, seed)) {
        printf("Invalid seed phrase (wrong words, wrong count, or checksum/typo). Nothing written.\n");
        return 1;
    }
    std::string pw = read_password("Set a passphrase for '" + name + "' (empty = unencrypted): ", true);
    if (!wallet_write(name + ".wallet", seed, pw)) { printf("failed to write wallet\n"); return 1; }
    Wallet w = Wallet::from_seed(seed);
    auto a = w.address();
    printf("Wallet '%s' restored%s.\n  address: %s\n", name.c_str(),
           pw.empty() ? " (UNENCRYPTED)" : " (encrypted)", tohex(a.data(), 32).c_str());
    return 0;
}

// Interactive mode when the exe is double-clicked (no arguments): pick a wallet, then
// choose Dashboard (live balance) or Transfer.
static int interactive_wallet() {
    printf("======================================\n"
           "   nHash - wallet\n"
           "======================================\n\n");
    std::string name;
    while (name.empty()) {
        name = ask_line("Wallet name (the user you mine with): ");
        for (char& c : name) if (c == ' ') c = '_';
    }
    if (!file_exists(name + ".wallet")) {
        printf("\nCannot find '%s.wallet' in this folder.\n", name.c_str());
        printf("Run this program in the same folder as nhash.exe (where you created your wallet).\n");
        ask_line("\nPress Enter to close...");
        return 1;
    }
    while (true) {
        printf("\nWallet: %s\n", name.c_str());
        printf("  [1] Dashboard  (view balance, live)\n");
        printf("  [2] Transfer   (send nHash)\n");
        printf("  [3] Backup     (show 24-word seed phrase)\n");
        printf("  [q] Quit\n");
        std::string choice = ask_line("Choose: ");
        if (choice == "1") return cmd_dashboard(name);   // live panel until Ctrl+C
        else if (choice == "2") interactive_transfer(name);
        else if (choice == "3") { cmd_backup(name); ask_line("\nPress Enter to continue..."); }
        else if (choice == "q" || choice == "Q") return 0;
        else printf("  Invalid option.\n");
    }
}

int main(int argc, char** argv) {
    // Network selection matches the daemon: mainnet by default; COREHASH_NET=regtest gives an
    // isolated network (easy genesis, different magic) for local testing. A wallet must run on
    // the same network as the node whose chain.dat it reads.
    const char* netsel = std::getenv("COREHASH_NET");
    if (netsel && std::string(netsel) == "regtest") select_regtest(); else select_mainnet();
    if (argc < 2) return interactive_wallet();
    std::string cmd = argv[1];
    auto arg = [&](int i)->std::string { return i < argc ? argv[i] : ""; };
    if (cmd == "init")       return cmd_init(arg(2) == "force");
    if (cmd == "newwallet")  return argc>=3 ? cmd_newwallet(arg(2)) : (usage(),1);
    if (cmd == "backup")     return argc>=3 ? cmd_backup(arg(2)) : (usage(),1);
    if (cmd == "restore") {
        if (argc < 3) { usage(); return 1; }
        std::string phrase; for (int i = 3; i < argc; i++) { if (i > 3) phrase += ' '; phrase += argv[i]; }
        return cmd_restore(arg(2), phrase);
    }
    if (cmd == "address")    return argc>=3 ? cmd_address(arg(2))   : (usage(),1);
    if (cmd == "balance")    return argc>=3 ? cmd_balance(arg(2))   : (usage(),1);
    if (cmd == "dashboard" || cmd == "watch") return argc>=3 ? cmd_dashboard(arg(2)) : (usage(),1);
    if (cmd == "transfer")   return argc>=5 ? do_transfer(arg(2),arg(3),arg(4), argc>=6?arg(5):"") : (usage(),1);
    if (cmd == "send")       return argc>=5 ? cmd_send(arg(2),arg(3),arg(4)) : (usage(),1);
    if (cmd == "estimatefee") return argc>=4 ? cmd_estimatefee(arg(2),arg(3)) : (usage(),1);
    if (cmd == "mine")       return argc>=3 ? cmd_mine(arg(2), argc>=4?atoi(argv[3]):1) : (usage(),1);
    if (cmd == "info")       return cmd_info();
    usage();
    return 1;
}
