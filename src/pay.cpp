// nHash payment gateway (single-address mode). A tiny local HTTP/JSON service your
// product's backend calls to accept nHash for something (e.g. GrgAI PRO). ALL payments
// go to one address (yours); each order gets a unique tiny amount so payments are matched
// automatically. Read-only: it only watches the chain via a node's RPC.
//
// Usage: corehash-pay <node_host:rpcport> <receive_address_hex> <http_port>
//   Endpoints (GET, JSON):
//     /invoice?order=<id>&amount=<coins> -> {"address","amount_units","amount_display"}
//     /status?amount=<units>             -> {"paid","tip"}
#include "corehash.h"
#include "net.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <set>
#include <sstream>
#include <fstream>
#include <map>

static const uint64_t COIN = 100000000ULL;
static std::string g_node_host; static uint16_t g_node_port;
static std::string g_recv_addr;              // the single receiving address (yours)
static std::set<uint64_t> g_paid;            // amounts seen paid (persisted, so it stays paid after you sweep)
static const char* PAID_FILE = "paid_amounts.txt";

static void load_paid() { std::ifstream f(PAID_FILE); uint64_t v; while (f >> v) g_paid.insert(v); }
static void save_paid(uint64_t v) { g_paid.insert(v); std::ofstream f(PAID_FILE, std::ios::app); f << v << "\n"; }

// A small, near-unique fractional amount for an order id, so a shared address can still
// tell orders apart (base price + this delta of base units, < 0.001 nHash).
static uint64_t order_delta(const std::string& order) {
    uint8_t h[32]; ch::blake2b(h, 32, (const uint8_t*)order.data(), order.size());
    uint64_t d = 0; for (int i = 0; i < 5; i++) d = (d << 8) | h[i];
    return (d % 99999) + 1;
}

static bool node_rpc(const std::string& req, std::string& resp) {
    sock_t s = net::connect_to(g_node_host, g_node_port);
    if (s == CH_BADSOCK) return false;
    std::vector<uint8_t> out(req.begin(), req.end()); uint8_t type; std::vector<uint8_t> pl;
    bool ok = net::send_msg(s, 1, out) && net::recv_msg(s, type, pl);
    net::close_sock(s);
    if (ok) resp.assign((char*)pl.data(), pl.size());
    return ok;
}
// True if a UTXO of exactly `amount` base units currently sits at the receive address.
static bool has_exact_utxo(uint64_t amount, uint64_t& tip) {
    std::string resp; if (!node_rpc("getutxos " + g_recv_addr, resp) || resp.rfind("OK ", 0) != 0) return false;
    std::istringstream is(resp.substr(3)); uint64_t n = 0; is >> tip >> n;
    for (uint64_t i = 0; i < n; i++) { std::string item; if (!(is >> item)) break;
        size_t p = 0; std::vector<std::string> f;
        for (int k = 0; k < 4; k++) { auto q = item.find(':', p); f.push_back(item.substr(p, q - p)); p = q + 1; } f.push_back(item.substr(p));
        if (f.size() >= 3 && strtoull(f[2].c_str(), nullptr, 10) == amount) return true;
    }
    return false;
}

static std::map<std::string, std::string> parse_query(const std::string& q) {
    std::map<std::string, std::string> m; size_t p = 0;
    while (p < q.size()) { size_t amp = q.find('&', p); std::string kv = q.substr(p, amp == std::string::npos ? std::string::npos : amp - p);
        auto eq = kv.find('='); if (eq != std::string::npos) m[kv.substr(0, eq)] = kv.substr(eq + 1);
        if (amp == std::string::npos) break; p = amp + 1; }
    return m;
}
static void http_send(sock_t c, const std::string& body, const char* status = "200 OK") {
    std::string h = "HTTP/1.1 " + std::string(status) + "\r\nContent-Type: application/json\r\n"
                    "Access-Control-Allow-Origin: *\r\nContent-Length: " + std::to_string(body.size()) +
                    "\r\nConnection: close\r\n\r\n" + body;
    ::send(c, h.data(), (int)h.size(), 0);
}

static void handle(sock_t c) {
    char buf[4096]; int n = ::recv(c, buf, sizeof(buf) - 1, 0);
    if (n <= 0) { net::close_sock(c); return; }
    buf[n] = 0;
    std::string req(buf); size_t sp1 = req.find(' '); size_t sp2 = req.find(' ', sp1 + 1);
    std::string target = (sp1 != std::string::npos && sp2 != std::string::npos) ? req.substr(sp1 + 1, sp2 - sp1 - 1) : "/";
    std::string path = target, query;
    auto qm = target.find('?'); if (qm != std::string::npos) { path = target.substr(0, qm); query = target.substr(qm + 1); }
    auto q = parse_query(query);

    std::string body;
    if (path == "/invoice") {
        std::string order = q.count("order") ? q["order"] : "";
        uint64_t coins = q.count("amount") ? strtoull(q["amount"].c_str(), nullptr, 10) : 0;
        if (order.empty() || coins == 0) { http_send(c, "{\"error\":\"need order and amount\"}", "400 Bad Request"); net::close_sock(c); return; }
        uint64_t units = coins * COIN + order_delta(order);
        char disp[48]; snprintf(disp, sizeof(disp), "%llu.%08llu", (unsigned long long)(units / COIN), (unsigned long long)(units % COIN));
        body = "{\"address\":\"" + g_recv_addr + "\",\"amount_units\":" + std::to_string(units) + ",\"amount_display\":\"" + disp + "\"}";
    } else if (path == "/status") {
        uint64_t units = q.count("amount") ? strtoull(q["amount"].c_str(), nullptr, 10) : 0;
        uint64_t tip = 0; bool paid = g_paid.count(units) > 0;
        if (!paid && units > 0 && has_exact_utxo(units, tip)) { paid = true; save_paid(units); }
        body = std::string("{\"paid\":") + (paid ? "true" : "false") + ",\"tip\":" + std::to_string(tip) + "}";
    } else {
        http_send(c, "{\"error\":\"unknown endpoint\"}", "404 Not Found"); net::close_sock(c); return;
    }
    http_send(c, body);
    net::close_sock(c);
}

int main(int argc, char** argv) {
    if (argc < 4) { printf("usage: corehash-pay <node_host:rpcport> <receive_address_hex> <http_port>\n"); return 1; }
    std::string hp = argv[1]; auto pos = hp.rfind(':');
    g_node_host = hp.substr(0, pos); g_node_port = (uint16_t)atoi(hp.substr(pos + 1).c_str());
    g_recv_addr = argv[2]; uint16_t http_port = (uint16_t)atoi(argv[3]);
    if (g_recv_addr.size() != 64) { printf("receive address must be 64 hex chars\n"); return 1; }
    setvbuf(stdout, nullptr, _IONBF, 0);
    net::init(); load_paid();

    sock_t ls = net::listen_local(http_port);
    if (ls == CH_BADSOCK) { printf("cannot bind 127.0.0.1:%u\n", http_port); return 1; }
    printf("corehash-pay: HTTP 127.0.0.1:%u  ->  all payments to %s\n", http_port, g_recv_addr.c_str());
    while (true) { std::string ip; sock_t c = net::accept_one(ls, ip); if (c == CH_BADSOCK) break; handle(c); }
    return 0;
}
