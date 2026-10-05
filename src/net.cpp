#include "net.h"
#include <cstring>

#ifdef _WIN32
  #pragma comment(lib, "ws2_32.lib")
#endif

namespace net {

static const uint32_t MAX_MSG = 2u * 1024 * 1024; // 2 MB cap (> max block size)

void init() {
#ifdef _WIN32
    WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);
#endif
}

void close_sock(sock_t s) {
#ifdef _WIN32
    closesocket(s);
#else
    ::close(s);
#endif
}

sock_t listen_on(uint16_t port) {
    sock_t s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == CH_BADSOCK) return CH_BADSOCK;
    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = INADDR_ANY; a.sin_port = htons(port);
    if (bind(s, (sockaddr*)&a, sizeof(a)) != 0) { close_sock(s); return CH_BADSOCK; }
    if (listen(s, 8) != 0) { close_sock(s); return CH_BADSOCK; }
    return s;
}

sock_t listen_local(uint16_t port) {
    sock_t s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == CH_BADSOCK) return CH_BADSOCK;
    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (bind(s, (sockaddr*)&a, sizeof(a)) != 0) { close_sock(s); return CH_BADSOCK; }
    if (listen(s, 8) != 0) { close_sock(s); return CH_BADSOCK; }
    return s;
}

sock_t accept_one(sock_t listener, std::string& peer_ip) {
    sockaddr_in a{}; socklen_t len = sizeof(a);
    sock_t c = accept(listener, (sockaddr*)&a, &len);
    if (c == CH_BADSOCK) return CH_BADSOCK;
    char buf[64] = {0};
    inet_ntop(AF_INET, &a.sin_addr, buf, sizeof(buf));
    peer_ip = buf;
    return c;
}

sock_t connect_to(const std::string& host, uint16_t port) {
    addrinfo hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    std::string p = std::to_string(port);
    if (getaddrinfo(host.c_str(), p.c_str(), &hints, &res) != 0 || !res) return CH_BADSOCK;
    sock_t s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == CH_BADSOCK) { freeaddrinfo(res); return CH_BADSOCK; }
    if (connect(s, res->ai_addr, (int)res->ai_addrlen) != 0) { close_sock(s); freeaddrinfo(res); return CH_BADSOCK; }
    freeaddrinfo(res);
    return s;
}

static bool send_all(sock_t s, const uint8_t* p, size_t n) {
    size_t off = 0;
    while (off < n) {
        int k = send(s, (const char*)p + off, (int)(n - off), 0);
        if (k <= 0) return false;
        off += (size_t)k;
    }
    return true;
}
static bool recv_all(sock_t s, uint8_t* p, size_t n) {
    size_t off = 0;
    while (off < n) {
        int k = recv(s, (char*)p + off, (int)(n - off), 0);
        if (k <= 0) return false;
        off += (size_t)k;
    }
    return true;
}

bool send_msg(sock_t s, uint8_t type, const std::vector<uint8_t>& payload) {
    uint32_t len = (uint32_t)(1 + payload.size());
    uint8_t hdr[5];
    hdr[0] = (uint8_t)(len);       hdr[1] = (uint8_t)(len >> 8);
    hdr[2] = (uint8_t)(len >> 16); hdr[3] = (uint8_t)(len >> 24);
    hdr[4] = type;
    if (!send_all(s, hdr, 5)) return false;
    if (!payload.empty()) return send_all(s, payload.data(), payload.size());
    return true;
}

bool recv_msg(sock_t s, uint8_t& type, std::vector<uint8_t>& payload) {
    uint8_t lb[4];
    if (!recv_all(s, lb, 4)) return false;
    uint32_t len = (uint32_t)lb[0] | ((uint32_t)lb[1] << 8) | ((uint32_t)lb[2] << 16) | ((uint32_t)lb[3] << 24);
    if (len < 1 || len > MAX_MSG) return false;
    if (!recv_all(s, &type, 1)) return false;
    payload.resize(len - 1);
    if (len - 1 > 0) return recv_all(s, payload.data(), len - 1);
    return true;
}

} // namespace net
