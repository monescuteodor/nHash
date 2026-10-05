// Minimal cross-platform TCP + length-prefixed message framing (Winsock / BSD sockets).
#pragma once
#include <cstdint>
#include <vector>
#include <string>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  typedef SOCKET sock_t;
  #define CH_BADSOCK INVALID_SOCKET
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
  typedef int sock_t;
  #define CH_BADSOCK (-1)
#endif

namespace net {

void   init();                                   // WSAStartup on Windows; no-op elsewhere
sock_t listen_on(uint16_t port);                 // listen on all interfaces (0.0.0.0)
sock_t listen_local(uint16_t port);              // listen on 127.0.0.1 only (for RPC)
sock_t accept_one(sock_t listener, std::string& peer_ip);
sock_t connect_to(const std::string& host, uint16_t port);
void   close_sock(sock_t s);

// Frame = [u32 little-endian length = 1 + payload][u8 type][payload bytes].
bool send_msg(sock_t s, uint8_t type, const std::vector<uint8_t>& payload);
bool recv_msg(sock_t s, uint8_t& type, std::vector<uint8_t>& payload); // blocking; false on EOF/error

} // namespace net
