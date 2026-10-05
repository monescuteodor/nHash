// Core primitive types: 256-bit hash/target and deterministic serialization.
#pragma once
#include <cstdint>
#include <array>
#include <vector>
#include <string>
#include <cstring>
#include <stdexcept>

// 256-bit value stored little-endian (b[0] = least significant byte).
// Used both as a hash (block id, txid, merkle) and as a numeric difficulty target.
struct uint256 {
    std::array<uint8_t, 32> b{};

    bool operator==(const uint256& o) const { return b == o.b; }
    bool operator!=(const uint256& o) const { return !(*this == o); }

    // Numeric comparison as a 256-bit big-endian magnitude (b[31] most significant).
    bool operator<(const uint256& o) const {
        for (int i = 31; i >= 0; --i)
            if (b[i] != o.b[i]) return b[i] < o.b[i];
        return false;
    }
    bool operator<=(const uint256& o) const { return !(o < *this); }
    bool is_zero() const { for (auto x : b) if (x) return false; return true; }

    // Big-endian hex (most significant byte first), the conventional display form.
    std::string hex() const {
        static const char* d = "0123456789abcdef";
        std::string s(64, '0');
        for (int i = 0; i < 32; i++) {
            uint8_t byte = b[31 - i];
            s[2 * i] = d[byte >> 4];
            s[2 * i + 1] = d[byte & 0xf];
        }
        return s;
    }
    static uint256 from_bytes(const uint8_t p[32]) {
        uint256 r; memcpy(r.b.data(), p, 32); return r;
    }
};

// ---- Deterministic little-endian serializer (canonical byte form for hashing/network) ----
struct Writer {
    std::vector<uint8_t> data;
    void u8 (uint8_t v)  { data.push_back(v); }
    void u16(uint16_t v) { for (int i = 0; i < 2; i++) data.push_back((uint8_t)(v >> (8 * i))); }
    void u32(uint32_t v) { for (int i = 0; i < 4; i++) data.push_back((uint8_t)(v >> (8 * i))); }
    void u64(uint64_t v) { for (int i = 0; i < 8; i++) data.push_back((uint8_t)(v >> (8 * i))); }
    void raw(const uint8_t* p, size_t n) { data.insert(data.end(), p, p + n); }
    void h256(const uint256& h) { raw(h.b.data(), 32); }
    // Bitcoin-style CompactSize varint.
    void varint(uint64_t v) {
        if (v < 0xfd) { u8((uint8_t)v); }
        else if (v <= 0xffff) { u8(0xfd); u16((uint16_t)v); }
        else if (v <= 0xffffffff) { u8(0xfe); u32((uint32_t)v); }
        else { u8(0xff); u64(v); }
    }
    void bytes(const std::vector<uint8_t>& v) { varint(v.size()); raw(v.data(), v.size()); }
};

// ---- Matching reader for deserialization (network/persistence). ----
struct Reader {
    const uint8_t* p; size_t n, pos = 0;
    Reader(const uint8_t* data, size_t len) : p(data), n(len) {}
    void need(size_t k) const { if (pos + k > n) throw std::runtime_error("Reader: out of bounds"); }
    uint8_t  u8()  { need(1); return p[pos++]; }
    uint16_t u16() { need(2); uint16_t v = 0; for (int i = 0; i < 2; i++) v |= (uint16_t)p[pos++] << (8 * i); return v; }
    uint32_t u32() { need(4); uint32_t v = 0; for (int i = 0; i < 4; i++) v |= (uint32_t)p[pos++] << (8 * i); return v; }
    uint64_t u64() { need(8); uint64_t v = 0; for (int i = 0; i < 8; i++) v |= (uint64_t)p[pos++] << (8 * i); return v; }
    uint256 h256() { need(32); uint256 h; memcpy(h.b.data(), p + pos, 32); pos += 32; return h; }
    uint64_t varint() {
        uint8_t t = u8();
        if (t < 0xfd) return t;
        if (t == 0xfd) return u16();
        if (t == 0xfe) return u32();
        return u64();
    }
    std::vector<uint8_t> bytes() {
        uint64_t len = varint(); need(len);
        std::vector<uint8_t> v(p + pos, p + pos + len); pos += len; return v;
    }
};
