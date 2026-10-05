#include "ed25519.h"
#include <cstring>
#include <vector>

namespace ed {

// ============================ SHA-512 ============================
static inline uint64_t ror64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }
static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

void sha512(uint8_t out[64], const uint8_t* in, size_t len) {
    uint64_t h[8] = {
        0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL
    };
    // Padded length: message + 0x80 + zeros + 16-byte length, multiple of 128.
    size_t total = len + 1 + 16;
    size_t nblocks = (total + 127) / 128;
    std::vector<uint8_t> buf(nblocks * 128, 0);
    memcpy(buf.data(), in, len);
    buf[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) buf[buf.size() - 1 - i] = (uint8_t)(bits >> (8 * i)); // low 64 of 128-bit length

    for (size_t b = 0; b < nblocks; b++) {
        const uint8_t* p = buf.data() + b * 128;
        uint64_t w[80];
        for (int i = 0; i < 16; i++) {
            w[i] = 0;
            for (int j = 0; j < 8; j++) w[i] = (w[i] << 8) | p[i * 8 + j]; // big-endian
        }
        for (int i = 16; i < 80; i++) {
            uint64_t s0 = ror64(w[i-15],1) ^ ror64(w[i-15],8) ^ (w[i-15] >> 7);
            uint64_t s1 = ror64(w[i-2],19) ^ ror64(w[i-2],61) ^ (w[i-2] >> 6);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint64_t a=h[0],bb=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 80; i++) {
            uint64_t S1 = ror64(e,14) ^ ror64(e,18) ^ ror64(e,41);
            uint64_t ch = (e & f) ^ (~e & g);
            uint64_t t1 = hh + S1 + ch + K512[i] + w[i];
            uint64_t S0 = ror64(a,28) ^ ror64(a,34) ^ ror64(a,39);
            uint64_t maj = (a & bb) ^ (a & c) ^ (bb & c);
            uint64_t t2 = S0 + maj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=bb; bb=a; a=t1+t2;
        }
        h[0]+=a;h[1]+=bb;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++) out[i*8+j] = (uint8_t)(h[i] >> (56 - 8*j));
}

// ============================ Field GF(2^255-19), radix 2^51 ============================
static const uint64_t MASK51 = 0x7ffffffffffffULL;

#if defined(__SIZEOF_INT128__)
typedef unsigned __int128 u128;
static inline u128 M64(uint64_t a, uint64_t b) { return (u128)a * b; }
static inline uint64_t SHR51(u128 x) { return (uint64_t)(x >> 51); }
static inline uint64_t LOW51(u128 x) { return (uint64_t)x & MASK51; }
#else
#include <intrin.h>
struct u128 { uint64_t lo, hi; };
static inline u128 M64(uint64_t a, uint64_t b) { u128 r; r.lo = _umul128(a, b, &r.hi); return r; }
static inline u128 operator+(u128 a, u128 b) { u128 r; r.lo = a.lo + b.lo; r.hi = a.hi + b.hi + (r.lo < a.lo); return r; }
static inline u128 operator+(u128 a, uint64_t b) { u128 r; r.lo = a.lo + b; r.hi = a.hi + (r.lo < a.lo); return r; }
static inline uint64_t SHR51(u128 x) { return (x.lo >> 51) | (x.hi << 13); }
static inline uint64_t LOW51(u128 x) { return x.lo & MASK51; }
#endif

typedef uint64_t fe[5];

static void fe_0(fe h) { h[0]=h[1]=h[2]=h[3]=h[4]=0; }
static void fe_1(fe h) { h[0]=1; h[1]=h[2]=h[3]=h[4]=0; }
static void fe_copy(fe h, const fe f) { for (int i=0;i<5;i++) h[i]=f[i]; }
static void fe_add(fe h, const fe f, const fe g) { for (int i=0;i<5;i++) h[i]=f[i]+g[i]; }
static void fe_sub(fe h, const fe f, const fe g) {
    h[0] = f[0] + 0xfffffffffffdaULL - g[0];
    h[1] = f[1] + 0xffffffffffffeULL - g[1];
    h[2] = f[2] + 0xffffffffffffeULL - g[2];
    h[3] = f[3] + 0xffffffffffffeULL - g[3];
    h[4] = f[4] + 0xffffffffffffeULL - g[4];
}

static void fe_mul(fe h, const fe f, const fe g) {
    uint64_t f0=f[0],f1=f[1],f2=f[2],f3=f[3],f4=f[4];
    uint64_t g0=g[0],g1=g[1],g2=g[2],g3=g[3],g4=g[4];
    uint64_t g1_19=19*g1, g2_19=19*g2, g3_19=19*g3, g4_19=19*g4;
    u128 h0 = M64(f0,g0) + M64(f1,g4_19) + M64(f2,g3_19) + M64(f3,g2_19) + M64(f4,g1_19);
    u128 h1 = M64(f0,g1) + M64(f1,g0)    + M64(f2,g4_19) + M64(f3,g3_19) + M64(f4,g2_19);
    u128 h2 = M64(f0,g2) + M64(f1,g1)    + M64(f2,g0)    + M64(f3,g4_19) + M64(f4,g3_19);
    u128 h3 = M64(f0,g3) + M64(f1,g2)    + M64(f2,g1)    + M64(f3,g0)    + M64(f4,g4_19);
    u128 h4 = M64(f0,g4) + M64(f1,g3)    + M64(f2,g2)    + M64(f3,g1)    + M64(f4,g0);
    uint64_t c;
    uint64_t r0,r1,r2,r3,r4;
    r0 = LOW51(h0); c = SHR51(h0); h1 = h1 + c;
    r1 = LOW51(h1); c = SHR51(h1); h2 = h2 + c;
    r2 = LOW51(h2); c = SHR51(h2); h3 = h3 + c;
    r3 = LOW51(h3); c = SHR51(h3); h4 = h4 + c;
    r4 = LOW51(h4); c = SHR51(h4);
    r0 += 19 * c;
    c = r0 >> 51; r0 &= MASK51; r1 += c;
    h[0]=r0; h[1]=r1; h[2]=r2; h[3]=r3; h[4]=r4;
}
static void fe_sq(fe h, const fe f) { fe_mul(h, f, f); }

static void fe_neg(fe h, const fe f) { fe z; fe_0(z); fe_sub(h, z, f); }

static uint64_t load64_le(const uint8_t* p) {
    uint64_t r = 0; for (int i=0;i<8;i++) r |= (uint64_t)p[i] << (8*i); return r;
}
static void fe_frombytes(fe h, const uint8_t s[32]) {
    h[0] = (load64_le(s))       & MASK51;
    h[1] = (load64_le(s+6) >> 3) & MASK51;
    h[2] = (load64_le(s+12) >> 6) & MASK51;
    h[3] = (load64_le(s+19) >> 1) & MASK51;
    h[4] = (load64_le(s+24) >> 12) & MASK51;
}
static void fe_reduce(uint64_t t[5]) {
    t[1] += t[0] >> 51; t[0] &= MASK51;
    t[2] += t[1] >> 51; t[1] &= MASK51;
    t[3] += t[2] >> 51; t[2] &= MASK51;
    t[4] += t[3] >> 51; t[3] &= MASK51;
    t[0] += 19 * (t[4] >> 51); t[4] &= MASK51;
}
static void fe_tobytes(uint8_t s[32], const fe f) {
    uint64_t t[5] = { f[0],f[1],f[2],f[3],f[4] };
    fe_reduce(t);
    // Conditionally subtract p to get the canonical representative.
    uint64_t q = (t[0] + 19) >> 51;
    q = (t[1] + q) >> 51; q = (t[2] + q) >> 51; q = (t[3] + q) >> 51; q = (t[4] + q) >> 51;
    t[0] += 19 * q;
    t[1] += t[0] >> 51; t[0] &= MASK51;
    t[2] += t[1] >> 51; t[1] &= MASK51;
    t[3] += t[2] >> 51; t[2] &= MASK51;
    t[4] += t[3] >> 51; t[3] &= MASK51;
    t[4] &= MASK51;
    // Pack 5 x 51-bit limbs into 32 little-endian bytes.
    memset(s, 0, 32);
    int bitpos = 0;
    for (int limb = 0; limb < 5; limb++) {
        for (int b = 0; b < 51; b++) {
            if ((t[limb] >> b) & 1) {
                int pos = bitpos + b;
                s[pos >> 3] |= (uint8_t)(1u << (pos & 7));
            }
        }
        bitpos += 51;
    }
}
static int fe_isnegative(const fe f) { uint8_t s[32]; fe_tobytes(s, f); return s[0] & 1; }
static int fe_iszero(const fe f) { uint8_t s[32]; fe_tobytes(s, f); uint8_t r=0; for (int i=0;i<32;i++) r|=s[i]; return r==0; }

static void fe_invert(fe out, const fe z) {
    fe t0,t1,t2,t3; int i;
    fe_sq(t0,z);
    fe_sq(t1,t0); fe_sq(t1,t1); fe_mul(t1,z,t1);
    fe_mul(t0,t0,t1);
    fe_sq(t2,t0); fe_mul(t1,t1,t2);
    fe_sq(t2,t1); for(i=1;i<5;i++) fe_sq(t2,t2); fe_mul(t1,t2,t1);
    fe_sq(t2,t1); for(i=1;i<10;i++) fe_sq(t2,t2); fe_mul(t2,t2,t1);
    fe_sq(t3,t2); for(i=1;i<20;i++) fe_sq(t3,t3); fe_mul(t2,t3,t2);
    fe_sq(t2,t2); for(i=1;i<10;i++) fe_sq(t2,t2); fe_mul(t1,t2,t1);
    fe_sq(t2,t1); for(i=1;i<50;i++) fe_sq(t2,t2); fe_mul(t2,t2,t1);
    fe_sq(t3,t2); for(i=1;i<100;i++) fe_sq(t3,t3); fe_mul(t2,t3,t2);
    fe_sq(t2,t2); for(i=1;i<50;i++) fe_sq(t2,t2); fe_mul(t1,t2,t1);
    fe_sq(t1,t1); for(i=1;i<5;i++) fe_sq(t1,t1); fe_mul(out,t1,t0);
}
static void fe_pow22523(fe out, const fe z) {
    fe t0,t1,t2; int i;
    fe_sq(t0,z);
    fe_sq(t1,t0); fe_sq(t1,t1); fe_mul(t1,z,t1);
    fe_mul(t0,t0,t1);
    fe_sq(t0,t0); fe_mul(t0,t1,t0);
    fe_sq(t1,t0); for(i=1;i<5;i++) fe_sq(t1,t1); fe_mul(t0,t1,t0);
    fe_sq(t1,t0); for(i=1;i<10;i++) fe_sq(t1,t1); fe_mul(t1,t1,t0);
    fe_sq(t2,t1); for(i=1;i<20;i++) fe_sq(t2,t2); fe_mul(t1,t2,t1);
    fe_sq(t1,t1); for(i=1;i<10;i++) fe_sq(t1,t1); fe_mul(t0,t1,t0);
    fe_sq(t1,t0); for(i=1;i<50;i++) fe_sq(t1,t1); fe_mul(t1,t1,t0);
    fe_sq(t2,t1); for(i=1;i<100;i++) fe_sq(t2,t2); fe_mul(t1,t2,t1);
    fe_sq(t1,t1); for(i=1;i<50;i++) fe_sq(t1,t1); fe_mul(t0,t1,t0);
    fe_sq(t0,t0); fe_sq(t0,t0); fe_mul(out,t0,z);
}

// ============================ Group edwards25519 (extended coords) ============================
struct ge { fe X, Y, Z, T; };

// Curve constant d and 2d, and sqrt(-1), loaded from their canonical encodings.
static const uint8_t D_BYTES[32] = {
    0xa3,0x78,0x59,0x13,0xca,0x4d,0xeb,0x75,0xab,0xd8,0x41,0x41,0x4d,0x0a,0x70,0x00,
    0x98,0xe8,0x79,0x77,0x79,0x40,0xc7,0x8c,0x73,0xfe,0x6f,0x2b,0xee,0x6c,0x03,0x52 };
static const uint8_t SQRTM1_BYTES[32] = {
    0xb0,0xa0,0x0e,0x4a,0x27,0x1b,0xee,0xc4,0x78,0xe4,0x2f,0xad,0x06,0x18,0x43,0x2f,
    0xa7,0xd7,0xfb,0x3d,0x99,0x00,0x4d,0x2b,0x0b,0xdf,0xc1,0x4f,0x80,0x24,0x83,0x2b };
// Base point encoding: y = 4/5, x positive.
static const uint8_t B_BYTES[32] = {
    0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
    0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66 };

static void ge_identity(ge& p) { fe_0(p.X); fe_1(p.Y); fe_1(p.Z); fe_0(p.T); }

static bool ge_frombytes(ge& p, const uint8_t s[32]) {
    fe d, sqrtm1, u, v, v3, vxx, check;
    fe_frombytes(d, D_BYTES);
    fe_frombytes(sqrtm1, SQRTM1_BYTES);
    fe_frombytes(p.Y, s);
    fe_1(p.Z);
    fe_sq(u, p.Y);
    fe_mul(v, u, d);
    fe_sub(u, u, p.Z);   // u = y^2 - 1
    fe_add(v, v, p.Z);   // v = d*y^2 + 1
    fe_sq(v3, v); fe_mul(v3, v3, v);            // v^3
    fe_sq(p.X, v3); fe_mul(p.X, p.X, v); fe_mul(p.X, p.X, u); // u*v^7
    fe_pow22523(p.X, p.X);
    fe_mul(p.X, p.X, v3); fe_mul(p.X, p.X, u);  // x = u*v^3*(u*v^7)^((p-5)/8)
    fe_sq(vxx, p.X); fe_mul(vxx, vxx, v);
    fe_sub(check, vxx, u);
    if (!fe_iszero(check)) {
        fe_add(check, vxx, u);
        if (!fe_iszero(check)) return false;
        fe_mul(p.X, p.X, sqrtm1);
    }
    if (fe_isnegative(p.X) != (s[31] >> 7)) fe_neg(p.X, p.X);
    fe_mul(p.T, p.X, p.Y);
    return true;
}

static void ge_tobytes(uint8_t s[32], const ge& p) {
    fe recip, x, y;
    fe_invert(recip, p.Z);
    fe_mul(x, p.X, recip);
    fe_mul(y, p.Y, recip);
    fe_tobytes(s, y);
    s[31] ^= (uint8_t)(fe_isnegative(x) << 7);
}

// Complete unified addition for a=-1 twisted Edwards (works for doubling too).
static void ge_add(ge& r, const ge& p, const ge& q) {
    fe d2, a, b, c, dd, e, f, g, h, t;
    fe_frombytes(d2, D_BYTES); fe_add(d2, d2, d2); // 2d
    fe_sub(a, p.Y, p.X); fe_sub(t, q.Y, q.X); fe_mul(a, a, t);
    fe_add(b, p.Y, p.X); fe_add(t, q.Y, q.X); fe_mul(b, b, t);
    fe_mul(c, p.T, q.T); fe_mul(c, c, d2);
    fe_mul(dd, p.Z, q.Z); fe_add(dd, dd, dd);
    fe_sub(e, b, a);
    fe_sub(f, dd, c);
    fe_add(g, dd, c);
    fe_add(h, b, a);
    fe_mul(r.X, e, f);
    fe_mul(r.Y, g, h);
    fe_mul(r.T, e, h);
    fe_mul(r.Z, f, g);
}

// Constant-time conditional move: f = b ? g : f, with b in {0,1}. No secret-dependent
// branch or memory-access pattern (mask is all-ones when b==1, all-zeros when b==0).
static void fe_cmov(fe f, const fe g, uint64_t b) {
    uint64_t mask = (uint64_t)0 - (b & 1);
    for (int i = 0; i < 5; i++) f[i] ^= mask & (f[i] ^ g[i]);
}
static void ge_cmov(ge& r, const ge& g, uint64_t b) {
    fe_cmov(r.X, g.X, b); fe_cmov(r.Y, g.Y, b);
    fe_cmov(r.Z, g.Z, b); fe_cmov(r.T, g.T, b);
}

// r = scalar * P, scalar as 32-byte little-endian, MSB-first double-and-add.
// Constant-time: every bit does exactly one double AND one add, and the result is
// selected branchlessly, so timing/branch/cache behaviour is independent of the
// (possibly secret) scalar. Bit-identical to the plain double-and-add, so RFC 8032
// test vectors are unchanged.
static void ge_scalarmult(ge& r, const uint8_t scalar[32], const ge& P) {
    ge R; ge_identity(R);
    for (int i = 255; i >= 0; i--) {
        ge_add(R, R, R);
        ge T; ge_add(T, R, P);
        uint64_t bit = (scalar[i >> 3] >> (i & 7)) & 1;
        ge_cmov(R, T, bit);
    }
    r = R;
}

// ============================ Scalars mod L ============================
static const uint8_t L_BYTES[32] = {
    0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10 };

static int ge32(const uint8_t* a, const uint8_t* b) { // a >= b ?
    for (int i = 31; i >= 0; i--) if (a[i] != b[i]) return a[i] > b[i];
    return 1;
}
// Constant-time: r -= L iff r >= L. Always computes r-L into a scratch buffer and
// selects branchlessly, so no data-dependent branch or timing leak on r's value.
static void csub_L(uint8_t r[32]) {
    uint8_t t[32]; int borrow = 0;
    for (int i = 0; i < 32; i++) { int v = (int)r[i] - L_BYTES[i] - borrow; borrow = (v >> 8) & 1; t[i] = (uint8_t)(v & 0xff); }
    // borrow==0 -> r>=L -> take t (mask 0xFF); borrow==1 -> r<L -> keep r (mask 0x00).
    uint8_t mask = (uint8_t)(borrow - 1);
    for (int i = 0; i < 32; i++) r[i] ^= mask & (r[i] ^ t[i]);
}
// Reduce a little-endian integer of `len` bytes modulo L into out[32]. Constant-time:
// fixed iteration count and a branchless conditional subtract each step.
static void mod_L(const uint8_t* in, size_t len, uint8_t out[32]) {
    uint8_t r[32] = {0};
    for (size_t bit = len * 8; bit-- > 0; ) {
        int carry = 0;
        for (int i = 0; i < 32; i++) { int v = (r[i] << 1) | carry; r[i] = (uint8_t)(v & 0xff); carry = (v >> 8) & 1; }
        r[0] |= (in[bit >> 3] >> (bit & 7)) & 1;
        csub_L(r);
    }
    memcpy(out, r, 32);
}
static void mul256(const uint8_t a[32], const uint8_t b[32], uint8_t out[64]) {
    uint32_t A[8], B[8]; uint32_t res[16] = {0};
    for (int i = 0; i < 8; i++) { A[i] = (uint32_t)a[4*i] | ((uint32_t)a[4*i+1]<<8) | ((uint32_t)a[4*i+2]<<16) | ((uint32_t)a[4*i+3]<<24);
                                  B[i] = (uint32_t)b[4*i] | ((uint32_t)b[4*i+1]<<8) | ((uint32_t)b[4*i+2]<<16) | ((uint32_t)b[4*i+3]<<24); }
    for (int i = 0; i < 8; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 8; j++) {
            uint64_t cur = (uint64_t)res[i+j] + (uint64_t)A[i] * B[j] + carry;
            res[i+j] = (uint32_t)cur; carry = cur >> 32;
        }
        res[i+8] += (uint32_t)carry;
    }
    for (int i = 0; i < 16; i++) { out[4*i]=(uint8_t)res[i]; out[4*i+1]=(uint8_t)(res[i]>>8); out[4*i+2]=(uint8_t)(res[i]>>16); out[4*i+3]=(uint8_t)(res[i]>>24); }
}
// out = (a*b + c) mod L
static void sc_muladd(uint8_t out[32], const uint8_t a[32], const uint8_t b[32], const uint8_t c[32]) {
    uint8_t prod[64]; mul256(a, b, prod);
    int carry = 0;
    for (int i = 0; i < 32; i++) { int t = prod[i] + c[i] + carry; prod[i] = (uint8_t)(t & 0xff); carry = t >> 8; }
    for (int i = 32; i < 64 && carry; i++) { int t = prod[i] + carry; prod[i] = (uint8_t)(t & 0xff); carry = t >> 8; }
    mod_L(prod, 64, out);
}

// ============================ High-level API ============================
static void clamp(uint8_t a[32]) { a[0] &= 248; a[31] &= 127; a[31] |= 64; }

void publickey(uint8_t pub[32], const uint8_t seed[32]) {
    uint8_t h[64]; sha512(h, seed, 32);
    uint8_t a[32]; memcpy(a, h, 32); clamp(a);
    ge B; ge_frombytes(B, B_BYTES);
    ge A; ge_scalarmult(A, a, B);
    ge_tobytes(pub, A);
}

void sign(uint8_t sig[64], const uint8_t seed[32], const uint8_t pub[32],
          const uint8_t* msg, size_t mlen) {
    uint8_t h[64]; sha512(h, seed, 32);
    uint8_t a[32]; memcpy(a, h, 32); clamp(a);
    const uint8_t* prefix = h + 32;

    std::vector<uint8_t> buf;
    buf.assign(prefix, prefix + 32); buf.insert(buf.end(), msg, msg + mlen);
    uint8_t rh[64]; sha512(rh, buf.data(), buf.size());
    uint8_t r[32]; mod_L(rh, 64, r);

    ge B; ge_frombytes(B, B_BYTES);
    ge R; ge_scalarmult(R, r, B);
    uint8_t Renc[32]; ge_tobytes(Renc, R);

    buf.assign(Renc, Renc + 32); buf.insert(buf.end(), pub, pub + 32); buf.insert(buf.end(), msg, msg + mlen);
    uint8_t kh[64]; sha512(kh, buf.data(), buf.size());
    uint8_t k[32]; mod_L(kh, 64, k);

    uint8_t S[32]; sc_muladd(S, k, a, r);
    memcpy(sig, Renc, 32);
    memcpy(sig + 32, S, 32);
}

bool verify(const uint8_t sig[64], const uint8_t pub[32], const uint8_t* msg, size_t mlen) {
    const uint8_t* Renc = sig;
    const uint8_t* S = sig + 32;
    if (ge32(S, L_BYTES)) return false; // S must be canonical (< L)

    ge A;
    if (!ge_frombytes(A, pub)) return false;
    fe_neg(A.X, A.X); fe_neg(A.T, A.T); // use -A

    std::vector<uint8_t> buf;
    buf.assign(Renc, Renc + 32); buf.insert(buf.end(), pub, pub + 32); buf.insert(buf.end(), msg, msg + mlen);
    uint8_t kh[64]; sha512(kh, buf.data(), buf.size());
    uint8_t k[32]; mod_L(kh, 64, k);

    ge B; ge_frombytes(B, B_BYTES);
    ge sB; ge_scalarmult(sB, S, B);
    ge kA; ge_scalarmult(kA, k, A);
    ge P; ge_add(P, sB, kA);            // S*B - k*A

    uint8_t check[32]; ge_tobytes(check, P);
    return memcmp(check, Renc, 32) == 0;
}

} // namespace ed
