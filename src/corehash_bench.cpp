// CoreHash v2 - tunable benchmark harness (fill = AES-NI, mix = dual-lane).
// Mirrors src/corehash.cpp but with runtime-tunable scratchpad size and iteration count
// so we can profile phases and sweep parameters. Build with AES: MSVC needs no flag;
// g++ needs -maes.
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <chrono>
#include <thread>
#include <atomic>
#include <string>
#include <immintrin.h>

// ---- Blake2b (RFC 7693) ----
static const uint64_t IV[8] = {
    0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL };
static const uint8_t SIG[12][16] = {
    { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},{14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
    {11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4},{7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8},
    {9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13},{2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9},
    {12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11},{13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10},
    {6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5},{10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0},
    {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},{14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3} };
static inline uint64_t rotr64(uint64_t x,int n){return (x>>n)|(x<<(64-n));}
static inline uint64_t rotl64(uint64_t x,int n){return (x<<n)|(x>>(64-n));}
#define G(r,i,a,b,c,d) a=a+b+m[SIG[r][2*i+0]];d=rotr64(d^a,32);c=c+d;b=rotr64(b^c,24); \
    a=a+b+m[SIG[r][2*i+1]];d=rotr64(d^a,16);c=c+d;b=rotr64(b^c,63);
static void compress(uint64_t h[8],const uint8_t blk[128],uint64_t t0,uint64_t t1,int last){
    uint64_t v[16],m[16];
    for(int i=0;i<16;i++) memcpy(&m[i],blk+8*i,8);
    for(int i=0;i<8;i++) v[i]=h[i];
    for(int i=0;i<8;i++) v[8+i]=IV[i];
    v[12]^=t0; v[13]^=t1; if(last) v[14]=~v[14];
    for(int r=0;r<12;r++){ G(r,0,v[0],v[4],v[8],v[12]);G(r,1,v[1],v[5],v[9],v[13]);
        G(r,2,v[2],v[6],v[10],v[14]);G(r,3,v[3],v[7],v[11],v[15]);
        G(r,4,v[0],v[5],v[10],v[15]);G(r,5,v[1],v[6],v[11],v[12]);
        G(r,6,v[2],v[7],v[8],v[13]);G(r,7,v[3],v[4],v[9],v[14]); }
    for(int i=0;i<8;i++) h[i]^=v[i]^v[8+i];
}
static void blake2b(uint8_t* out,size_t outlen,const uint8_t* in,size_t inlen){
    uint64_t h[8]; memcpy(h,IV,sizeof(h)); h[0]^=0x01010000ULL^(uint64_t)outlen;
    uint64_t t0=0,t1=0; uint8_t blk[128]; size_t i=0;
    while(inlen-i>128){ memcpy(blk,in+i,128); t0+=128; if(t0<128)t1++; compress(h,blk,t0,t1,0); i+=128; }
    size_t rem=inlen-i; memset(blk,0,128); if(rem)memcpy(blk,in+i,rem);
    t0+=rem; if(t0<rem)t1++; compress(h,blk,t0,t1,1); memcpy(out,h,outlen);
}

// ---- AES-NI fill ----
static void fill_scratchpad(uint64_t* pad,size_t words,const uint8_t seed[32]){
    __m128i k0=_mm_loadu_si128((const __m128i*)seed);
    __m128i k1=_mm_loadu_si128((const __m128i*)(seed+16));
    __m128i blk=_mm_xor_si128(k0,k1);
    __m128i* out=(__m128i*)pad; size_t nblk=(words*8)/16;
    for(size_t i=0;i<nblk;i++){ blk=_mm_aesenc_si128(blk,k0); blk=_mm_aesenc_si128(blk,k1); _mm_storeu_si128(out+i,blk); }
}

// ---- CoreHash v2 (dual-lane), tunable ----
static const uint64_t GOLDEN=0x9E3779B97F4A7C15ULL;
struct PhaseProf{ double fill_ns=0,mix_ns=0; uint64_t n=0; };
static void corehash(const uint8_t* header,size_t hlen,uint64_t nonce,uint8_t out[32],
                     uint64_t* pad,size_t pad_words,uint64_t iter,PhaseProf* prof=nullptr){
    const uint64_t mask=pad_words-1;
    uint8_t buf[256]; size_t hl=hlen>248?248:hlen; memcpy(buf,header,hl); memcpy(buf+hl,&nonce,8);
    uint8_t seed[32]; blake2b(seed,32,buf,hl+8);

    auto tf0=std::chrono::steady_clock::now();
    fill_scratchpad(pad,pad_words,seed);
    auto tf1=std::chrono::steady_clock::now();

    uint64_t a,b,c,d;
    memcpy(&a,seed,8); memcpy(&b,seed+8,8); memcpy(&c,seed+16,8); memcpy(&d,seed+24,8);
    uint64_t e=rotl64(a,17)^rotl64(b,31)^rotl64(c,47)^d;

    auto tm0=std::chrono::steady_clock::now();
    for(uint64_t i=0;i<iter;i++){
        uint64_t addr1=(a^b)&mask, addr2=(c^d)&mask;
        uint64_t v1=pad[addr1], v2=pad[addr2];
        switch(v1&3){
            case 0: a=a+v1; a=rotl64(a,(int)((v1>>6)&63)); break;
            case 1: a=a^(v1*GOLDEN); break;
            case 2: a=(a-v1)^rotl64(b,(int)(v1&63)); break;
            default:a=a*(v1|1ULL); break; }
        switch(v2&3){
            case 0: c=c+v2; c=rotl64(c,(int)((v2>>6)&63)); break;
            case 1: c=c^(v2*GOLDEN); break;
            case 2: c=(c-v2)^rotl64(d,(int)(v2&63)); break;
            default:c=c*(v2|1ULL); break; }
        b+=c; d+=a; e=rotl64(e^v1^v2,23); a^=v2^e; c^=v1^e;
        pad[addr1]=v1+d+e; pad[addr2]=v2+b+e;
    }
    auto tm1=std::chrono::steady_clock::now();
    if(prof){ prof->fill_ns+=std::chrono::duration<double,std::nano>(tf1-tf0).count();
              prof->mix_ns +=std::chrono::duration<double,std::nano>(tm1-tm0).count(); prof->n++; }

    uint8_t fin[64];
    memcpy(fin,&a,8);memcpy(fin+8,&b,8);memcpy(fin+16,&c,8);memcpy(fin+24,&d,8);memcpy(fin+32,&e,8);
    uint64_t s0=pad[a&mask],s1=pad[c&mask],s2=pad[e&mask];
    memcpy(fin+40,&s0,8);memcpy(fin+48,&s1,8);memcpy(fin+56,&s2,8);
    blake2b(out,32,fin,64);
}

// ---- harness ----
static const size_t   DEF_PAD_WORDS=524288;   // 4 MB
static const uint64_t DEF_ITER=262144;        // 2^18 dual-lane
static bool is_pow2(size_t x){return x&&!(x&(x-1));}
static size_t mb_to_words(int mb){ if(mb<=0||!is_pow2((size_t)mb))return 0; return (size_t)mb*1024*1024/8; }

static uint64_t timed_bench(int threads,int seconds,size_t pad_words,uint64_t iter){
    std::atomic<uint64_t> total{0}; std::atomic<bool> stop{false};
    auto worker=[&](){ uint64_t* pad=(uint64_t*)malloc(pad_words*8); uint8_t h[32];
        const char* hdr="CoreHash-v2-benchmark-header-000"; uint64_t n=0,local=0;
        while(!stop.load(std::memory_order_relaxed)){ corehash((const uint8_t*)hdr,strlen(hdr),n++,h,pad,pad_words,iter);
            if((++local&15)==0){ total.fetch_add(16,std::memory_order_relaxed); local=0; } }
        total.fetch_add(local,std::memory_order_relaxed); free(pad); };
    std::vector<std::thread> pool; for(int i=0;i<threads;i++) pool.emplace_back(worker);
    std::this_thread::sleep_for(std::chrono::seconds(seconds)); stop.store(true);
    for(auto& t:pool) t.join(); return total.load();
}
static void print_vector(size_t pad_words,uint64_t iter){
    uint64_t* pad=(uint64_t*)malloc(pad_words*8); uint8_t h[32];
    const char* hdr="CoreHash-v2-testvector";
    corehash((const uint8_t*)hdr,strlen(hdr),0,h,pad,pad_words,iter);
    printf("Test vector (pad=%zuMB iter=%llu nonce=0): ",(pad_words*8)/(1024*1024),(unsigned long long)iter);
    for(int i=0;i<32;i++) printf("%02x",h[i]); printf("\n"); free(pad);
}
static void usage(const char* p){
    printf("Usage:\n  %s bench   <threads> <seconds> [padMB=4] [iterK=256]\n",p);
    printf("  %s profile <hashes>  [padMB=4] [iterK=256]\n",p);
    printf("  %s sweep   [seconds=3]\n  %s vector  [padMB=4] [iterK=256]\n",p,p);
}
int main(int argc,char** argv){
    const char* prog="corehash_bench"; std::string cmd=(argc>1)?argv[1]:"bench";
    bool legacy=(argc>1)&&(atoi(argv[1])>0||strcmp(argv[1],"0")==0); if(legacy)cmd="bench";
    int base=legacy?0:1;
    if(cmd=="sweep"){
        int seconds=(argc>2)?atoi(argv[2]):3;
        printf("CoreHash v2 | single-thread scratchpad sweep (iter=%lluK, %ds each)\n",(unsigned long long)(DEF_ITER/1024),seconds);
        printf("%-8s %-12s %s\n","padMB","H/s","notes");
        for(int mb:{1,2,4,8}){ size_t w=mb_to_words(mb); uint64_t hh=timed_bench(1,seconds,w,DEF_ITER);
            printf("%-8d %-12.1f %s\n",mb,(double)hh/seconds,(mb<=4)?"fits 2500K L3":"spills on 2500K"); }
        return 0;
    }
    if(cmd=="profile"){
        int hashes=(argc>base+1)?atoi(argv[base+1]):200; int padMB=(argc>base+2)?atoi(argv[base+2]):4;
        uint64_t iter=(argc>base+3)?(uint64_t)atoi(argv[base+3])*1024:DEF_ITER;
        size_t w=mb_to_words(padMB); if(!w){printf("padMB must be power of two\n");return 1;}
        uint64_t* pad=(uint64_t*)malloc(w*8); uint8_t h[32]; const char* hdr="CoreHash-v2-profile"; PhaseProf pr;
        for(int i=0;i<hashes;i++) corehash((const uint8_t*)hdr,strlen(hdr),i,h,pad,w,iter,&pr);
        double fill=pr.fill_ns/pr.n/1e6, mix=pr.mix_ns/pr.n/1e6;
        printf("Phase breakdown (pad=%dMB iter=%lluK, %llu hashes):\n",padMB,(unsigned long long)(iter/1024),(unsigned long long)pr.n);
        printf("  fill (AES-NI,   compute):        %.3f ms  (%.1f%%)\n",fill,100*fill/(fill+mix));
        printf("  mix  (dual-lane, latency-bound): %.3f ms  (%.1f%%)\n",mix,100*mix/(fill+mix));
        printf("  total: %.3f ms/hash -> %.1f H/s/thread\n",fill+mix,1000.0/(fill+mix)); free(pad); return 0;
    }
    if(cmd=="vector"){
        int padMB=(argc>base+1)?atoi(argv[base+1]):4; uint64_t iter=(argc>base+2)?(uint64_t)atoi(argv[base+2])*1024:DEF_ITER;
        size_t w=mb_to_words(padMB); if(!w){printf("padMB must be power of two\n");return 1;} print_vector(w,iter); return 0;
    }
    if(cmd=="bench"){
        int threads=(argc>base+1)?atoi(argv[base+1]):1; int seconds=(argc>base+2)?atoi(argv[base+2]):5;
        int padMB=(argc>base+3)?atoi(argv[base+3]):4; uint64_t iter=(argc>base+4)?(uint64_t)atoi(argv[base+4])*1024:DEF_ITER;
        if(threads<1)threads=1; size_t w=mb_to_words(padMB); if(!w){printf("padMB must be power of two\n");return 1;}
        printf("CoreHash v2 | scratchpad=%dMB iterations=%lluK threads=%d\n",padMB,(unsigned long long)(iter/1024),threads);
        print_vector(w,iter); printf("\n");
        uint64_t hh=timed_bench(threads,seconds,w,iter); double hs=(double)hh/seconds;
        printf("Hashes: %llu | Hashrate: %.1f H/s (%.1f H/s per thread)\n",(unsigned long long)hh,hs,hs/threads); return 0;
    }
    usage(prog); return 1;
}
