// Efficiency experiment: does allocating the 4 MB scratchpad on 2 MB HUGE PAGES speed up
// CoreHash v2? A latency-bound random-access hash suffers TLB misses with 4 KB pages
// (4 MB needs 1024 page-table entries); 2 MB pages need only 2, cutting TLB pressure.
// This is the same trick RandomX uses for a ~20-30% gain, and it lowers hashes-per-watt.
//
// Compares normal (malloc) vs large-page scratchpad, single thread. Windows: large pages
// need the "Lock pages in memory" privilege (SeLockMemoryPrivilege) for your account; if
// absent, the large-page path is skipped and the program says so. Build: MSVC (no flag).
#include "corehash.h"
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <chrono>
#include <immintrin.h>
#ifdef _WIN32
  #include <windows.h>
#endif
using namespace ch;
static const uint64_t GOLDEN=0x9E3779B97F4A7C15ULL;
static inline uint64_t rotl64s(uint64_t x,int n){return (x<<n)|(x>>(64-n));}

static void fill(uint64_t* pad,size_t words,const uint8_t seed[32]){
    __m128i k0=_mm_loadu_si128((const __m128i*)seed),k1=_mm_loadu_si128((const __m128i*)(seed+16));
    __m128i blk=_mm_xor_si128(k0,k1); __m128i* out=(__m128i*)pad; size_t nblk=(words*8)/16;
    for(size_t i=0;i<nblk;i++){ blk=_mm_aesenc_si128(blk,k0); blk=_mm_aesenc_si128(blk,k1); _mm_storeu_si128(out+i,blk); }
}
static void corehash_pad(const uint8_t* in,size_t len,uint64_t nonce,uint8_t out[32],uint64_t* pad){
    const uint64_t mask=COREHASH_PAD_WORDS-1;
    uint8_t buf[128]; size_t hl=len>100?100:len; memcpy(buf,in,hl); memcpy(buf+hl,&nonce,8);
    uint8_t seed[32]; blake2b(seed,32,buf,hl+8);
    fill(pad,COREHASH_PAD_WORDS,seed);
    uint64_t a,b,c,d; memcpy(&a,seed,8);memcpy(&b,seed+8,8);memcpy(&c,seed+16,8);memcpy(&d,seed+24,8);
    uint64_t e=rotl64s(a,17)^rotl64s(b,31)^rotl64s(c,47)^d;
    for(uint64_t i=0;i<COREHASH_ITERS;i++){
        uint64_t a1=(a^b)&mask,a2=(c^d)&mask; uint64_t v1=pad[a1],v2=pad[a2];
        switch(v1&3){case 0:a=a+v1;a=rotl64s(a,(int)((v1>>6)&63));break;case 1:a=a^(v1*GOLDEN);break;
                     case 2:a=(a-v1)^rotl64s(b,(int)(v1&63));break;default:a=a*(v1|1ULL);break;}
        switch(v2&3){case 0:c=c+v2;c=rotl64s(c,(int)((v2>>6)&63));break;case 1:c=c^(v2*GOLDEN);break;
                     case 2:c=(c-v2)^rotl64s(d,(int)(v2&63));break;default:c=c*(v2|1ULL);break;}
        b+=c;d+=a;e=rotl64s(e^v1^v2,23);a^=v2^e;c^=v1^e; pad[a1]=v1+d+e; pad[a2]=v2+b+e;
    }
    uint8_t fin[64]; memcpy(fin,&a,8);memcpy(fin+8,&b,8);memcpy(fin+16,&c,8);memcpy(fin+24,&d,8);memcpy(fin+32,&e,8);
    uint64_t s0=pad[a&mask],s1=pad[c&mask],s2=pad[e&mask]; memcpy(fin+40,&s0,8);memcpy(fin+48,&s1,8);memcpy(fin+56,&s2,8);
    blake2b(out,32,fin,64);
}
static double bench(uint64_t* pad,double secs){
    uint8_t out[32]; const char* h="hugepage-bench"; uint64_t n=0,cnt=0;
    auto t0=std::chrono::steady_clock::now();
    while(std::chrono::duration<double>(std::chrono::steady_clock::now()-t0).count()<secs){ corehash_pad((const uint8_t*)h,strlen(h),n++,out,pad); cnt++; }
    double dt=std::chrono::duration<double>(std::chrono::steady_clock::now()-t0).count();
    return cnt/dt;
}

#ifdef _WIN32
static bool enable_lock_priv(){
    HANDLE tok; if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&tok)) return false;
    LUID luid; if(!LookupPrivilegeValue(NULL,SE_LOCK_MEMORY_NAME,&luid)){CloseHandle(tok);return false;}
    TOKEN_PRIVILEGES tp; tp.PrivilegeCount=1; tp.Privileges[0].Luid=luid; tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    BOOL ok=AdjustTokenPrivileges(tok,FALSE,&tp,sizeof(tp),NULL,NULL);
    bool held = ok && GetLastError()==ERROR_SUCCESS; CloseHandle(tok); return held;
}
static uint64_t* alloc_large(size_t bytes){
    SIZE_T lp=GetLargePageMinimum(); if(lp==0) return nullptr;
    size_t rounded=((bytes+lp-1)/lp)*lp;
    return (uint64_t*)VirtualAlloc(NULL,rounded,MEM_RESERVE|MEM_COMMIT|MEM_LARGE_PAGES,PAGE_READWRITE);
}
static void free_large(uint64_t* p){ if(p) VirtualFree(p,0,MEM_RELEASE); }
#endif

int main(int argc,char** argv){
    double secs=(argc>1)?atof(argv[1]):6.0; if(secs<1)secs=1;
    const size_t bytes=COREHASH_PAD_BYTES;
    printf("CoreHash v2 huge-page efficiency test (single thread, %.0fs each)\n\n",secs);

    uint64_t* normal=(uint64_t*)malloc(bytes);
    double hn=bench(normal,secs);
    printf("normal pages (4 KB) : %.1f H/s\n",hn);
    free(normal);

#ifdef _WIN32
    if(!enable_lock_priv()){
        printf("large pages (2 MB)  : unavailable — account lacks 'Lock pages in memory' privilege.\n");
        printf("   To enable: secpol.msc -> Local Policies -> User Rights Assignment ->\n");
        printf("   'Lock pages in memory' -> add your user -> sign out/in. (xmrig needs the same.)\n");
        return 0;
    }
    uint64_t* large=alloc_large(bytes);
    if(!large){ printf("large pages (2 MB)  : VirtualAlloc(MEM_LARGE_PAGES) failed (privilege/config).\n"); return 0; }
    double hl=bench(large,secs);
    printf("large pages (2 MB)  : %.1f H/s\n",hl);
    free_large(large);
    printf("\nspeedup from huge pages: %.2fx  (%+.0f%%)\n",hl/hn,100.0*(hl/hn-1.0));
#else
    printf("(large-page test is Windows-only in this tool; Linux uses THP/hugetlbfs.)\n");
#endif
    return 0;
}
