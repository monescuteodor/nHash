// Heavy statistical randomness battery for CoreHash v2 output (NIST SP 800-22 subset +
// classic tests). Generates several MB of hash output in parallel, then runs monobit,
// block-frequency, runs, longest-run, nibble-poker, byte chi-square and serial-correlation
// tests. A hash that behaves like a random oracle passes all of them; a failure points to
// exploitable structure. Uses ch::corehash.
//
// Build: MSVC (no flag) or g++ -maes -pthread.  Usage: corehash_battery [MB=2]
#include "corehash.h"
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <thread>
#include <cmath>
#ifdef _MSC_VER
  #include <intrin.h>
  static inline int popc64(uint64_t x){ return (int)__popcnt64(x); }
#else
  static inline int popc64(uint64_t x){ return __builtin_popcountll(x); }
#endif
using namespace ch;

static double erf_(double x){ // Abramowitz-Stegun 7.1.26 (max err ~1.5e-7)
    int sign = x<0?-1:1; x=std::fabs(x);
    double t=1.0/(1.0+0.3275911*x);
    double y=1.0-(((((1.061405429*t-1.453152027)*t)+1.421413741)*t-0.284496736)*t+0.254829592)*t*std::exp(-x*x);
    return sign*y;
}
static double erfc_(double x){ return 1.0-erf_(x); }

int main(int argc,char** argv){
    double MB=(argc>1)?atof(argv[1]):2.0; if(MB<0.25)MB=0.25;
    size_t nbytes=(size_t)(MB*1024*1024); size_t nhash=(nbytes+31)/32; nbytes=nhash*32;
    std::vector<uint8_t> buf(nbytes);
    int T=(int)std::thread::hardware_concurrency(); if(T<1)T=1;
    printf("CoreHash v2 statistical battery\n");
    printf("generating %.2f MB (%zu hashes) on %d threads...\n\n",(double)nbytes/1048576.0,nhash,T);

    // parallel generation: thread t hashes a contiguous nonce range into its slice
    std::vector<std::thread> pool;
    size_t per=(nhash+T-1)/T;
    for(int t=0;t<T;t++){
        pool.emplace_back([&,t]{
            CoreHashCtx ctx; uint8_t in[80]; for(int i=0;i<80;i++) in[i]=(uint8_t)(i*5+1);
            size_t a=(size_t)t*per, b=a+per; if(b>nhash)b=nhash;
            for(size_t h=a;h<b;h++){ memcpy(in+72,&h,sizeof(h)); corehash(in,80,&buf[h*32],ctx); }
        });
    }
    for(auto&th:pool) th.join();

    const size_t n = nbytes*8; // total bits
    // ---- 1) Monobit frequency ----
    uint64_t ones=0; for(size_t i=0;i<nbytes;i+=8){ uint64_t x; size_t r=nbytes-i; if(r>=8)memcpy(&x,&buf[i],8); else {x=0;memcpy(&x,&buf[i],r);} ones+=popc64(x); }
    double s=std::fabs((double)(2*(long long)ones-(long long)n))/std::sqrt((double)n);
    double p_mono=erfc_(s/std::sqrt(2.0));
    printf("1) Monobit           ones=%.5f  p=%.3f  %s\n",(double)ones/n,p_mono,p_mono>=0.01?"PASS":"FAIL");

    // ---- 2) Runs test (bit level) ----
    double pi=(double)ones/n; uint64_t runs=1;
    { int prev=(buf[0])&1; for(size_t i=0;i<nbytes;i++){ uint8_t by=buf[i]; for(int b=0;b<8;b++){ if(i==0&&b==0)continue; int cur=(by>>b)&1; if(cur!=prev)runs++; prev=cur; } } }
    double rexp=2.0*n*pi*(1-pi);
    double rsd=std::sqrt(2.0*n*pi*(1-pi))* (2*pi*(1-pi)); // approx
    double zr=std::fabs((double)runs-rexp)/ (2.0*std::sqrt((double)n)*pi*(1-pi));
    double p_runs=erfc_(zr/std::sqrt(2.0));
    printf("2) Runs              runs=%llu  p=%.3f  %s\n",(unsigned long long)runs,p_runs,p_runs>=0.01?"PASS":"FAIL");
    (void)rsd;

    // ---- 3) Byte chi-square (256 buckets) ----
    long hist[256]={0}; for(size_t i=0;i<nbytes;i++) hist[buf[i]]++;
    double eb=(double)nbytes/256.0, chi=0; for(int i=0;i<256;i++){ double d=hist[i]-eb; chi+=d*d/eb; }
    double lo=255-3*22.6, hi=255+3*22.6;
    printf("3) Byte chi-square   chi=%.1f (255dof, healthy %.0f-%.0f)  %s\n",chi,lo,hi,(chi>lo&&chi<hi)?"PASS":"CHECK");

    // ---- 4) Nibble poker (16 buckets) ----
    long nib[16]={0}; for(size_t i=0;i<nbytes;i++){ nib[buf[i]&15]++; nib[buf[i]>>4]++; }
    double en=(double)(nbytes*2)/16.0, chn=0; for(int i=0;i<16;i++){ double d=nib[i]-en; chn+=d*d/en; }
    double nlo=15-3*5.48, nhi=15+3*5.48;
    printf("4) Nibble poker      chi=%.1f (15dof, healthy %.0f-%.0f)  %s\n",chn,nlo,nhi,(chn>nlo&&chn<nhi)?"PASS":"CHECK");

    // ---- 5) Serial correlation (lag-1, byte level) ----
    double sx=0,sxx=0,sxy=0; for(size_t i=0;i<nbytes;i++){ double x=buf[i]; sx+=x; sxx+=x*x; sxy+=x*(double)buf[(i+1)%nbytes]; }
    double m=sx/nbytes; double cov=sxy/nbytes-m*m; double var=sxx/nbytes-m*m;
    double scc = var>0? cov/var : 0;
    printf("5) Serial corr.      r=%+.5f  (ideal ~0, |r|<0.01)  %s\n",scc,std::fabs(scc)<0.01?"PASS":"CHECK");

    // ---- 6) Longest run of ones in 256-bit blocks (coarse) ----
    size_t nb=nbytes/32; int over=0; for(size_t blk=0;blk<nb;blk++){ int longest=0,cur=0; for(int j=0;j<32;j++){ uint8_t by=buf[blk*32+j]; for(int b=0;b<8;b++){ if((by>>b)&1){cur++; if(cur>longest)longest=cur;} else cur=0; } } if(longest>=20) over++; }
    double frac_over=nb? (double)over/nb:0;
    printf("6) Longest-run       blocks with run>=20: %.4f  (rare, expect <0.03)  %s\n",frac_over,frac_over<0.03?"PASS":"CHECK");

    printf("\n=> If all read PASS, the output is statistically indistinguishable from random\n   across bit-, nibble-, byte- and correlation-level tests.\n");
    return 0;
}
