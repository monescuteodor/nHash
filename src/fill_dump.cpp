// Dumps authoritative intermediate values so an independent implementation can match the
// AES-NI fill exactly. Prints the seed for input "" and the first 64 scratchpad bytes.
#include "corehash.h"
#include <immintrin.h>
#include <cstdio>
using namespace ch;
int main(){
    uint8_t seed[32]; blake2b(seed,32,(const uint8_t*)"",0);
    printf("seed: "); for(int i=0;i<32;i++) printf("%02x",seed[i]); printf("\n");
    __m128i k0=_mm_loadu_si128((const __m128i*)seed), k1=_mm_loadu_si128((const __m128i*)(seed+16));
    __m128i blk=_mm_xor_si128(k0,k1);
    unsigned char out[64];
    for(int j=0;j<4;j++){ blk=_mm_aesenc_si128(blk,k0); blk=_mm_aesenc_si128(blk,k1); _mm_storeu_si128((__m128i*)(out+16*j),blk); }
    printf("fill[0:64]: "); for(int i=0;i<64;i++) printf("%02x",out[i]); printf("\n");
    return 0;
}
