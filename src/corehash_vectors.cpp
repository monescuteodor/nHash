// Prints authoritative CoreHash v2 test vectors for the specification.
#include "corehash.h"
#include <cstdio>
#include <cstring>
using namespace ch;
static void pv(const char* label, const uint8_t* in, size_t len){
    CoreHashCtx ctx; uint8_t o[32]; corehash(in,len,o,ctx);
    printf("  %-16s (%2zu bytes) -> ",label,len); for(int i=0;i<32;i++)printf("%02x",o[i]); printf("\n");
}
int main(){
    pv("empty",(const uint8_t*)"",0);
    pv("\"abc\"",(const uint8_t*)"abc",3);
    const char* s="CoreHash-v2"; pv("\"CoreHash-v2\"",(const uint8_t*)s,strlen(s));
    uint8_t z80[80]={0}; pv("80 zero bytes",z80,80);
    return 0;
}
