#include "go_byte_primitives.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static uint64_t number(FILE *f,unsigned bytes) {
    uint64_t value=0;for(unsigned i=0;i<bytes;i++){int c=fgetc(f);assert(c!=EOF);value=(value<<8)|(unsigned)c;}return value;
}
int main(int argc,char **argv) {
    assert(argc==2);FILE *f=fopen(argv[1],"rb");assert(f);
    char magic[8];assert(fread(magic,1,8,f)==8 && !memcmp(magic,"XCSSIMD3",8));
    unsigned cases=(unsigned)number(f,4);
    for(unsigned k=0;k<cases;k++) {
        size_t size=(size_t)number(f,4),off=(size_t)number(f,4),len=(size_t)number(f,4);unsigned target=(unsigned)number(f,4);
        uint8_t *allocation=malloc(size+32);assert(allocation);uint8_t *p=(uint8_t *)(((uintptr_t)allocation+31)&~(uintptr_t)31);
        assert(fread(p,1,size,f)==size);
        uint64_t wanted_count=number(f,8),wanted_index_bits=number(f,8),count;
        int64_t index,padded;int64_t wanted_index=wanted_index_bits==UINT64_MAX ? -1 : (int64_t)wanted_index_bits;
        assert(xcs_count_slice(p,size,off,len,target,&count)==0 && count==wanted_count);
        assert(xcs_index_slice(p,size,off,len,target,&index)==0 && index==wanted_index);
        assert(xcs_index_padded_slice(p,size,off,len,target,&padded)==0 && padded==wanted_index);
        free(allocation);
    }
    assert(fgetc(f)==EOF);fclose(f);
    printf("{\"c_status\":\"PASS\",\"backend\":\"%s\",\"fixture_inputs\":%u,\"result_checks\":%u}\n",xcs_byte_backend(),cases,cases*3);
}
