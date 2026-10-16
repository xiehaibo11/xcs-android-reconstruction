#include "go_byte_primitives.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
    uint64_t count=123;int64_t index=123;unsigned checks=0;
    assert(xcs_count_slice(NULL,0,0,0,255,&count)==0 && count==0);checks++;
    assert(xcs_index_slice(NULL,0,0,0,255,&index)==0 && index==-1);checks++;
    assert(xcs_index_padded_slice(NULL,0,0,0,255,&index)==0 && index==-1);checks++;
    uint8_t sample[8]={0};
    assert(xcs_count_slice(sample,8,9,0,0,&count)==XCS_INVALID_RANGE);checks++;
    assert(xcs_index_slice(sample,8,1,SIZE_MAX,0,&index)==XCS_INVALID_RANGE);checks++;
    assert(xcs_count_slice(sample,8,0,0,256,&count)==XCS_INVALID_ARGUMENT);checks++;
    assert(xcs_index_slice(sample,8,0,0,UINT_MAX,&index)==XCS_INVALID_ARGUMENT);checks++;
    assert(xcs_count_slice(NULL,1,0,1,0,&count)==XCS_INVALID_ARGUMENT);checks++;
    assert(xcs_index_slice(NULL,0,1,0,0,&index)==XCS_INVALID_ARGUMENT);checks++;
    assert(xcs_count_slice(sample,8,0,8,0,NULL)==XCS_INVALID_ARGUMENT);checks++;
    assert(xcs_index_slice(sample,8,0,8,0,NULL)==XCS_INVALID_ARGUMENT);checks++;
    /* Exact malloc spans let AddressSanitizer catch even a one-byte over-read. */
    for(size_t n=1;n<=4097;n++) {
        uint8_t *p=malloc(n);assert(p);memset(p,0xa5,n);p[n-1]=0x5a;
        assert(xcs_count_slice(p,n,0,n,0xa5,&count)==0 && count==n-1);checks++;
        assert(xcs_index_slice(p,n,0,n,0x5a,&index)==0 && index==(int64_t)n-1);checks++;
        assert(xcs_index_slice(p,n,0,n,0x31,&index)==0 && index==-1);checks++;
        free(p);
    }
    long page=sysconf(_SC_PAGESIZE);assert(page>0);
    uint8_t *mapping=mmap(NULL,(size_t)page*3,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);
    assert(mapping!=MAP_FAILED);uint8_t *p=mapping+page;
    assert(mprotect(p,(size_t)page,PROT_READ|PROT_WRITE)==0);memset(p,0x11,(size_t)page);
    for(size_t n=1;n<=129;n++) {
        for(unsigned side=0;side<2;side++) {
            size_t off=side ? (size_t)page-n : 0;
            assert(xcs_count_slice(p,(size_t)page,off,n,0x11,&count)==0 && count==n);checks++;
            assert(xcs_index_slice(p,(size_t)page,off,n,0x22,&index)==0 && index==-1);checks++;
            assert(xcs_index_padded_slice(p,(size_t)page,off,n,0x22,&index)==0 && index==-1);checks++;
        }
    }
    /* Explicitly reject the original algorithm's missing aligned padding. */
    assert(xcs_index_padded_slice(p+1,1,0,1,0x11,&index)==XCS_NEEDS_PADDING);checks++;
    assert(xcs_index_padded_slice(p,1,0,1,0x11,&index)==XCS_NEEDS_PADDING);checks++;
    assert(munmap(mapping,(size_t)page*3)==0);
    printf("{\"status\":\"PASS\",\"backend\":\"%s\",\"checks\":%u}\n",xcs_byte_backend(),checks);
    return 0;
}
