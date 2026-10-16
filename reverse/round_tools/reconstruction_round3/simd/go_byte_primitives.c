#include "go_byte_primitives.h"
#include <limits.h>

#if defined(__aarch64__) && defined(__ARM_NEON) && !defined(XCS_FORCE_SCALAR) \
    && defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#include <arm_neon.h>
#define XCS_NEON 1
#else
#define XCS_NEON 0
#endif

const char *xcs_byte_backend(void) { return XCS_NEON ? "arm64-neon" : "portable-c"; }

static int check_slice(const uint8_t *p, size_t size, size_t off, size_t len,
                       unsigned target, const void *result) {
    if (!result || target > 255 || (!p && (size || off || len)))
        return XCS_INVALID_ARGUMENT;
    if (off > size || len > size-off || len > INT64_MAX)
        return XCS_INVALID_RANGE;
    return XCS_OK;
}

/* Each source byte occupies two bits of the 64-bit mask, as at 0x5b318..0x5b35c.
 * Every load is from a complete caller-provided 32-byte block. */
static uint64_t match_bits(const uint8_t *p, uint8_t target) {
#if XCS_NEON
    const uint8x16_t needle = vdupq_n_u8(target);
    const uint8x16_t weights = vreinterpretq_u8_u32(vdupq_n_u32(UINT32_C(0x40100401)));
    uint8x16_t a = vandq_u8(vceqq_u8(vld1q_u8(p), needle), weights);
    uint8x16_t b = vandq_u8(vceqq_u8(vld1q_u8(p+16), needle), weights);
    uint8x16_t pairs = vpaddq_u8(a,b);
    pairs = vpaddq_u8(pairs,pairs);
    return vgetq_lane_u64(vreinterpretq_u64_u8(pairs),0);
#else
    uint64_t bits=0;
    for (unsigned i=0;i<32;i++)
        if (p[i]==target) bits |= UINT64_C(1)<<(2*i);
    return bits;
#endif
}

/* Only used with a nonzero mask. This is RBIT+CLZ divided by two in the APK. */
static unsigned first_match(uint64_t bits) {
    unsigned n=0;
    while (!(bits & 1)) {bits>>=1;n++;}
    return n/2;
}

int xcs_count_slice(const uint8_t *storage, size_t size, size_t off,
                    size_t len, unsigned target, uint64_t *result) {
    int error=check_slice(storage,size,off,len,target,result);
    if (error) return error;
    uint64_t total=0;
    if (!len) {*result=0;return XCS_OK;}
    const uint8_t *p=storage+off;
    /* Same count prefix/full-block/tail partition as 0x5aea0..0x5af34. */
    while (len && ((uintptr_t)p & 31)) {total+=(*p++==target);len--;}
    while (len>=32) {
#if XCS_NEON
        uint8x16_t needle=vdupq_n_u8((uint8_t)target);
        uint8x16_t ones=vdupq_n_u8(1);
        uint8x16_t a=vandq_u8(vceqq_u8(vld1q_u8(p),needle),ones);
        uint8x16_t b=vandq_u8(vceqq_u8(vld1q_u8(p+16),needle),ones);
        total+=vaddlvq_u8(vpaddq_u8(a,b));
#else
        for(unsigned i=0;i<32;i++) total+=(p[i]==target);
#endif
        p+=32;len-=32;
    }
    while (len) {total+=(*p++==target);len--;}
    *result=total;
    return XCS_OK;
}

int xcs_index_slice(const uint8_t *storage, size_t size, size_t off,
                    size_t len, unsigned target, int64_t *result) {
    int error=check_slice(storage,size,off,len,target,result);
    if(error) return error;
    *result=-1;
    if(!len) return XCS_OK;
    const uint8_t *p=storage+off;
    size_t i=0;
    /* Bounded replacement: handle partial blocks without original over-reads. */
    while(i<len && ((uintptr_t)(p+i)&31)) {
        if(p[i]==target) {*result=(int64_t)i;return XCS_OK;}
        i++;
    }
    while(len-i>=32) {
        uint64_t bits=match_bits(p+i,(uint8_t)target);
        if(bits) {*result=(int64_t)(i+first_match(bits));return XCS_OK;}
        i+=32;
    }
    while(i<len) {
        if(p[i]==target) {*result=(int64_t)i;return XCS_OK;}
        i++;
    }
    return XCS_OK;
}

int xcs_index_padded_slice(const uint8_t *storage, size_t size, size_t off,
                          size_t len, unsigned target, int64_t *result) {
    int error=check_slice(storage,size,off,len,target,result);
    if(error) return error;
    if(!len) {*result=-1;return XCS_OK;}
    uintptr_t base=(uintptr_t)storage;
    if(size>UINTPTR_MAX-base) return XCS_INVALID_RANGE;
    uintptr_t begin=base+off, end=begin+len;
    uintptr_t block=begin & ~(uintptr_t)31;
    uintptr_t last=(end-1) & ~(uintptr_t)31;
    if(block<base || last>UINTPTR_MAX-32 || last+32>base+size)
        return XCS_NEEDS_PADDING;
    *result=-1;
    for (;;) {
        uint64_t bits=match_bits((const uint8_t *)block,(uint8_t)target);
        if(block<begin) bits &= UINT64_MAX << (2*(begin-block));
        if(block==last && end-block<32)
            bits &= (UINT64_C(1) << (2*(end-block)))-1;
        if(bits) {
            *result=(int64_t)((block+first_match(bits))-begin);
            return XCS_OK;
        }
        if(block==last) return XCS_OK;
        block+=32;
    }
}
