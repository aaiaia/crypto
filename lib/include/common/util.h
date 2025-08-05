#ifndef UTIL_H
#define UTIL_H

#define MACRO_test_print_bignum(p, title) {                              \
    printf("bignum addr:0x%p, bignum_t size:%lu\r\n", (p), sizeof(bignum_t));  \
    printf("[%s]\r\n", (title));                                        \
    for(size_t i = (p)->length- 1u; i != ((size_t)-1); i--) {           \
        printf("0x%08x", (p)->data[i]);                                 \
        if(i != 0u) printf(":");                                        \
        else        printf("\r\n");                                     \
    }                                                                   \
}
#define UIN_CEIL(NUM, MOD)  (((NUM)/(MOD))+((((NUM)%(MOD))!=0U)?(1U):(0U)))
#define INT_CEIL(NUM, MOD)  (((NUM)/(MOD))+((((NUM)%(MOD))!=0)?(1):(0)))

#define LASTBITMASK(bits, TYPE) ((TYPE)(-1)>>(sizeof(TYPE)<<3UL)-(bits%(sizeof(TYPE)<<3UL)))

#define BITS2SIZE(BITS)     ((BITS>>3U)+((((BITS)&0x7U)!=0x0U)?(1U):(0U)))
#define BYTE2BITS(SIZE)     ((SIZE)<<3U)

#define BIT2U16L(bits)      ((bits>>4u)+(((bits&0x0Fu)!=0x0u)?(1u):(0u)))
#define U16L2BIT(U16L)      (U16L<<4u)
#define BYTE2U16L(SIZE)     (((SIZE)>>1U)+((((SIZE)&0x1U)!=0x0U)?(1U):(0U)))
#define U16L2BYTE(U16L)     ((U16L)<<1U)

#define BIT2U32L(bits)      ((bits>>5u)+(((bits&0x1Fu)!=0x0u)?(1u):(0u)))
#define U32L2BIT(U32L)      (U32L<<5u)
#define BYTE2U32L(SIZE)     (((SIZE)>>2U)+((((SIZE)&0x3U)!=0x0U)?(1U):(0U)))
#define U32L2BYTE(U32L)     ((U32L)<<2U)

#define BIT2U64L(bits)      ((bits>>6u)+(((bits&0x3Fu)!=0x0u)?(1u):(0u)))
#define U64L2BIT(U64L)      (U64L<<6u)
#define BYTE2U64L(SIZE)     (((SIZE)>>3U)+((((SIZE)&0x7U)!=0x0U)?(1U):(0U)))
#define U64L2BYTE(U64L)     ((U64L)<<3U)

#endif/* UTIL_H */
