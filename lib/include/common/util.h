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

#define BITS2SIZE_REM(BITS)     ((BITS)&0x7U)
#define BITS2SIZE_FLOOR(BITS)   (BITS>>3U)
#define BITS2SIZE_CEIL(BITS)    (BITS2SIZE_FLOOR(BITS)+((BITS2SIZE_REM(BITS)!=0x0U)?(1U):(0U)))
#define BITS2SIZE(BITS)         BITS2SIZE_CEIL(BITS)
#define BYTE2BITS(SIZE)         ((SIZE)<<3U)

#define REMBITU16(bits)         (bits&0x0Fu)
#define QUOBITU16(bits)         (bits>>4u)
#define BIT2U16L_REM(bits)      REMBITU16(bits)
#define BIT2U16L_FLOOR(bits)    QUOBITU16(bits)
#define BIT2U16L_CEIL(bits)     (BIT2U16L_FLOOR(bits)+((BIT2U16L_REM(bits)!=0x0u)?(1u):(0u)))
#define BIT2U16L(bits)          BIT2U16L_CEIL(bits)
#define U16L2BIT(U16L)          (U16L<<4u)
#define BYTE2U16L_REM(SIZE)     ((SIZE)&0x1U)
#define BYTE2U16L_FLOOR(SIZE)   ((SIZE)>>1U)
#define BYTE2U16L_CEIL(SIZE)    (BYTE2U16L_FLOOR(SIZE)+((BYTE2U16L_REM(SIZE)!=0x0U)?(1U):(0U)))
#define BYTE2U16L(SIZE)         BYTE2U16L_CEIL(SIZE)
#define U16L2BYTE(U16L)         ((U16L)<<1U)

#define REMBITU32(bits)         (bits&0x1Fu)
#define QUOBITU32(bits)         (bits>>5u)
#define BIT2U32L_REM(bits)      REMBITU32(bits)
#define BIT2U32L_FLOOR(bits)    QUOBITU32(bits)
#define BIT2U32L_CEIL(bits)     (BIT2U32L_FLOOR(bits)+((BIT2U32L_REM(bits)!=0x0u)?(1u):(0u)))
#define BIT2U32L(bits)          BIT2U32L_CEIL(bits)
#define U32L2BIT(U32L)          (U32L<<5u)
#define BYTE2U32L_REM(SIZE)     ((SIZE)&0x3U)
#define BYTE2U32L_FLOOR(SIZE)   ((SIZE)>>2U)
#define BYTE2U32L_CEIL(SIZE)    (BYTE2U32L_FLOOR(SIZE)+((BYTE2U32L_REM(SIZE)!=0x0U)?(1U):(0U)))
#define BYTE2U32L(SIZE)         BYTE2U32L_CEIL(SIZE)
#define U32L2BYTE(U32L)         ((U32L)<<2U)

#define REMBITU64(bits)         (bits&0x3Fu)
#define QUOBITU64(bits)         (bits>>6u)
#define BIT2U64L_REM(bits)      REMBITU64(bits)
#define BIT2U64L_FLOOR(bits)    QUOBITU64(bits)
#define BIT2U64L_CEIL(bits)     (BIT2U64L_REM(bits)+((BIT2U64L_REM(bits)!=0x0u)?(1u):(0u)))
#define BIT2U64L(bits)          BIT2U64L_CEIL(bits)    
#define U64L2BIT(U64L)          (U64L<<6u)
#define BYTE2U64L_REM(SIZE)     ((SIZE)&0x7U)
#define BYTE2U64L_FLOOR(SIZE)   ((SIZE)>>3U)
#define BYTE2U64L_CEIL(SIZE)    (BYTE2U64L_FLOOR(SIZE)+((BYTE2U64L_REM(SIZE)!=0x0U)?(1U):(0U)))
#define BYTE2U64L(SIZE)         BYTE2U64L_CEIL(SIZE) 
#define U64L2BYTE(U64L)         ((U64L)<<3U)

#endif/* UTIL_H */
