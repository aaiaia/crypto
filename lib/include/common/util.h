#define UIN_CEIL(NUM, MOD)  (((NUM)/(MOD))+((((NUM)%(MOD))!=0U)?(1U):(0U)))
#define INT_CEIL(NUM, MOD)  (((NUM)/(MOD))+((((NUM)%(MOD))!=0)?(1):(0)))

#define BITS2SIZE(BITS)     ((BITS>>3U)+((((BITS)&0x7U)!=0x0U)?(1U):(0U)))
#define BYTE2BITS(SIZE)     ((SIZE)<<3U)

#define BYTE2U32L(SIZE)     (((SIZE)>>2U)+((((SIZE)&0x3U)!=0x0U)?(1U):(0U)))
#define U32L2BYTE(U32L)     ((U32L)<<2U)

#define BYTE2U64L(SIZE)     (((SIZE)>>3U)+((((SIZE)&0x7U)!=0x0U)?(1U):(0U)))
#define U64L2BYTE(U64L)     ((U64L)<<3U)
