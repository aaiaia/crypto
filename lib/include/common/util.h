#define UIN_CEIL(n, m)  ((n/m)+(((n%m)!=0u)?(1u):(0u)))
#define INT_CEIL(n, m)  ((n/m)+(((n%m)!=0)?(1):(0)))

#define BIT2SIZE(bits)  ((bits>>3u)+(((bits&0x7u)!=0x0u)?(1u):(0u)))
#define BYTE2BIT(size)  ((size) << 3U)
#define BYTE2WORD(size) ((size) >> 2U) // size of WORD is 32bit
