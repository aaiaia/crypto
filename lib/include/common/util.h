#define UIN_CEIL(n, m)  ((n/m)+(((n%m)!=0u)?(1u):(0u)))
#define INT_CEIL(n, m)  ((n/m)+(((n%m)!=0)?(1):(0)))

#define LASTBITMASK(bits, TYPE) ((TYPE)(-1)>>(sizeof(TYPE)<<3UL)-(bits%(sizeof(TYPE)<<3UL)))
#define BIT2SIZE(bits)  ((bits>>3u)+(((bits&0x7u)!=0x0u)?(1u):(0u)))
