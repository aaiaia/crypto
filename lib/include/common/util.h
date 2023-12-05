#ifndef UTIL_H
#define UTIL_H

#define UIN_CEIL(n, m)  ((n/m)+(((n%m)!=0u)?(1u):(0u)))
#define INT_CEIL(n, m)  ((n/m)+(((n%m)!=0)?(1):(0)))

#define LASTBITMASK(bits, TYPE) ((TYPE)(-1)>>(sizeof(TYPE)<<3UL)-(bits%(sizeof(TYPE)<<3UL)))
#define BIT_U8_SIZE(bits)   ((bits>>3u)+(((bits&0x07u)!=0x0u)?(1u):(0u)))
#define BIT_U16_SIZE(bits)  ((bits>>3u)+(((bits&0x0Fu)!=0x0u)?(1u):(0u)))
#define BIT_U32_SIZE(bits)  ((bits>>3u)+(((bits&0x1Fu)!=0x0u)?(1u):(0u)))
#define BIT_U64_SIZE(bits)  ((bits>>6u)+(((bits&0x3Fu)!=0x0u)?(1u):(0u)))
#define U16_SIZE(size)  ((size&(~0x1U))+(((size & 0x1U)!=0U)?(2U):(0U)))
#define U32_SIZE(size)  ((size&(~0x3U))+(((size & 0x3U)!=0U)?(4U):(0U)))
#define U64_SIZE(size)  ((size&(~0x7U))+(((size & 0x7U)!=0U)?(8U):(0U)))

#define MACRO_test_print_ntype(p, title) {                              \
    printf("ntype addr:0x%p, NTYPE size:%lu\r\n", (p), sizeof(NTYPE));  \
    printf("[%s]\r\n", (title));                                        \
    for(size_t i = (p)->length- 1u; i != ((size_t)-1); i--) {           \
        printf("0x%08x", (p)->data[i]);                                 \
        if(i != 0u) printf(":");                                        \
        else        printf("\r\n");                                     \
    }                                                                   \
}
#endif
