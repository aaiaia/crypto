#ifndef UTIL_H
#define UTIL_H

#define UIN_CEIL(n, m)  ((n/m)+(((n%m)!=0u)?(1u):(0u)))
#define INT_CEIL(n, m)  ((n/m)+(((n%m)!=0)?(1):(0)))

#define LASTBITMASK(bits, TYPE) ((TYPE)(-1)>>(sizeof(TYPE)<<3UL)-(bits%(sizeof(TYPE)<<3UL)))
#define BIT2SIZE(bits)  ((bits>>3u)+(((bits&0x7u)!=0x0u)?(1u):(0u)))

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
