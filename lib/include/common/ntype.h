#include <stdint.h>
#include <stddef.h> // size_t, NULL

#define BNU32  uint32_t
typedef struct {
    size_t  bits;    // bit width length
    size_t  size;    // size
    size_t  nlen;    // type length
    BNU32*  nums;
}bigNumU32s_s;

bigNumU32s_s* mkBigNumU32s(size_t bits);
int rmBitNumU32s(bigNumU32s_s** p);

