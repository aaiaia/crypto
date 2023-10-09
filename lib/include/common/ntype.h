#include <stdint.h>

#define NTYPE       uint32_t
#define BITPERBYTE  8u

typedef struct {
    NTYPE* array;
    uint32_t blen;
    uint32_t alen;
}ntype_s;

ntype_s* mkNum(uint32_t blen);
int rmNum(ntype_s** p);

