#ifndef BTYPE_H
#define BTYPE_H

#include <stdint.h>

#define NTYPE       uint32_t
#define BITPERBYTE  8u

typedef struct {
    NTYPE* array;
    size_t bitLen;
    size_t size;
}ntype_s;

ntype_s* mkNum(size_t bitLen);
int rmNum(ntype_s** p);

#endif
