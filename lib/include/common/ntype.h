#ifndef BTYPE_H
#define BTYPE_H

#include <stdint.h>

#define NTYPE       uint32_t
#define BITPERBYTE  8u

typedef struct {
    NTYPE* data;
    size_t bits;
    size_t length;
    size_t size;
}ntype_s;

ntype_s* mkNum(size_t bits);
int rmNum(ntype_s** p);

#endif
