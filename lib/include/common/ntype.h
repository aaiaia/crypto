#ifndef BTYPE_H
#define BTYPE_H

#include <stdint.h>

#define NTYPE       uint32_t
#define NTYPE_SIZE  8U
#define NTYPE_BITS  32U

typedef struct {
    NTYPE* data;
    NTYPE  lastMask;
    size_t bits;
    size_t length;
    size_t size;
}ntype_s;

ntype_s* mkNum(size_t bits);
int rmNum(ntype_s** p);

#endif
