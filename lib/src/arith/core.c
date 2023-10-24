#include <stdlib.h>
#include <stdint.h>

#include "arith/core.h"

NTYPE add_u32(NTYPE* d, NTYPE* s1, NTYPE* s0, size_t len, NTYPE c) {
    for(size_t i=0ul; i<len; i++) {
        NTYPE s;
        s = s0[i] + c;
        c = (s < s0[i]);
        s += s1[i];
        c |= (s < s1[i]);
        d[i] = s;
    }
    return c;
}

