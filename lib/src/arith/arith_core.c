#include <stdlib.h>
#include <stdint.h>

#include "arith/core.h"

NTYPE add_u32(ntype_s* d, ntype_s* s1, ntype_s* s0, NTYPE c) {
    for(size_t i=0ul; i<d->length; i++) {
        NTYPE s;
        s = s0->data[i] + c;
        c = (s < s0->data[i]);
        s += s1->data[i];
        c |= (s < s1->data[i]);
        d->data[i] = s;
    }
    return c;
}

NTYPE sub_u32(ntype_s* d, ntype_s* s1, ntype_s* s0, NTYPE c) {
    for(size_t i=0UL; i<d->length; i++) {
        NTYPE s;
        s = s0->data[i] - c;
        c = (s > s0->data[i]);
        s -= s1->data[i];
        c |= (s > s1->data[i]);
        d->data[i] = s;
    }
    return c;
}
