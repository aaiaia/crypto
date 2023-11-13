#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "arith/arith_core.h"

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

ReturnType mul_u31(ntype_s* d, ntype_s* s1, ntype_s* s0) {
    if(((d->length) >= ((s1->length)<<1U)) && ((d->length) >= ((s0->length)<<1U))) {
        // clear destination 'd'
        (void)memset(d->data, 0x0U, d->size);

        ntype_s* tmp = mkNum(d->bits);
        // clear temp 'tmp'
        (void)memset((tmp->data + s0->length), 0x0U, (tmp->size - s0->size));
        (void)memcpy(tmp->data, s0->data, s0->size);

        for(size_t bShft = d->bits; bShft != 0U; bShft--) {
            /* INSERT STATEMENTS */
        }
    } else {
        return E_ERROR_ARGS;
    }
}
