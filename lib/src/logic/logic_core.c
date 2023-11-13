#include "logic/logic_core.h"

ReturnType sftL1b(ntype_s* d, NTYPE* ovf, NTYPE c) {
    if(d != NULL) {
        for(size_t i = 0U; i < d->length; i++) {
            NTYPE tmp = d->data[i];
            d->data[i] = ((d->data[i] << 1U) | c);
            c = ((tmp >> (NTYPE_BITS-1U)) != 0U)?(1U):(0U);
        }

        if(ovf != NULL) {
            *ovf = c;
        } else { /* Do nothing */ }
    } else {
        return E_ERROR_NULL;
    }
    return E_OK;
}
