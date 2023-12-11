#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "arith/arith_core.h"
#include "logic/logic_core.h"

NTYPE add_NTYPE(ntype_s* d, ntype_s* s1, ntype_s* s0, NTYPE c) {
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

NTYPE sub_NTYPE(ntype_s* d, ntype_s* s1, ntype_s* s0, NTYPE c) {
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

#define MACRO_MULTIPLIER_COMMON_OPEN(D, S1, S0, T) {                            \
    /* clear destination */                                                     \
    (void)memset((D)->data, 0x0U, (D)->size);                                   \
    (T) = mkNum((D)->bits);                                                     \
    /* clear temp '(T)' */                                                      \
    (void)memset(((T)->data + (S0)->length), 0x0U, ((T)->size - (S0)->size));   \
    (void)memcpy((T)->data, (S0)->data, s0->size);                              \
}

#define MACRO_MULTIPLIER_COMMON_CLOSE(D, S1, S0, T) {   \
    rmNum(&(T));                                        \
}
// idea notes.
// s0 accumulates then shift left
// s1 checks inclease data index and shift likes bit witth
ReturnType mul_NTYPE_bs_ext(ntype_s* d, ntype_s* s1, ntype_s* s0, bool guard) {
    if((d != NULL) && (s1 != NULL) && (s0 != NULL)) {
        if((d->length) >= (s1->length + s0->length) || (!guard)) {
            ntype_s* tmp;
            MACRO_MULTIPLIER_COMMON_OPEN(d, s1, s0, tmp);

#if 1   /* IMPL_BIT_SHIFT_MULTIPLIER */
            size_t nSftBit = s0->bits;
            for(size_t i = 0U; i < s1->length; i++) {
                size_t sftBit = (nSftBit >= NTYPE_BITS)?(NTYPE_BITS):(nSftBit);
                for(size_t sft = 0U; sft < sftBit; sft++) {
                    if(((s1->data[i] >> sft) & 0x1U) != 0x0u) {
                        add_NTYPE(d, d, tmp, 0U);
                    } else { /* Do nothing */}
                    sftL1b(tmp, NULL, 0U);
                }
                nSftBit-=sftBit;
            }
#endif  /* IMPL_BIT_SHIFT_MULTIPLIER */
            MACRO_MULTIPLIER_COMMON_CLOSE(d, s1, s0, tmp);

#if 1   /* IMPL_BIT_SHIFT_MULTIPLIER */
            if(nSftBit != 0U) {
                return E_ERROR_RUNTIME;
            } else { /* Do nothing */ }
#endif  /* IMPL_BIT_SHIFT_MULTIPLIER */
        } else {
            return E_ERROR_ARGS;
        }
    } else {
        return E_ERROR_NULL;
    }
    return E_OK;
}

NTYPE add_NTYPE_loc(ntype_s* d, NTYPE v, size_t loc) {
    NTYPE s;
    NTYPE c = v;
    for(size_t i = loc; i < d->length; i++) {
        s = d->data[i] + c;
        c = (s < d->data[i]);
        d->data[i] = s;
        if(c != 0UL) {
            continue;
        }
        else {
            break;
        }
    }
    return c;
}
