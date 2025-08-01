#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "bignum/bignum_math.h"
#include "bignum/bignum_logic.h"

bignum_t add_bignum(bignum_s* d, bignum_s* s1, bignum_s* s0, bignum_t c) {
    for(size_t i=0ul; i<d->nlen; i++) {
        bignum_t _s0, _s1;
        _s0 = s0->nums[i] + c;
        c = (_s0 < s0->nums[i]);
        _s1 = _s0 + s1->nums[i];
        c |= (_s1 < _s0);
        d->nums[i] = _s1;
    }
    return c;
}

bignum_t sub_bignum(bignum_s* d, bignum_s* s1, bignum_s* s0, bignum_t c) {
    for(size_t i=0UL; i<d->nlen; i++) {
        bignum_t _s0, _s1;
        _s0 = s0->nums[i] - c;
        c = (_s0 > s0->nums[i]);
        _s1 = _s0 - s1->nums[i];
        c |= (_s1 > _s0);
        d->nums[i] = _s1;
    }
    return c;
}

#define MACRO_MULTIPLIER_COMMON_OPEN(D, S1, S0, T) { \
    /* clear destination */ \
    (void)memset((D)->nums, 0x0U, (D)->size); \
    (T) = mkBigNum((D)->bits); \
    /* clear temp '(T)' */ \
    (void)memset(((T)->nums + (S0)->nlen), 0x0U, ((T)->size - (S0)->size)); \
    (void)memcpy((T)->nums, (S0)->nums, s0->size); \
}

#define MACRO_MULTIPLIER_COMMON_CLOSE(D, S1, S0, T) { \
    rmBitNum(&(T)); \
}
// idea notes.
// s0 accumulates then shift left
// s1 checks inclease nums index and shift likes bit witth
ReturnType mul_bignum_bs_ext(bignum_s* d, bignum_s* s1, bignum_s* s0, bool guard) {
    if((d != NULL) && (s1 != NULL) && (s0 != NULL)) {
        if((d->nlen) >= (s1->nlen + s0->nlen) || (!guard)) {
            bignum_s* tmp;
            MACRO_MULTIPLIER_COMMON_OPEN(d, s1, s0, tmp);

#if 1   /* IMPL_BIT_SHIFT_MULTIPLIER */
            size_t nSftBit = s0->bits;
            for(size_t i = 0U; i < s1->nlen; i++) {
                size_t sftBit = (nSftBit >= bignum_bits)?(bignum_bits):(nSftBit);
                for(size_t sft = 0U; sft < sftBit; sft++) {
                    if(((s1->nums[i] >> sft) & 0x1U) != 0x0u) {
                        add_bignum(d, d, tmp, 0U);
                    } else { /* Do nothing */}
                    lsl1b_bignum(tmp, NULL, 0U);
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

bignum_t add_bignum_loc(bignum_s* d, bignum_t v, size_t loc) {
    bignum_t s;
    bignum_t c = v;
    for(size_t i = loc; i < d->nlen; i++) {
        s = d->nums[i] + c;
        c = (s < d->nums[i]);
        d->nums[i] = s;
        if(c != 0UL) {
            continue;
        }
        else {
            break;
        }
    }
    return c;
}
