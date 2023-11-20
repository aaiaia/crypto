#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "arith/arith_core.h"
#include "logic/logic_core.h"

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

// idea notes.
// s0 accumulates then shift left
// s1 checks inclease data index and shift likes bit witth
ReturnType mul_u32_bs_ext(ntype_s* d, ntype_s* s1, ntype_s* s0, bool guard) {
    if((d != NULL) && (s1 != NULL) && (s0 != NULL)) {
        if((d->length) >= (s1->length + s0->length) || (!guard)) {
            // clear destination 'd'
            (void)memset(d->data, 0x0U, d->size);

            ntype_s* tmp = mkNum(d->bits);

            // clear temp 'tmp'
            (void)memset((tmp->data + s0->length), 0x0U, (tmp->size - s0->size));
            (void)memcpy(tmp->data, s0->data, s0->size);

            size_t nSftBit = s0->bits;
            for(size_t i = 0U; i < s1->length; i++) {
                size_t sftBit = (nSftBit >= NTYPE_BITS)?(NTYPE_BITS):(nSftBit);
                for(size_t sft = 0U; sft < sftBit; sft++) {
                    if(((s1->data[i] >> sft) & 0x1U) != 0x0u) {
                        add_u32(d, d, tmp, 0U);
                    } else { /* Do nothing */}
                    sftL1b(tmp, NULL, 0U);
                }
                nSftBit-=sftBit;
            }
            rmNum(&tmp);

            if(nSftBit != 0U) {
                return E_ERROR_RUNTIME;
            } else { /* Do nothing */ }
        } else {
            return E_ERROR_ARGS;
        }
    } else {
        return E_ERROR_NULL;
    }
    return E_OK;
}

ReturnType mul_u4(ntype_s* d, ntype_s* s1, ntype_s* s0, NTYPE* ovf) {
    if((d != NULL) && (s1 != NULL) && (s0 != NULL)) {
        if((s1->length == s0->length) && (s1->length == d->length)) {
            uint8_t ou4 = 0U;
            uint8_t tu4;
            uint8_t* a = (uint8_t*)(s0->data);
            uint8_t* b = (uint8_t*)(s1->data);
            for(size_t i = 0U; i < d->size; i++) {
                tu4 = ((((a[i] >> 0U) & 0xfU) * ((b[i] >> 0U) & 0xfU)) + ou4);
                ou4 = ((tu4 >> 4U) & 0xfU);
                tu4 = ((((a[i] >> 4U) & 0xfU) * ((b[i] >> 4U) & 0xfU)) + ou4);
                ou4 = ((tu4 >> 4U) & 0xfU);
            }

            if(ovf != NULL) {
                *ovf = ou4;
            }
        } else {
            return E_ERROR_ARGS;
        }
    } else {
        return E_ERROR_NULL;
    }
    return E_OK;
}
