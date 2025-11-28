#include <stdlib.h>
#include <stdint.h>

#include "bignum/bignum.h"
#include "common/util.h"

bignum_s* mkBigNum(const size_t bits) {
    bignum_s* p = (bignum_s*)malloc(sizeof(bignum_s));
    p->bits = bits;
    p->size = BITS2SIZE(bits);
    p->nlen = BIGNUM_BITS_LEN(bits);
    p->lmsk = LASTBITMASK(bits, bignum_t);
    p->nums = (bignum_t*)calloc(p->nlen, sizeof(bignum_t));
    return p;
}

int rmBigNum(bignum_s** p) {
    int fs = 0;
    if((void*)p!=NULL) {
        if((void*)(*p)!=NULL) {
            free((*p)->nums);
            free((*p));
            (*p) = (bignum_s*)NULL;
        }
        else {
            fs = -1;
        }
    }
    else {
        fs = -1;
    }
    return fs;
}

