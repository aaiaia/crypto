#include <stdlib.h>
#include <stdint.h>

#include "common/ntype.h"
#include "common/util.h"

bigNumU32s_s* mkBigNumU32s(size_t bits) {
    bigNumU32s_s* p = (bigNumU32s_s*)malloc(sizeof(bigNumU32s_s));
    p->bits = bits;
    p->size = BITS2SIZE(bits);
    p->nlen = BYTE2U32L(BITS2SIZE(bits));
    p->nums = (BNU32*)calloc(p->nlen, sizeof(BNU32));
    return p;
}

int rmBitNumU32s(bigNumU32s_s** p) {
    int fs = 0;
    if((void*)p!=NULL) {
        if((void*)(*p)!=NULL) {
            free((*p)->nums);
            free((*p));
            (*p) = (bigNumU32s_s*)NULL;
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

