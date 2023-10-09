#include <stdlib.h>
#include <stdint.h>

#include "common/ntype.h"
#include "common/util.h"

ntype_s* mkNum(uint32_t blen) {
    ntype_s* p = (ntype_s*)malloc(sizeof(ntype_s));
    p->blen = blen;
    p->alen = BIT2SIZE(blen);
    p->array = (NTYPE*)calloc(p->alen, sizeof(NTYPE));
    return p;
}

int rmNum(ntype_s** p) {
    int fs = 0;
    if((void*)p!=NULL) {
        if((void*)(*p)!=NULL) {
            free((*p)->array);
            free((*p));
            (*p) = (ntype_s*)NULL;
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
