#include <stdlib.h>
#include <stdint.h>

#include "common/ntype.h"
#include "common/util.h"

ntype_s* mkNum(size_t bits) {
    ntype_s* p = (ntype_s*)malloc(sizeof(ntype_s));
    p->bits = bits;
    p->lastMask = LASTBITMASK(bits, NTYPE);
    p->size = BIT2SIZE(bits);
    p->length= p->size/sizeof(NTYPE);
    p->data = (NTYPE*)malloc(p->size);
    return p;
}

int rmNum(ntype_s** p) {
    int fs = 0;
    if((void*)p!=NULL) {
        if((void*)(*p)!=NULL) {
            free((*p)->data);
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
