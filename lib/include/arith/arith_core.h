#ifndef ADD_H
#define ADD_H

#include <stdlib.h>

#include "common/ntype.h"
#include "common/util.h"

NTYPE add_u32(ntype_s* d, ntype_s* s1, ntype_s* s0, NTYPE c);
NTYPE sub_u32(ntype_s* d, ntype_s* s1, ntype_s* s0, NTYPE c);

#endif
