#ifndef ADD_H
#define ADD_H

#include <stdlib.h>

#include "common/ntype.h"
#include "common/util.h"

NTYPE add_u32(NTYPE* d, NTYPE* s1, NTYPE* s0, size_t len, NTYPE c);
NTYPE sub_u32(NTYPE* d, NTYPE* s1, NTYPE* s0, size_t len, NTYPE c);

#endif
