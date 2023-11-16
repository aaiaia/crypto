#ifndef ARITH_CORE_H
#define ARITH_CORE_H

#include <stdlib.h>
#include <stdbool.h>

#include "common/returnType.h"
#include "common/ntype.h"
#include "common/util.h"

NTYPE add_u32(ntype_s* d, ntype_s* s1, ntype_s* s0, NTYPE c);
NTYPE sub_u32(ntype_s* d, ntype_s* s1, ntype_s* s0, NTYPE c);
#define mul_u32(d, s1, s0)  mul_u32_ext(d, s1, s0, true)
ReturnType mul_u32_ext(ntype_s* d, ntype_s* s1, ntype_s* s0, bool guard);

#endif
