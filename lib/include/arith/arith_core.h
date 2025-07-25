#ifndef ARITH_CORE_H
#define ARITH_CORE_H

#include <stdlib.h>
#include <stdbool.h>

#include "common/returnType.h"
#include "common/ntype.h"
#include "common/util.h"

bignum_t add_NTYPE(bignum_s* d, bignum_s* s1, bignum_s* s0, bignum_t c);
bignum_t sub_NTYPE(bignum_s* d, bignum_s* s1, bignum_s* s0, bignum_t c);
#define mul_NTYPE_bs(d, s1, s0)  mul_NTYPE_bs_ext(d, s1, s0, true)
ReturnType mul_NTYPE_bs_ext(bignum_s* d, bignum_s* s1, bignum_s* s0, bool guard);

bignum_t add_NTYPE_loc(bignum_s* d, bignum_t v, size_t loc);

#endif
