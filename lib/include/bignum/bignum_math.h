#ifndef BIGNUM_MATH_H
#define BIGNUM_MATH_H

#include <stdlib.h>
#include <stdbool.h>

#include "common/returnType.h"
#include "bignum/bignum.h"
#include "common/util.h"

bignum_t add_bignum(bignum_s* d, const bignum_s* s1, const bignum_s* s0, const bignum_t c);
bignum_t sub_bignum(bignum_s* d, const bignum_s* s1, const bignum_s* s0, const bignum_t c);
#define mul_bignum_bs(d, s1, s0)    mul_bignum_bs_ext(d, s1, s0, true)
ReturnType mul_bignum_bs_ext(bignum_s* d, const bignum_s* s1, const bignum_s* s0, const bool guard);

bignum_t add_bignum_loc(bignum_s* d, const bignum_t v, const size_t loc);

#endif/* BIGNUM_MATH_H */
