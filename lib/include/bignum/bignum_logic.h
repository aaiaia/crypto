#ifndef BIGNUM_LOGIC_H
#define BIGNUM_LOGIC_H

#include <stdio.h>
#include <stdint.h>

#include "common/returnType.h"
#include "bignum/bignum.h"

/* MSB: Most Significant Bit */
size_t find_bignum_MSBL(const bignum_s* bignum);
/* LSB: Least Significant Bit */
size_t find_bignum_LSBL(const bignum_s* bignum);

ReturnType lslb_bignum(bignum_s* d, const size_t blen);
ReturnType rslb_bignum(bignum_s* d, const size_t blen);

ReturnType lslnb_bignum(bignum_s* d, bignum_t* co, const bignum_t ci, const size_t blen);
static inline ReturnType lsl1b_bignum(bignum_s* d, bignum_t* co, const bignum_t ci)
{
    return lslnb_bignum(d, co, ci, 1UL);
}

#endif/* BIGNUM_LOGIC_H */
