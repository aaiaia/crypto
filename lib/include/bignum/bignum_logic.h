#ifndef BIGNUM_LOGIC_H
#define BIGNUM_LOGIC_H

#include <stdio.h>
#include <stdint.h>

#include "common/returnType.h"
#include "bignum/bignum.h"

/* ab: All bits */
ReturnType inv_bignum(bignum_s* n);
ReturnType set_bignum(bignum_s* n);
ReturnType clr_bignum(bignum_s* n);

ReturnType set1b_bignum(bignum_s* n, const size_t bloc);
ReturnType clr1b_bignum(bignum_s* n, const size_t bloc);

/* MSB: Most Significant Bit */
size_t find_bignum_MSBL_bitLoc(const bignum_s* bignum, const size_t bitloc);
size_t find_bignum_MSBL(const bignum_s* bignum);
/* LSB: Least Significant Bit */
size_t find_bignum_LSBL_bitLoc(const bignum_s* bignum, const size_t bitloc);
size_t find_bignum_LSBL(const bignum_s* bignum);

ReturnType lslb_bignum_self(bignum_s* d, const size_t blen);
ReturnType lsrb_bignum_self(bignum_s* d, const size_t blen);

ReturnType lmlw_bignum_self(bignum_s* d, const size_t lml);
ReturnType lmrw_bignum_self(bignum_s* d, const size_t lmr);

ReturnType lslnb_bignum_self(bignum_s* d, bignum_t* co, const bignum_t ci, const size_t lslb);
static inline ReturnType lsl1b_bignum_self(bignum_s* d, bignum_t* co, const bignum_t ci)
{
    return lslnb_bignum_self(d, co, ci, 1UL);
}
ReturnType lsrnb_bignum_self(bignum_s* d, bignum_t* co, const bignum_t ci, const size_t lsrb);
static inline ReturnType lsr1b_bignum_self(bignum_s* d, bignum_t* co, const bignum_t ci)
{
    return lsrnb_bignum_self(d, co, ci, 1UL);
}

#endif/* BIGNUM_LOGIC_H */
