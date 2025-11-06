#ifndef BIGNUM_LOGIC_H
#define BIGNUM_LOGIC_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "common/returnType.h"
#include "bignum/bignum.h"

/* ab: All bits */
ReturnType inv_bignum(bignum_s* n);
ReturnType set_bignum(bignum_s* n);
ReturnType clr_bignum(bignum_s* n);

ReturnType set1b_bignum(bignum_s* n, const size_t bloc);
ReturnType clr1b_bignum(bignum_s* n, const size_t bloc);
bignum_t chk1b_bignum(const bignum_s* n, const size_t bloc);

/* MSB: Most Significant Bit */
size_t find_bignum_MSBL_bitLoc(const bignum_s* bignum, const size_t bitloc);
size_t find_bignum_MSBL(const bignum_s* bignum);
/* LSB: Least Significant Bit */
size_t find_bignum_LSBL_bitLoc(const bignum_s* bignum, const size_t bitloc);
size_t find_bignum_LSBL(const bignum_s* bignum);

ReturnType slb_bitnum_self_ext(bignum_s* d, const size_t blen, const bool arith);
ReturnType srb_bignum_self_ext(bignum_s* d, const size_t blen, const bool arith);
/* logical */
static inline ReturnType lslb_bignum_self(bignum_s* d, const size_t blen)
{
    return slb_bitnum_self_ext(d, blen, false);
}
static inline ReturnType lsrb_bignum_self(bignum_s* d, const size_t blen)
{
    return srb_bignum_self_ext(d, blen, false);
}
/* arithmatic */
static inline ReturnType aslb_bignum_self(bignum_s* d, const size_t blen)
{
    return slb_bitnum_self_ext(d, blen, true);
}
static inline ReturnType asrb_bignum_self(bignum_s* d, const size_t blen)
{
    return srb_bignum_self_ext(d, blen, true);
}

ReturnType mlw_bignum_self_ext(bignum_s* d, const size_t lml, const bool arith);
ReturnType mrw_bignum_self_ext(bignum_s* d, const size_t lmr, const bool arith);
/* logical */
static inline ReturnType lmlw_bignum_self(bignum_s* d, const size_t lml)
{
    return mlw_bignum_self_ext(d, lml, false);
}
static inline ReturnType lmrw_bignum_self(bignum_s* d, const size_t lmr)
{
    return mrw_bignum_self_ext(d, lmr, false);
}
/* arithmatic */
static inline ReturnType amlw_bignum_self(bignum_s* d, const size_t lml)
{
    return mlw_bignum_self_ext(d, lml, true);
}
static inline ReturnType amrw_bignum_self(bignum_s* d, const size_t lmr)
{
    return mrw_bignum_self_ext(d, lmr, true);
}

ReturnType slnb_bignum_self_ext(bignum_s* d, bignum_t* co, const bignum_t ci, const size_t lslb, const bool arith);
ReturnType srnb_bignum_self_ext(bignum_s* d, bignum_t* co, const bignum_t ci, const size_t lsrb, const bool arith);
/* logical */
static inline ReturnType lslnb_bignum_self(bignum_s* d, bignum_t* co, const bignum_t ci, const size_t lslb)
{
    return slnb_bignum_self_ext(d, co, ci, lslb, false);
}
static inline ReturnType lsl1b_bignum_self(bignum_s* d, bignum_t* co, const bignum_t ci)
{
    return slnb_bignum_self_ext(d, co, ci, 1UL, false);
}
static inline ReturnType lsrnb_bignum_self(bignum_s* d, bignum_t* co, const bignum_t ci, const size_t lsrb)
{
    return srnb_bignum_self_ext(d, co, ci, lsrb, false);
}
static inline ReturnType lsr1b_bignum_self(bignum_s* d, bignum_t* co, const bignum_t ci)
{
    return srnb_bignum_self_ext(d, co, ci, 1UL, false);
}
/* arithmatic */
static inline ReturnType aslnb_bignum_self(bignum_s* d, bignum_t* co, const bignum_t ci, const size_t lslb)
{
    return slnb_bignum_self_ext(d, co, ci, lslb, true);
}
static inline ReturnType asl1b_bignum_self(bignum_s* d, bignum_t* co, const bignum_t ci)
{
    return slnb_bignum_self_ext(d, co, ci, 1UL, true);
}
static inline ReturnType asrnb_bignum_self(bignum_s* d, bignum_t* co, const bignum_t ci, const size_t lsrb)
{
    return srnb_bignum_self_ext(d, co, ci, lsrb, true);
}
static inline ReturnType asr1b_bignum_self(bignum_s* d, bignum_t* co, const bignum_t ci)
{
    return srnb_bignum_self_ext(d, co, ci, 1UL, true);
}


#endif/* BIGNUM_LOGIC_H */
