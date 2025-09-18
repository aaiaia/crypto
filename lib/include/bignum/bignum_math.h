#ifndef BIGNUM_MATH_H
#define BIGNUM_MATH_H

#include <stdlib.h>
#include <stdbool.h>

#include "common/returnType.h"
#include "bignum/bignum.h"
#include "common/util.h"
typedef enum {
    BIGNUM_CMP_NU,  // Not Used(Reserved)
    BIGNUM_CMP_NZ,  // Not Zero
    BIGNUM_CMP_ZO,  // ZerO
    BIGNUM_CMP_NO,  // Not One
    BIGNUM_CMP_ON,  // ONe
    BIGNUM_CMP_EQ,  // EQual
    BIGNUM_CMP_GT,  // Greater Than
    BIGNUM_CMP_LT,  // Less Than
    BIGNUM_CMP_ER,  // ERror
} bignum_cmp_e;
typedef enum {
    BIGNUM_SIGN_NU, // Not Used(Reserved)
    BIGNUM_SIGN_POS,// POSitive
    BIGNUM_SIGN_NEG,// NEGative
    BIGNUM_SIGN_ERR,// ERRor
} bignum_sign_e;

ReturnType cpy_bignum_math_ext(bignum_s* d, const bignum_s* s, const bool force);
static inline ReturnType cpy_bignum_math(bignum_s* d, const bignum_s* s)
{
    return cpy_bignum_math_ext(d, s, false);
}

ReturnType twos_bignum(bignum_s* d, const bignum_s* s);
ReturnType abs_bignum(bignum_s* d, const bignum_s* s);
bignum_sign_e sign_bignum_ext(const bignum_s* s, const bool ignoreType);
static inline bignum_sign_e sign_bignum(const bignum_s* s)
{
    return sign_bignum_ext(s, false);
}
static inline bignum_sign_e sign_bignum_unsafe(const bignum_s* s)
{
    return sign_bignum_ext(s, true);
}
bignum_sign_e NOT_IMPLEMENT_signbit_bignum(const bignum_s* s, const size_t msbl, const bignum_sign_e sign);
bignum_cmp_e cmp0_bignum(const bignum_s* s);
bignum_cmp_e cmp1_bignum(const bignum_s* s);
bignum_cmp_e cmp2_bignum(const bignum_s* s);
bignum_cmp_e cmp_bignum_with_sub_add_twos(const bignum_s* s0, const bignum_s* s1);
bignum_cmp_e cmp_bignum_logical(const bignum_s* s0, const bignum_s* s1);
ReturnType add_bignum(bignum_t* co, bignum_s* d, const bignum_s* s0, const bignum_s* s1, const bignum_t ci);
bignum_t add_bignum_carry_loc(bignum_s* d, const bignum_t v, const size_t idx);
ReturnType sub_bignum(bignum_t* co, bignum_s* d, const bignum_s* s0, const bignum_s* s1, const bignum_t ci);
ReturnType sub_bignum_with_add_twos(bignum_t* co, bignum_s* d, const bignum_s* s0, const bignum_s* s1, const bignum_t ci);
ReturnType mul_bignum_1bs_ext(bignum_s* d, const bignum_s* s1, const bignum_s* s0, const bool guard);
ReturnType mul_bignum_nbs_dn2up_ext(bignum_s* d, const bignum_s* s1, const bignum_s* s0, const bool guard);
ReturnType mul_bignum_nbs_up2dn_ext(bignum_s* d, const bignum_s* s1, const bignum_s* s0, const bool guard);
static inline ReturnType mul_bignum_1bs(bignum_s* d, const bignum_s* s1, const bignum_s* s0)
{
    return mul_bignum_1bs_ext(d, s1, s0, true);
}
static inline ReturnType mul_bignum(bignum_s* d, const bignum_s* s1, const bignum_s* s0)
{
    return mul_bignum_nbs_up2dn_ext(d, s1, s0, true);
}
static inline ReturnType mul_bignum_unsafe(bignum_s* d, const bignum_s* s1, const bignum_s* s0)
{
    return mul_bignum_nbs_dn2up_ext(d, s1, s0, false);
}
/* Divide with Modulo: 'n'umerator = 'q'uotient * 'd'enominator + 'r'emainder */
ReturnType div_bignum_with_mod_nbs_ext(bignum_s* q, bignum_s* r, const bignum_s* n, const bignum_s* d, const bool guard);
static inline ReturnType div_bignum_with_mod(bignum_s* q, bignum_s* r, const bignum_s* n, const bignum_s* d)
{
    return div_bignum_with_mod_nbs_ext(q, r, n, d, true);   // bit length guard
}

ReturnType gcd_bignum_ext(bignum_s* r, bignum_s* s, bignum_s* t, const bignum_s* a, const bignum_s* b, const bool guard);
static inline ReturnType gcd_bignum(bignum_s* r, bignum_s* s, bignum_s* t, const bignum_s* a, const bignum_s* b)
{
    return gcd_bignum_ext(r, s, t, a, b, true);
}

/* mim_bignum and mim_bignum_ext is muliplicative inverse modular */
ReturnType mim_bignum_ext(bignum_s* t, const bignum_s* a, const bignum_s* n, const bool guard);
static inline ReturnType mim_bignum(bignum_s* t, const bignum_s* a, const bignum_s* n)
{
    return mim_bignum_ext(t, a, n, true);
}
#endif/* BIGNUM_MATH_H */
