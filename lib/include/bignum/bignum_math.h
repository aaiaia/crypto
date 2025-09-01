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

ReturnType cpy_bignum_math(bignum_s* dst, const bignum_s* s);

ReturnType twos_bignum(bignum_s* d, const bignum_s* s);
ReturnType abs_bignum(bignum_s* d, const bignum_s* s);
bignum_sign_e sign_bignum(const bignum_s* s);
bignum_sign_e NOT_IMPLEMENT_signbit_bignum(const bignum_s* s, const size_t msbl, const bignum_sign_e sign);
bignum_cmp_e cmp0_bignum(const bignum_s* s);
bignum_cmp_e NOT_IMPLEMENT_cmp_bignum_with_sub(const bignum_s* s0, const bignum_s* s1);
bignum_cmp_e cmp_bignum_logical(const bignum_s* s0, const bignum_s* s1);
ReturnType add_bignum(bignum_t* co, bignum_s* d, const bignum_s* s0, const bignum_s* s1, const bignum_t ci);
ReturnType sub_bignum(bignum_t* co, bignum_s* d, const bignum_s* s0, const bignum_s* s1, const bignum_t ci);
#define mul_bignum_bs(d, s1, s0)    mul_bignum_bs_ext(d, s1, s0, true)
ReturnType mul_bignum_bs_ext(bignum_s* d, const bignum_s* s1, const bignum_s* s0, const bool guard);
/* Divide with Modulo: 'n'umerator = 'q'uotient * 'd'enominator + 'r'emainder */
ReturnType div_bignum_with_mod_ext(bignum_t* q, bignum_t* r, const bignum_s* n, const bignum_s* d, const bool guard);

bignum_t add_bignum_loc(bignum_s* d, const bignum_t v, const size_t idx);

#endif/* BIGNUM_MATH_H */
