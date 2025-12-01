#ifndef BIGNUM_ALU_H
#define BIGNUM_ALU_H

#include <stdlib.h>
#include <stdbool.h>

#include "common/returnType.h"
#include "bignum/bignum.h"
#include "bignum/bignum_mont.h"
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

/* ab: All bits */
ReturnType inv_bignum(bignum_s* n);
ReturnType set_bignum(bignum_s* n);
ReturnType clr_bignum(bignum_s* n);

ReturnType inv1w_bignum(bignum_s* n, const size_t wloc);
ReturnType set1w_bignum(bignum_s* n, const size_t wloc);
ReturnType clr1w_bignum(bignum_s* n, const size_t wloc);
ReturnType put1w_bignum(bignum_s* n, const bignum_t v, const size_t wloc);

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

ReturnType cpy_bignum_mode_ext(bignum_s* d, const bignum_s* s, const bool inverse, const bool ign_sign, const bool ign_len);
// copy forward
static inline ReturnType cpy_bignum_ext(bignum_s* d, const bignum_s* s, const bool ign_sign, const bool ign_len)
{
    const bool inverse = false;
    return cpy_bignum_mode_ext(d, s, inverse, ign_sign, ign_len);
}
static inline ReturnType cpy_bignum_safe(bignum_s* d, const bignum_s* s, const bool ign_sign)
{
    const bool inverse = false, ign_len = false;
    return cpy_bignum_mode_ext(d, s, inverse, ign_sign, ign_len);
}
static inline ReturnType cpy_bignum_unsafe(bignum_s* d, const bignum_s* s, const bool ign_sign)
{
    const bool inverse = false, ign_len = true;
    return cpy_bignum_mode_ext(d, s, inverse, ign_sign, ign_len);
}
static inline ReturnType cpy_bignum_signed_safe(bignum_s* d, const bignum_s* s)
{
    const bool inverse = false, ign_sign = false, ign_len = false;
    return cpy_bignum_mode_ext(d, s, inverse, ign_sign, ign_len);
}
static inline ReturnType cpy_bignum_signed_unsafe(bignum_s* d, const bignum_s* s)
{
    const bool inverse = false, ign_sign = false, ign_len = true;
    return cpy_bignum_mode_ext(d, s, inverse, ign_sign, ign_len);
}
static inline ReturnType cpy_bignum_unsigned_safe(bignum_s* d, const bignum_s* s)
{
    const bool inverse = false, ign_sign = true, ign_len = false;
    return cpy_bignum_mode_ext(d, s, inverse, ign_sign, ign_len);
}
static inline ReturnType cpy_bignum_unsigned_unsafe(bignum_s* d, const bignum_s* s)
{
    const bool inverse = false, ign_sign = true, ign_len = true;
    return cpy_bignum_mode_ext(d, s, inverse, ign_sign, ign_len);
}
// copy inverse
static inline ReturnType cpy_bignum_inverse_ext(bignum_s* d, const bignum_s* s, const bool ign_sign, const bool ign_len)
{
    const bool inverse = true;
    return cpy_bignum_mode_ext(d, s, inverse, ign_sign, ign_len);
}
static inline ReturnType cpy_bignum_inverse_signed_safe(bignum_s* d, const bignum_s* s)
{
    const bool inverse = true, ign_sign = false, ign_len = false;
    return cpy_bignum_mode_ext(d, s, inverse, ign_sign, ign_len);
}
static inline ReturnType cpy_bignum_inverse_signed_unsafe(bignum_s* d, const bignum_s* s)
{
    const bool inverse = true, ign_sign = false, ign_len = true;
    return cpy_bignum_mode_ext(d, s, inverse, ign_sign, ign_len);
}
static inline ReturnType cpy_bignum_inverse_unsigned_safe(bignum_s* d, const bignum_s* s)
{
    const bool inverse = true, ign_sign = true, ign_len = false;
    return cpy_bignum_mode_ext(d, s, inverse, ign_sign, ign_len);
}
static inline ReturnType cpy_bignum_inverse_unsigned_unsafe(bignum_s* d, const bignum_s* s)
{
    const bool inverse = true, ign_sign = true, ign_len = true;
    return cpy_bignum_mode_ext(d, s, inverse, ign_sign, ign_len);
}

ReturnType cpy_bignum_twos_ext(bignum_s* d, const bignum_s* s, const bool ign_sign, const bool ign_len);
static inline ReturnType cpy_bignum_twos_signed(bignum_s* d, const bignum_s* s, const bool ign_len)
{
    const bool ign_sign = false;
    return cpy_bignum_twos_ext(d, s, ign_sign, ign_len);
}
static inline ReturnType cpy_bignum_twos_signed_safe(bignum_s* d, const bignum_s* s)
{
    const bool ign_sign = false, ign_len = false;
    return cpy_bignum_twos_ext(d, s, ign_sign, ign_len);
}
static inline ReturnType cpy_bignum_twos_signed_unsafe(bignum_s* d, const bignum_s* s)
{
    const bool ign_sign = false, ign_len = true;
    return cpy_bignum_twos_ext(d, s, ign_sign, ign_len);
}

ReturnType cpy_bignum_abs_safe_ext(bignum_s* d, const bignum_s* s, const bool ign_sign);
static inline ReturnType cpy_bignum_abs_safe(bignum_s* d, const bignum_s* s)
{
    return cpy_bignum_abs_safe_ext(d, s, false);
}
static inline ReturnType cpy_bignum_abs_signed_safe(bignum_s* d, const bignum_s* s)
{
    return cpy_bignum_abs_safe_ext(d, s, false);
}
static inline ReturnType cpy_bignum_abs_unsigned_safe(bignum_s* d, const bignum_s* s)
{
    return cpy_bignum_abs_safe_ext(d, s, true);
}
bignum_sign_e sign_bignum_ext(const bignum_s* s, const bool ign_sign);
static inline bignum_sign_e sign_bignum_signed(const bignum_s* s)
{
    return sign_bignum_ext(s, false);
}
static inline bignum_sign_e sign_bignum_unsigned(const bignum_s* s)
{
    return sign_bignum_ext(s, true);
}
bignum_cmp_e cmp0_bignum(const bignum_s* s);
bignum_cmp_e cmp1_bignum(const bignum_s* s);
bignum_cmp_e cmp2_bignum(const bignum_s* s);
bignum_cmp_e cmp_bignum_with_sub_add_twos(const bignum_s* s0, const bignum_s* s1);
bignum_cmp_e cmp_bignum_logical_ext(const bignum_s* s0, const bignum_s* s1, const bool ign_len, const bool ign_sign);
static inline bignum_cmp_e cmp_bignum_logical_safe_ext(const bignum_s* s0, const bignum_s* s1, const bool ign_sign)
{
    const bool ign_len = false;
    return cmp_bignum_logical_ext(s0, s1, ign_len, ign_sign);
}
static inline bignum_cmp_e cmp_bignum_logical_unsafe_ext(const bignum_s* s0, const bignum_s* s1, const bool ign_sign)
{
    const bool ign_len = true;
    return cmp_bignum_logical_ext(s0, s1, ign_len, ign_sign);
}
static inline bignum_cmp_e cmp_bignum_logical_signed_safe(const bignum_s* s0, const bignum_s* s1)
{
    const bool ign_len = false, ign_sign = false;
    return cmp_bignum_logical_ext(s0, s1, ign_len, ign_sign);
}
static inline bignum_cmp_e cmp_bignum_logical_signed_unsafe(const bignum_s* s0, const bignum_s* s1)
{
    const bool ign_len = true, ign_sign = false;
    return cmp_bignum_logical_ext(s0, s1, ign_len, ign_sign);
}
static inline bignum_cmp_e cmp_bignum_logical_unsigned_safe(const bignum_s* s0, const bignum_s* s1)
{
    const bool ign_len = false, ign_sign = true;
    return cmp_bignum_logical_ext(s0, s1, ign_len, ign_sign);
}
static inline bignum_cmp_e cmp_bignum_logical_unsigned_unsafe(const bignum_s* s0, const bignum_s* s1)
{
    const bool ign_len = true, ign_sign = true;
    return cmp_bignum_logical_ext(s0, s1, ign_len, ign_sign);
}
ReturnType add_bignum_ext(bignum_t* co, bignum_s* d, const bignum_s* s0, const bignum_s* s1, const bignum_t ci, const bool ign_sign);
static inline ReturnType add_bignum_unsafe(bignum_s* d, const bignum_s* s0, const bignum_s* s1, const bool ign_sign)
{
    return add_bignum_ext(NULL, d, s0, s1, 0U, ign_sign);
}
static inline ReturnType add_bignum_signed_unsafe(bignum_s* d, const bignum_s* s0, const bignum_s* s1)
{
    const bool ign_sign = false;
    return add_bignum_ext(NULL, d, s0, s1, 0U, ign_sign);
}
static inline ReturnType add_bignum_unsigned_unsafe(bignum_s* d, const bignum_s* s0, const bignum_s* s1)
{
    const bool ign_sign = true;
    return add_bignum_ext(NULL, d, s0, s1, 0U, ign_sign);
}
bignum_t add1w_bignum_loc_ext(bignum_s* d, const bignum_t v, const size_t idx, const bool ign_sign);
static inline bignum_t add1w_bignum_loc_signed(bignum_s* d, const bignum_t v, const size_t idx)
{
    return add1w_bignum_loc_ext(d, v, idx, false);
}
static inline bignum_t add1w_bignum_loc_unsigned(bignum_s* d, const bignum_t v, const size_t idx)
{
    return add1w_bignum_loc_ext(d, v, idx, true);
}
bignum_t sub1w_bignum_loc_ext(bignum_s* d, const bignum_t v, const size_t idx, const bool ign_sign);
static inline bignum_t sub1w_bignum_loc_signed(bignum_s* d, const bignum_t v, const size_t idx)
{
    return sub1w_bignum_loc_ext(d, v, idx, false);
}
static inline bignum_t sub1w_bignum_loc_unsigned(bignum_s* d, const bignum_t v, const size_t idx)
{
    return sub1w_bignum_loc_ext(d, v, idx, true);
}
ReturnType sub_bignum_ext(bignum_t* co, bignum_s* d, const bignum_s* s0, const bignum_s* s1, const bignum_t ci, const bool ign_sign);
static inline ReturnType sub_bignum_unsafe(bignum_s* d, const bignum_s* s0, const bignum_s* s1, const bool ign_sign)
{
    return sub_bignum_ext(NULL, d, s0, s1, 0U, ign_sign);
}
static inline ReturnType sub_bignum_signed_unsafe(bignum_s* d, const bignum_s* s0, const bignum_s* s1)
{
    const bool ign_sign = false;
    return sub_bignum_ext(NULL, d, s0, s1, 0U, ign_sign);
}
static inline ReturnType sub_bignum_unsigned_unsafe(bignum_s* d, const bignum_s* s0, const bignum_s* s1)
{
    const bool ign_sign = true;
    return sub_bignum_ext(NULL, d, s0, s1, 0U, ign_sign);
}
ReturnType sub_bignum_with_add_twos_ext(bignum_t* co, bignum_s* d, const bignum_s* s0, const bignum_s* s1, const bignum_t ci);
static inline ReturnType sub_bignum_with_add_twos(bignum_s* d, const bignum_s* s0, const bignum_s* s1)
{
    return sub_bignum_with_add_twos_ext(NULL, d, s0, s1, 0U);
}
ReturnType mul_bignum_1bs_ext(bignum_s* d, const bignum_s* s1, const bignum_s* s0, const bool ign_len);
ReturnType mul_bignum_nbs_dn2up_ext(bignum_s* d, const bignum_s* s1, const bignum_s* s0, const bool ign_sign, const bool ign_len);
static inline ReturnType mul_bignum_signed_1bs(bignum_s* d, const bignum_s* s1, const bignum_s* s0)
{
    return mul_bignum_1bs_ext(d, s1, s0, false);
}
static inline ReturnType mul_bignum_signed(bignum_s* d, const bignum_s* s1, const bignum_s* s0)
{
    const bool ign_sign = false, ign_len = false;
    return mul_bignum_nbs_dn2up_ext(d, s1, s0, ign_sign, ign_len);
}
static inline ReturnType mul_bignum_unsigned(bignum_s* d, const bignum_s* s1, const bignum_s* s0)
{
    const bool ign_sign = true, ign_len = false;
    return mul_bignum_nbs_dn2up_ext(d, s1, s0, ign_sign, ign_len);
}
static inline ReturnType mul_bignum_signed_unsafe(bignum_s* d, const bignum_s* s1, const bignum_s* s0)
{
    const bool ign_sign = false, ign_len = true;
    return mul_bignum_nbs_dn2up_ext(d, s1, s0, ign_sign, ign_len);
}
static inline ReturnType mul_bignum_unsigned_unsafe(bignum_s* d, const bignum_s* s1, const bignum_s* s0)
{
    const bool ign_sign = true, ign_len = true;
    return mul_bignum_nbs_dn2up_ext(d, s1, s0, ign_sign, ign_len);
}
ReturnType mul1w_bignum_unsigned_unsafe(bignum_s* d, const bignum_t ws1, const bignum_s* s0);
/* Divide with Modulo: 'n'umerator = 'q'uotient * 'd'enominator + 'r'emainder */
ReturnType div_bignum_with_mod_nbs_ext(bignum_s* q, bignum_s* r, const bignum_s* n, const bignum_s* d, const bool ign_len);
static inline ReturnType div_bignum_with_mod(bignum_s* q, bignum_s* r, const bignum_s* n, const bignum_s* d)
{
    return div_bignum_with_mod_nbs_ext(q, r, n, d, false);
}
static inline ReturnType div_bignum_with_mod_unsafe(bignum_s* q, bignum_s* r, const bignum_s* n, const bignum_s* d)
{
    return div_bignum_with_mod_nbs_ext(q, r, n, d, true);
}

static inline ReturnType div_bignum(bignum_s* q, const bignum_s* n, const bignum_s* d)
{
    return div_bignum_with_mod_nbs_ext(q, NULL, n, d, false);
}
static inline ReturnType div_bignum_unsafe(bignum_s* q, const bignum_s* n, const bignum_s* d)
{
    return div_bignum_with_mod_nbs_ext(q, NULL, n, d, true);
}

static inline ReturnType mod_bignum(bignum_s* r, const bignum_s* n, const bignum_s* d)
{
    return div_bignum_with_mod_nbs_ext(NULL, r, n, d, false);
}
static inline ReturnType mod_bignum_unsafe(bignum_s* r, const bignum_s* n, const bignum_s* d)
{
    return div_bignum_with_mod_nbs_ext(NULL, r, n, d, true);
}

/*
 * aim_bignum_signed_safe and aim_bignum_ext is additive inverse modular
 * Additive inverse in modulo: (x + y) mod p = 0
 * example) (-87) mod 97 is have to meet (87 + (-87)) mod 97 = 0
 * To figuring out, convert (-87) to 'x' then formula: (87 + 'x') mod 97 = 0
 * Easy way to finding value add modulo p(=97) both side then (87 + 'x' + 97) mod 97 = (97) mod 97 = 0
 * So, getting Additive inverse method (p - |n|) mod p
 */
ReturnType aim_bignum_ext(bignum_s* x, const bignum_s* n, const bignum_s* p, const bool ign_len, const bool ign_sign);
static inline ReturnType aim_bignum_safe(bignum_s* x, const bignum_s* n, const bignum_s* p, const bool ign_sign)
{
    const bool ign_len = false;
    return aim_bignum_ext(x, n, p, ign_len, ign_sign);
}
static inline ReturnType aim_bignum_signed_safe(bignum_s* x, const bignum_s* n, const bignum_s* p)
{
    const bool ign_len = false, ign_sign = false;
    return aim_bignum_ext(x, n, p, ign_len, ign_sign);
}
static inline ReturnType aim_bignum_unsigned_safe(bignum_s* x, const bignum_s* n, const bignum_s* p)
{
    const bool ign_len = false, ign_sign = true;
    return aim_bignum_ext(x, n, p, ign_len, ign_sign);
}
static inline ReturnType aim_bignum_unsafe(bignum_s* x, const bignum_s* n, const bignum_s* p, const bool ign_sign)
{
    const bool ign_len = true;
    return aim_bignum_ext(x, n, p, ign_len, ign_sign);
}
static inline ReturnType aim_bignum_signed_unsafe(bignum_s* x, const bignum_s* n, const bignum_s* p)
{
    const bool ign_len = true, ign_sign = false;
    return aim_bignum_ext(x, n, p, ign_len, ign_sign);
}
static inline ReturnType aim_bignum_unsigned_unsafe(bignum_s* x, const bignum_s* n, const bignum_s* p)
{
    const bool ign_len = true, ign_sign = true;
    return aim_bignum_ext(x, n, p, ign_len, ign_sign);
}

ReturnType gcd_bignum_ext(bignum_s* r, bignum_s* s, bignum_s* t, const bignum_s* a, const bignum_s* b, const bool ign_len);
static inline ReturnType gcd_bignum(bignum_s* r, bignum_s* s, bignum_s* t, const bignum_s* a, const bignum_s* b)
{
    return gcd_bignum_ext(r, s, t, a, b, false);
}

/*
 * mim_bignum and mim_bignum_ext is muliplicative inverse modular, 'bignum_s* r' is optional
 * multiplicative inverse in modulo: (x * y) mod p = 1
 * example) 18^(-1) mod 97 is have to meet (18*18^(-1)) mod 97 = 1
 * To figuring out, convert 18^(-1) to 'x', then formula: (18*'x') mod 97 = 1
 * 'x' can become 1 ~ 96, insert all of x into (18*'x') mod 97 and formaula become equal to '1'
 * The only value is 'x' is 89, so 18^(-1) is same with 89 in modulo
 */
ReturnType mim_bignum_ext(bignum_s* t, bignum_s* r, const bignum_s* a, const bignum_s* n, const bool ign_len);
static inline ReturnType mim_bignum(bignum_s* t, const bignum_s* a, const bignum_s* n)
{
    return mim_bignum_ext(t, NULL, a, n, false);
}
static inline ReturnType mim_bignum_unsafe(bignum_s* t, const bignum_s* a, const bignum_s* n)
{
    return mim_bignum_ext(t, NULL, a, n, true);
}

/*
 * Mongomery Reduction and Multiplication
 * Ref: Handbook of Applied Cryptography, 1996, CRC press
 * 14.3.2 Montgomery reduction in Chapter14
 * Study at https://blog.naver.com/aaiaia/224087676346
 */
ReturnType swapMontToBignum_unsigned_safe(bignum_s* dst, const bignum_s* src, const mont_conf_s* conf);
static inline ReturnType convBignumToMont_unsigned_safe(bignum_s* mont, const bignum_s* n, const mont_conf_s* conf)
{
    return swapMontToBignum_unsigned_safe(mont, n, conf);
}
static inline ReturnType convMontToBignum_unsigned_safe(bignum_s* n, const bignum_s* mont, const mont_conf_s* conf)
{
    return swapMontToBignum_unsigned_safe(n, mont, conf);
}
ReturnType mod_mont_unsigned_safe(bignum_s* mont, const bignum_s* n_x2bit, const mont_conf_s* conf);
ReturnType mul_mont_unsigned_safe(bignum_s* mont, const bignum_s* x, const bignum_s* y, const mont_conf_s* conf);
#endif/* BIGNUM_ALU_H */
