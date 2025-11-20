#include "ec/ec_cal.h"

#include "bignum/bignum_alu.h"

#include "test/test_tool.h"

#if 0 /* ENABLE_EC_LOG */
#ifndef ENABLE_EC_LOG
#define ENABLE_EC_LOG
#endif/* ENABLE_EC_LOG */
#endif/* ENABLE_EC_LOG */

#ifdef ENABLE_EC_LOG
#include <stdio.h>
#include "test/test_tool.h"
#define _EC_FN_(RV, FN) __RETURN_TYPE_WRAPPING__(RV, FN)

#define _DPRINTF_                   printf
#define _PRINT_BIGNUM_(p, title)    test_print_bignum(p, title)

#define _PRINT_wNAF_INFO_(p, title) test_print_wNAF_info(p, title)
#define _PRINT_wNAF_(p, title)      test_print_wNAF_PreCompute_info(p, title)
#else
#define _EC_FN_(RV, FN) ((RV) = (FN))

#define _DPRINTF_
#define _PRINT_BIGNUM_(p, title)

#define _PRINT_wNAF_INFO_(p, title)
#define _PRINT_wNAF_(p, title)
#endif /* ENABLE_EC_LOG */

#define EC_BIT_P1(ec_bits)  (ec_bits+1UL)
#define EC_BIT_X2(ec_bits)  (ec_bits<<1U)

/*
 * ec_calPoints_ext
 * xR, yR: Result of ec point addition(sum)
 * xP, yP: Operand ec point P
 * xQ, yQ: Operand ec point Q
 * a: coeffient of ec curve, y^2 = x^3 + a*x + b
 * p: prime number for modulo p(mod p)
 */
void ec_calPoints_ext(bignum_s* xR, bignum_s* yR, \
        const bignum_s* xP, const bignum_s* yP, \
        const bool nQ, \
        const bignum_s* xQ, const bignum_s* yQ, \
        const size_t ec_bits, const bignum_s* a, const bignum_s* p, \
        const bool ign_sign)
{
    bool slope_is_INFINITE = false;
    bool point_is_IDENTITY = false;
    ReturnType fr;

    if((cmp0_bignum(xP) == BIGNUM_CMP_ZO) && (cmp0_bignum(yP) == BIGNUM_CMP_ZO)) {
        _DPRINTF_("[INFO] Point P is IDENTITY ELEMENTS\r\n");
        point_is_IDENTITY |= true;
    }
    if((cmp0_bignum(xQ) == BIGNUM_CMP_ZO) && (cmp0_bignum(yQ) == BIGNUM_CMP_ZO)) {
        _DPRINTF_("[INFO] Point Q is IDENTITY ELEMENTS\r\n");
        point_is_IDENTITY |= true;
    }

    _PRINT_BIGNUM_(xP, "| | | | | xP | | | | |");
    _PRINT_BIGNUM_(yP, "| | | | | yP | | | | |");
    _DPRINTF_("[INFO] Point Q is %s\r\n", nQ?"Negative":"Positive");
    _PRINT_BIGNUM_(xQ, "| | | | | xQ | | | | |");
    _PRINT_BIGNUM_(yQ, "| | | | | yQ | | | | |");
    _PRINT_BIGNUM_(p, "| | | | | p | | | | |");
    _PRINT_BIGNUM_(a, "| | | | | a | | | | |");

    if(!point_is_IDENTITY) {
        bignum_cmp_e cmp_x = cmp_bignum_logical_safe_ext(xP, xQ, ign_sign);
        bignum_cmp_e cmp_y = cmp_bignum_logical_safe_ext(yP, yQ, ign_sign);
        _DPRINTF_("[INFO] Point P and Q are %s\r\n", ((cmp_x == BIGNUM_CMP_EQ) && (cmp_y == BIGNUM_CMP_EQ))?"Same":"Diff");

        bignum_s* bitEx_p1_m = mkBigNum(EC_BIT_P1(ec_bits));
        bignum_s* bitEx_p1_x = mkBigNum(EC_BIT_P1(ec_bits));
        bignum_s* bitEx_p1_y = mkBigNum(EC_BIT_P1(ec_bits));

        bignum_s* bitEx_p1_p = mkBigNum(EC_BIT_P1(ec_bits));
        cpy_bignum_unsigned_unsafe(bitEx_p1_p, p);
        _PRINT_BIGNUM_(bitEx_p1_p, "| | | | | bitEx_p1_p | | | | |");

        if(!((cmp_x == BIGNUM_CMP_EQ) && (cmp_y == BIGNUM_CMP_EQ)))
        {
            /* P != Q */
            _DPRINTF_("P != Q\n");

            bignum_s* bitEx_x2_mul = mkBigNum(EC_BIT_X2(ec_bits)); // bit extended m

            bignum_s* bitEx_p1_dy  = mkBigNum(EC_BIT_P1(ec_bits));// by bit expension, unsigned to signed on addtion
            bignum_s* bitEx_p1_dx  = mkBigNum(EC_BIT_P1(ec_bits));// by bit expension, unsigned to signed on addtion
            bignum_s* bitEx_p1_dxi = mkBigNum(EC_BIT_P1(ec_bits));// by bit expension, unsigned to signed on addtion

            if(!nQ) {
                _EC_FN_(fr, sub_bignum_unsigned_unsafe(bitEx_p1_dy, yP, yQ));// bit expended, unsigned to sign
            } else {
                _EC_FN_(fr, add_bignum_unsigned_unsafe(bitEx_p1_dy, yP, yQ));// bit expended, unsigned to sign
            }
                _PRINT_BIGNUM_(bitEx_p1_dy, "| | | | | bitEx_p1_dy = yP - yQ | | | | |");
            _EC_FN_(fr, aim_bignum_signed_unsafe(bitEx_p1_dy, bitEx_p1_dy, bitEx_p1_p));
            _PRINT_BIGNUM_(bitEx_p1_dy, "| | | | | bitEx_p1_dy = (yP - yQ) mod bitEx_p1_p | | | | |");
            _EC_FN_(fr, sub_bignum_unsigned_unsafe(bitEx_p1_dx, xP, xQ));// bit expended, unsigned to sign
            _PRINT_BIGNUM_(bitEx_p1_dx, "| | | | | bitEx_p1_dx = xP - xQ | | | | |");
            _EC_FN_(fr, aim_bignum_signed_unsafe(bitEx_p1_dx, bitEx_p1_dx, bitEx_p1_p));
            _PRINT_BIGNUM_(bitEx_p1_dx, "| | | | | bitEx_p1_dx = (xP - xQ) mod bitEx_p1_p | | | | |");

            _EC_FN_(fr, mim_bignum_unsafe(bitEx_p1_dxi, bitEx_p1_dx, bitEx_p1_p));
            _PRINT_BIGNUM_(bitEx_p1_dxi, "| | | | | bitEx_p1_dx^(-1) = (xP - xQ)^(-1) mod bitEx_p1_p | | | | |");
            if(fr == E_HAS_NO_VALUE) {
                _DPRINTF_("[WARNING] slope(m) is INFINITE, coordinates have to be set (0, 0)\r\n");
                slope_is_INFINITE = true;
            }

            if(!slope_is_INFINITE) {
                _EC_FN_(fr, mul_bignum_unsigned_unsafe(bitEx_x2_mul, bitEx_p1_dy, bitEx_p1_dxi));
                _PRINT_BIGNUM_(bitEx_x2_mul, "| | | | | m = (yP - yQ)(xP - xQ)^(-1) | | | | |");
                _EC_FN_(fr, mod_bignum_unsafe(bitEx_p1_m, bitEx_x2_mul, p));
                _PRINT_BIGNUM_(bitEx_p1_m, "| | | | | m = (yP - yQ)(xP - xQ)^(-1) mod p | | | | |");
            }

            rmBigNum(&bitEx_x2_mul);

            rmBigNum(&bitEx_p1_dy);
            rmBigNum(&bitEx_p1_dx);
            rmBigNum(&bitEx_p1_dxi);
        }
        else
        {
            /* P == Q, xP == xQ, yP == yQ*/
            _DPRINTF_("P == Q\n");

            bignum_s* bitEx_x2_mul = mkBigNum(EC_BIT_X2(ec_bits));

            bignum_s* bitEx_p1_pow_x = mkBigNum(EC_BIT_P1(ec_bits));// by bit expension, unsigned to signed on addtion
            bignum_s* bitEx_p1_numer = mkBigNum(EC_BIT_P1(ec_bits));// by bit expension, unsigned to signed on addtion
            bignum_s* bitEx_p1_denom = mkBigNum(EC_BIT_P1(ec_bits));// by bit expension, unsigned to signed on addtion

            // x^2
            _EC_FN_(fr, mul_bignum_unsigned(bitEx_x2_mul, xP, xP));
            _PRINT_BIGNUM_(bitEx_x2_mul, "| | | | | xP^2 | | | | |");
            _EC_FN_(fr, mod_bignum_unsafe(bitEx_p1_pow_x, bitEx_x2_mul, p));
            _PRINT_BIGNUM_(bitEx_p1_pow_x, "| | | | | (xP^2) mod p  | | | | |");

            // x^2 + a
            _EC_FN_(fr, add_bignum_unsigned_unsafe(bitEx_p1_numer, bitEx_p1_pow_x, a));
            _PRINT_BIGNUM_(bitEx_p1_numer, "| | | | | xP^2 + a | | | | |");
            _EC_FN_(fr, aim_bignum_signed_unsafe(bitEx_p1_numer, bitEx_p1_numer, bitEx_p1_p));
            _PRINT_BIGNUM_(bitEx_p1_numer, "| | | | | (xP^2 + a) mod bitEx_p1_p | | | | |");
            // 2 * x^2
            _EC_FN_(fr, asl1b_bignum_self(bitEx_p1_pow_x, NULL, 0U));
            _PRINT_BIGNUM_(bitEx_p1_pow_x, "| | | | | 2 * xP^2 | | | | |");
            _EC_FN_(fr, aim_bignum_signed_unsafe(bitEx_p1_pow_x, bitEx_p1_pow_x, bitEx_p1_p));
            _PRINT_BIGNUM_(bitEx_p1_pow_x, "| | | | | (2 * xP^2) mod bitEx_p1_p | | | | |");
            // (x^2 + a) += (2 * x^2)
            _EC_FN_(fr, add_bignum_signed_unsafe(bitEx_p1_numer, bitEx_p1_numer, bitEx_p1_pow_x));
            _PRINT_BIGNUM_(bitEx_p1_numer, "| | | | | (3 * xP^2) + a | | | | |");
            _EC_FN_(fr, aim_bignum_signed_unsafe(bitEx_p1_numer, bitEx_p1_numer, bitEx_p1_p));
            _PRINT_BIGNUM_(bitEx_p1_numer, "| | | | | ((3 * xP^2) + a) mod bitEx_p1_p | | | | |");

            // 2 * y
#if 0 /* P_IS_Q_AND_Q_IS_NEGATIVE_DOUBLING */
            _EC_FN_(fr, add_bignum_unsigned_unsafe(bitEx_p1_denom, yP, yP));
#else
            if(!nQ) {
                cpy_bignum_unsigned_unsafe(bitEx_p1_denom, yP);
                _PRINT_BIGNUM_(bitEx_p1_denom, "| | | | | bitEx_p1_denom(yP, 1bit extention) | | | | |");
            } else {
                cpy_bignum_twos_signed_unsafe(bitEx_p1_denom, yP);
                _PRINT_BIGNUM_(bitEx_p1_denom, "| | | | | -bitEx_p1_denom(-yP, 1bit extention) | | | | |");
            }
            _EC_FN_(fr, asl1b_bignum_self(bitEx_p1_denom, NULL, 0U));
#endif/* P_IS_Q_AND_Q_IS_NEGATIVE_DOUBLING */
            _PRINT_BIGNUM_(bitEx_p1_denom, "| | | | | 2 * yP | | | | |");
            _EC_FN_(fr, aim_bignum_signed_unsafe(bitEx_p1_denom, bitEx_p1_denom, bitEx_p1_p));
            _PRINT_BIGNUM_(bitEx_p1_denom, "| | | | | (2 * yP) mod bitEx_p1_p | | | | |");

            _EC_FN_(fr, mim_bignum_unsafe(bitEx_p1_denom, bitEx_p1_denom, bitEx_p1_p));
            _PRINT_BIGNUM_(bitEx_p1_denom, "| | | | | (2 * yP)^(-1) mod bitEx_p1_p | | | | |");
            if(fr == E_HAS_NO_VALUE) {
                _DPRINTF_("[WARNING] slope(m) is INFINITE, coordinates have to be set (0, 0)\r\n");
                slope_is_INFINITE = true;
            }

            if(!slope_is_INFINITE) {
                _EC_FN_(fr, mul_bignum_unsigned(bitEx_x2_mul, bitEx_p1_numer, bitEx_p1_denom));
                _PRINT_BIGNUM_(bitEx_x2_mul, "| | | | | ((3 * xP^2) + a) * (2 * yP)^(-1) | | | | |");
                _EC_FN_(fr, mod_bignum_unsafe(bitEx_p1_m, bitEx_x2_mul, p));
                _PRINT_BIGNUM_(bitEx_p1_m, "| | | | | (((3 * xP^2) + a) * (2 * yP)^(-1)) mod p | | | | |");
            }

            rmBigNum(&bitEx_x2_mul);

            rmBigNum(&bitEx_p1_pow_x);
            rmBigNum(&bitEx_p1_numer);
            rmBigNum(&bitEx_p1_denom);
        }
        _PRINT_BIGNUM_(bitEx_p1_m, "| | | | | m | | | | |");

        /* Get xR */
        {
            bignum_s* bitEx_x2_mul = mkBigNum(EC_BIT_X2(ec_bits));

            bignum_s* bitEx_p1_pow_m = mkBigNum(EC_BIT_P1(ec_bits));// by bit expension, unsigned to signed on addtion

            // m^2
            _EC_FN_(fr, mul_bignum_unsigned(bitEx_x2_mul, bitEx_p1_m, bitEx_p1_m));
            _PRINT_BIGNUM_(bitEx_x2_mul, "| | | | | m^2 | | | | |");
            _EC_FN_(fr, mod_bignum_unsafe(bitEx_p1_pow_m, bitEx_x2_mul, p));
            _PRINT_BIGNUM_(bitEx_p1_pow_m, "| | | | | m^2 mod p | | | | |");

            // m^2 - xP
            _EC_FN_(fr, sub_bignum_unsigned_unsafe(bitEx_p1_x, bitEx_p1_pow_m, xP));
            _PRINT_BIGNUM_(xP, "| | | | | xP | | | | |");
            _PRINT_BIGNUM_(bitEx_p1_x, "| | | | | m^2 - xP | | | | |");
            _EC_FN_(fr, aim_bignum_signed_unsafe(bitEx_p1_x, bitEx_p1_x, bitEx_p1_p));
            _PRINT_BIGNUM_(bitEx_p1_x, "| | | | | (m^2 - xP) mod bitEx_p1_p | | | | |");
            // m(^2 - xP) - xQ
            _EC_FN_(fr, sub_bignum_unsigned_unsafe(bitEx_p1_x, bitEx_p1_x, xQ));
            _PRINT_BIGNUM_(xQ, "| | | | | xQ | | | | |");
            _PRINT_BIGNUM_(bitEx_p1_x, "| | | | | m^2 - xP - xQ | | | | |");
            // ( m(^2 - xP) - xQ ) mod bitEx_p1_p
            _EC_FN_(fr, aim_bignum_signed_unsafe(bitEx_p1_x, bitEx_p1_x, bitEx_p1_p));
            _PRINT_BIGNUM_(bitEx_p1_x, "| | | | | (m^2 - xP - xQ) mod bitEx_p1_p | | | | |");

            rmBigNum(&bitEx_x2_mul);

            rmBigNum(&bitEx_p1_pow_m);
        }
        _PRINT_BIGNUM_(bitEx_p1_x, "| | | | | xR(bitEx_p1_x) | | | | |");

        /* Get yR */
        {
            bignum_s* bitEx_x2_mul = mkBigNum(EC_BIT_X2(ec_bits));

            _EC_FN_(fr, sub_bignum_unsigned_unsafe(bitEx_p1_y, bitEx_p1_x, xP));
            _PRINT_BIGNUM_(xP, "| | | | | xP | | | | |");
            _PRINT_BIGNUM_(bitEx_p1_y, "| | | | | xR - xP | | | | |");
            _EC_FN_(fr, aim_bignum_signed_unsafe(bitEx_p1_y, bitEx_p1_y, bitEx_p1_p));
            _PRINT_BIGNUM_(bitEx_p1_y, "| | | | | (xR - xP) mod bitEx_p1_p | | | | |");
            _EC_FN_(fr, mul_bignum_unsigned(bitEx_x2_mul, bitEx_p1_m, bitEx_p1_y));
            _PRINT_BIGNUM_(bitEx_x2_mul, "| | | | | m(xR - xP) | | | | |");

            _EC_FN_(fr, mod_bignum_unsafe(bitEx_p1_y, bitEx_x2_mul, p));
            _PRINT_BIGNUM_(bitEx_p1_y, "| | | | | m(xR - xP) mod p | | | | |");

            _EC_FN_(fr, add_bignum_unsigned_unsafe(bitEx_p1_y, yP, bitEx_p1_y));
            _PRINT_BIGNUM_(yP, "| | | | | yP | | | | |");
            _PRINT_BIGNUM_(bitEx_p1_y, "| | | | | yP + m(xR - xP) | | | | |");
            _EC_FN_(fr, aim_bignum_signed_unsafe(bitEx_p1_y, bitEx_p1_y, bitEx_p1_p));
            _PRINT_BIGNUM_(bitEx_p1_y, "| | | | | ( yP + m(xR - xP) ) mod bitEx_p1_p | | | | |");

            rmBigNum(&bitEx_x2_mul);
        }
        _PRINT_BIGNUM_(bitEx_p1_y, "| | | | | yR | | | | |");

        // -yR
        _EC_FN_(fr, cpy_bignum_twos_signed_safe(bitEx_p1_y, bitEx_p1_y));
        _PRINT_BIGNUM_(bitEx_p1_y, "| | | | | (-yR) | | | | |");

        // (-yR) mod bitEx_p1_p
        _EC_FN_(fr, aim_bignum_signed_unsafe(bitEx_p1_y, bitEx_p1_y, bitEx_p1_p));
        _PRINT_BIGNUM_(bitEx_p1_y, "| | | | | (-yR) mod bitEx_p1_p | | | | |");

        if(!slope_is_INFINITE) {
            _EC_FN_(fr, cpy_bignum_unsigned_unsafe(xR, bitEx_p1_x));
            _EC_FN_(fr, cpy_bignum_unsigned_unsafe(yR, bitEx_p1_y));
        } else {
            _DPRINTF_("[WARNING] slope(m) is INFINITE, coordinates have to be set (0, 0)\r\n");
            _PRINT_BIGNUM_(bitEx_p1_x, "| | | | | x (INFINITE, clear to 0) | | | | |");
            _PRINT_BIGNUM_(bitEx_p1_y, "| | | | | y (INFINITE, clear to 0) | | | | |");
            _EC_FN_(fr, clr_bignum(xR));
            _EC_FN_(fr, clr_bignum(yR));
        }

        rmBigNum(&bitEx_p1_m);
        rmBigNum(&bitEx_p1_x);
        rmBigNum(&bitEx_p1_y);

        rmBigNum(&bitEx_p1_p);
    } else {
        _DPRINTF_("[INFO] Point P or Q was Identity Elements, just adding two points\r\n");
        _EC_FN_(fr, add_bignum_unsigned_unsafe(xR, xP, xQ));
        _EC_FN_(fr, add_bignum_unsigned_unsafe(yR, yP, yQ));
    }
}

wnaf_pre_compute_ec_s* mkWNAF_preCompute_ec(const uwnaf w, const size_t ec_bits)
{
    if(!chkWNAF_window_lenth(w))    return NULL;

    wnaf_pre_compute_ec_s* p = (wnaf_pre_compute_ec_s*)malloc(sizeof(wnaf_pre_compute_ec_s));

    p->w = w;
    p->l = getWNAF_preCompupte_lengh(w);
    p->x = (bignum_s**)calloc(p->l, sizeof(bignum_s*));
    p->y = (bignum_s**)calloc(p->l, sizeof(bignum_s*));

    for(uwnaf i = 0U; i < p->l; i++)
    {
        p->x[i] = mkBigNum(ec_bits);
        p->y[i] = mkBigNum(ec_bits);
    }

    return p;
}

int rmWNAF_preCompute_ec(wnaf_pre_compute_ec_s** p)
{
    if(p == NULL)   return -1;
    if(*p == NULL)  return -1;

    for(uwnaf i = 0U; i < (*p)->l; i++)
    {
         rmBigNum(&((*p)->x[i]));
         rmBigNum(&((*p)->y[i]));
    }

    free((*p)->x);
    free((*p)->y);

    free(*p);

    *p = NULL;

    return 0;
}

/*
 * ec_adsbPoints_ext
 * pc: pre-computation
 * xP, yP: Result of ec point doubling
 * ec_bits: bit length of ec point
 * p: prime number for modulo p(mod p)
 * a: coeffient of ec curve, y^2 = x^3 + a*x + b
 * w: window length of wNAF
 */
void ec_preCompute_WNAF(wnaf_pre_compute_ec_s* pc, \
        const bignum_s* xP, const bignum_s* yP, \
        const size_t ec_bits, const bignum_s* a, const bignum_s* p, \
        const uwnaf w, const bool ign_sign)
{
    if(!((pc != NULL) && (xP != NULL) && (yP != NULL) && (p != NULL) && (a != NULL)))   return; // NULL pointer
    if(!((xP->bits == ec_bits) && (yP->bits == ec_bits))) return; // x and y of point have to be same.
    bignum_s* x2P, * y2P;

    x2P = mkBigNum(ec_bits);
    y2P = mkBigNum(ec_bits);

    ec_addPoints(x2P, y2P, xP, yP, xP, yP, ec_bits, a, p, ign_sign);

    _PRINT_BIGNUM_(x2P, "x2P");
    _PRINT_BIGNUM_(y2P, "y2P");
    cpy_bignum_unsigned_safe(pc->x[0], xP);
    cpy_bignum_unsigned_safe(pc->y[0], yP);

    for(uwnaf i = 1U; i < pc->l; i++)
    {
        ec_addPoints(pc->x[i], pc->y[i], pc->x[i-1], pc->y[i-1], x2P, y2P, ec_bits, a, p, ign_sign);
    }

    rmBigNum(&x2P);
    rmBigNum(&y2P);
}

void ec_scalarMul_WNAF(
        bignum_s* xdP, bignum_s* ydP, \
        const bignum_s* d, \
        const bignum_s* xP, const bignum_s* yP, \
        const size_t ec_bits, const bignum_s* a, const bignum_s* p, \
        const uwnaf w, const bool ign_sign)
{
    uwnaf wnaf_idx;
    wnaf_s* wnaf_d = mkWNAF(w, ec_bits);
    wnaf_pre_compute_ec_s* wnaf_pc = mkWNAF_preCompute_ec(w, ec_bits);

    clr_bignum(xdP);
    clr_bignum(ydP);

    convBigNum_wNAF(wnaf_d, d);
    _PRINT_BIGNUM_(d, "d in ec_scalarMul_WNAF()");
    _PRINT_wNAF_INFO_(wnaf_d, "bignum to wnaf");
    ec_preCompute_WNAF(wnaf_pc, xP, yP, ec_bits, a, p, w, ign_sign);
    _PRINT_wNAF_(wnaf_pc, "Pre-Computation in ec_scalarMul_WNAF()");

    for(size_t i = (wnaf_d->bits - 1UL); i != SIZE_MAX; i--)
    {
        ec_doublePoints_self(xdP, ydP, ec_bits, a, p, ign_sign);
        _DPRINTF_("bit=%lu, ", i); _PRINT_BIGNUM_(xdP, "doubled xdP");
        _DPRINTF_("bit=%lu, ", i); _PRINT_BIGNUM_(ydP, "doubled ydP");

        if(wnaf_d->wnaf.ui[i] != 0U)
        {
            wnaf_idx = getWNAF_index(wnaf_d->wnaf.ui[i]);

            _DPRINTF_("[INFO] @%s, Line:%d, [OPERAND A]\r\n", __func__, __LINE__);
            _DPRINTF_("bit=%lu, WNAF=%d, N=%u", i, wnaf_d->wnaf.ui[i], wnaf_idx); _PRINT_BIGNUM_(xdP, "xdP");
            _DPRINTF_("bit=%lu, WNAF=%d, N=%u", i, wnaf_d->wnaf.ui[i], wnaf_idx); _PRINT_BIGNUM_(ydP, "ydP");

            if(!isNegWNAF(wnaf_d->wnaf.ui[i]))
            {
                // sum ec point
                _DPRINTF_("[ec_addPoints]\r\n");
                ec_addPoints(xdP, ydP, xdP, ydP, wnaf_pc->x[wnaf_idx], wnaf_pc->y[wnaf_idx], ec_bits, a, p, ign_sign);
            }
            else
            {
                // sub ec point
                _DPRINTF_("[ec_subPoints]\r\n");
                ec_subPoints(xdP, ydP, xdP, ydP, wnaf_pc->x[wnaf_idx], wnaf_pc->y[wnaf_idx], ec_bits, a, p, ign_sign);
            }
            _DPRINTF_("[INFO] @%s, Line:%d, [OPERAND B]\r\n", __func__, __LINE__);
            _DPRINTF_("bit=%lu, WNAF=%d, N=%u", i, wnaf_d->wnaf.ui[i], wnaf_idx); _PRINT_BIGNUM_(wnaf_pc->x[wnaf_idx], "x(2^(w-1)-1)P");
            _DPRINTF_("bit=%lu, WNAF=%d, N=%u", i, wnaf_d->wnaf.ui[i], wnaf_idx); _PRINT_BIGNUM_(wnaf_pc->y[wnaf_idx], "y(2^(w-1)-1)P");

            _DPRINTF_("[INFO] @%s, Line:%d, [RESULT]\r\n", __func__, __LINE__);
            _DPRINTF_("bit=%lu, WNAF=%d, N=%u", i, wnaf_d->wnaf.ui[i], wnaf_idx); _PRINT_BIGNUM_(xdP, "xdP");
            _DPRINTF_("bit=%lu, WNAF=%d, N=%u", i, wnaf_d->wnaf.ui[i], wnaf_idx); _PRINT_BIGNUM_(ydP, "ydP");
        }
    }

    rmWNAF(&wnaf_d);
    rmWNAF_preCompute_ec(&wnaf_pc);
}

// The point at infinity corresponds to (1 : 1 : 0), while the negative of (X : Y : Z) is (X :−Y : Z).
bool ec_isInfJacobi(const bignum_s* jXP, const bignum_s* jYP, const bignum_s* jZP)
{
    bignum_cmp_e cmpX;
    bignum_cmp_e cmpY;
    bignum_cmp_e cmpZ;

    cmpX = cmp1_bignum(jXP);
    cmpY = cmp1_bignum(jYP);
    cmpZ = cmp0_bignum(jZP);

    return ((cmpX == BIGNUM_CMP_ON) &&(cmpY == BIGNUM_CMP_ON) && (cmpZ == BIGNUM_CMP_ZO));
}

void ec_convAffineToJacobi(bignum_s* jXP, bignum_s* jYP, bignum_s* jZP, \
        const bignum_s* xP, const bignum_s* yP)
{
    ReturnType fr;

    _EC_FN_(fr, cpy_bignum_unsigned_safe(jXP, xP));
    _EC_FN_(fr, cpy_bignum_unsigned_safe(jYP, yP));
    _EC_FN_(fr, clr_bignum(jZP));
    _EC_FN_(fr, set1b_bignum(jZP, 0UL));
}

void ec_convJacobiToAffine(bignum_s* xP, bignum_s* yP, \
        const bignum_s* jXP, const bignum_s* jYP, const bignum_s* jZP, \
        const size_t ec_bits, const bignum_s* p)
{
    ReturnType fr;

    bignum_s* tmp_iZ1 = mkBigNum(ec_bits);
    bignum_s* tmp_iZ2 = mkBigNum(ec_bits);
    bignum_s* tmp_iZ3 = mkBigNum(ec_bits);
    bignum_s* tmp_mul = mkBigNum(EC_BIT_X2(ec_bits));

    // Z^(-1)
    _EC_FN_(fr, mim_bignum(tmp_iZ1, jZP, p));

    // Z^(-2)
    _EC_FN_(fr, mul_bignum_unsigned(tmp_mul, tmp_iZ1, tmp_iZ1));
    _EC_FN_(fr, mod_bignum_unsafe(tmp_iZ2, tmp_mul, p));

    // Z^(-3)
    _EC_FN_(fr, mul_bignum_unsigned(tmp_mul, tmp_iZ2, tmp_iZ1));
    _EC_FN_(fr, mod_bignum_unsafe(tmp_iZ3, tmp_mul, p));

    // X * Z^(-2)
    _EC_FN_(fr, mul_bignum_unsigned(tmp_mul, jXP, tmp_iZ2));
    _EC_FN_(fr, mod_bignum_unsafe(xP, tmp_mul, p));

    // Y * Z^(-3)
    _EC_FN_(fr, mul_bignum_unsigned(tmp_mul, jYP, tmp_iZ3));
    _EC_FN_(fr, mod_bignum_unsafe(yP, tmp_mul, p));

    rmBigNum(&tmp_iZ1);
    rmBigNum(&tmp_iZ2);
    rmBigNum(&tmp_iZ3);
    rmBigNum(&tmp_mul);
}

void ec_doublingPoint_inJacobi(bignum_s* jXP, bignum_s* jYP, bignum_s* jZP, \
        const bool nP, \
        const size_t ec_bits, const bignum_s* a, const bignum_s* p)
{
    // added condition that: P != −P, jYP != -jYP

    ReturnType fr;

    bignum_s* bitEx_p1_p = mkBigNum(EC_BIT_P1(ec_bits));

    bignum_s* jX1P = mkBigNum(ec_bits);
    bignum_s* jY1P = mkBigNum(ec_bits);
    bignum_s* jZ1P = mkBigNum(ec_bits);

    bignum_s* t_x2_mul = mkBigNum(EC_BIT_X2(ec_bits));
    bignum_s* t_p1_buf = mkBigNum(EC_BIT_P1(ec_bits));
    bignum_s* t_p0_buf = mkBigNum(ec_bits);

    bignum_s* tmp_A = mkBigNum(ec_bits);
    bignum_s* tmp_B = mkBigNum(ec_bits);
    bignum_s* tmp_C = mkBigNum(ec_bits);
    bignum_s* tmp_D = mkBigNum(ec_bits);

    _EC_FN_(fr, cpy_bignum_unsigned_safe(bitEx_p1_p, p));

    _EC_FN_(fr, cpy_bignum_unsigned_safe(jX1P, jXP));
    _EC_FN_(fr, cpy_bignum_unsigned_safe(jY1P, jYP));
    _EC_FN_(fr, cpy_bignum_unsigned_safe(jZ1P, jZP));

    #define X_1 jX1P
    #define Y_1 jY1P
    #define Z_1 jZ1P

    #define X_3 jXP
    #define Y_3 jYP
    #define Z_3 jZP

    _PRINT_BIGNUM_(bitEx_p1_p, "| | | | | GF(bitEx_p1_p) | | | | |");

    // A = Y_1^2
    _PRINT_BIGNUM_(Y_1, "| | | | | Y_1 | | | | |");
    _EC_FN_(fr, mul_bignum_unsigned(t_x2_mul, Y_1, Y_1));
    _EC_FN_(fr, mod_bignum_unsafe(tmp_A, t_x2_mul, bitEx_p1_p));
    _PRINT_BIGNUM_(tmp_A, "| | | | | tmp_A = Y_1^2 mod bitEx_p1_p | | | | |");

    // B = 4 * X_1 * A
    _PRINT_BIGNUM_(X_1, "| | | | | X_1 | | | | |");
    _PRINT_BIGNUM_(tmp_A, "| | | | | tmp_A | | | | |");
    _EC_FN_(fr, mul_bignum_unsigned(t_x2_mul, X_1, tmp_A));
    _EC_FN_(fr, mod_bignum_unsafe(t_x2_mul, t_x2_mul, bitEx_p1_p));
    _PRINT_BIGNUM_(t_x2_mul, "| | | | |  t_x2_mul = X_1 * tmp_A mod bitEx_p1_p | | | | |");
    _EC_FN_(fr, lslb_bignum_self(t_x2_mul, 2UL));
    _EC_FN_(fr, mod_bignum_unsafe(tmp_B, t_x2_mul, bitEx_p1_p));
    _PRINT_BIGNUM_(tmp_B, "| | | | |  tmp_B = 4 * t_x2_mul mod bitEx_p1_p | | | | |");

    // C = 8 * A^2
    _PRINT_BIGNUM_(tmp_A, "| | | | | tmp_A | | | | |");
    _EC_FN_(fr, mul_bignum_unsigned(t_x2_mul, tmp_A, tmp_A));
    _EC_FN_(fr, mod_bignum_unsafe(t_x2_mul, t_x2_mul, bitEx_p1_p));
    _PRINT_BIGNUM_(t_x2_mul, "| | | | |  t_x2_mul = tmp_A^2 mod bitEx_p1_p | | | | |");
    _EC_FN_(fr, lslb_bignum_self(t_x2_mul, 3UL));
    _EC_FN_(fr, mod_bignum_unsafe(tmp_C, t_x2_mul, bitEx_p1_p));
    _PRINT_BIGNUM_(tmp_C, "| | | | |  tmp_C = 8 * tmp_A mod bitEx_p1_p | | | | |");

    // D = 3 * X_1^2 + a * Z_1^4
    // tmp_D = a * Z_1^4
    // t_p0_buf = Z_1^2
    _PRINT_BIGNUM_(Z_1, "| | | | | Z_1 | | | | |");
    _EC_FN_(fr, mul_bignum_unsigned(t_x2_mul, Z_1, Z_1));
    _EC_FN_(fr, mod_bignum_unsafe(t_p0_buf, t_x2_mul, bitEx_p1_p));
    _PRINT_BIGNUM_(t_p0_buf, "| | | | |  t_p0_buf = Z_1^2 mod bitEx_p1_p | | | | |");
    // t_p0_buf = Z_1^4 = t_p0_buf * t_p0_buf
    _PRINT_BIGNUM_(t_p0_buf, "| | | | |  t_p0_buf | | | | |");
    _EC_FN_(fr, mul_bignum_unsigned(t_x2_mul, t_p0_buf, t_p0_buf));
    _EC_FN_(fr, mod_bignum_unsafe(t_p0_buf, t_x2_mul, bitEx_p1_p));
    _PRINT_BIGNUM_(t_p0_buf, "| | | | | t_p0_buf = t_p0_buf^2 mod bitEx_p1_p | | | | |");
    // tmp_D = a * Z_1^4 = a * t_p0_buf
    _PRINT_BIGNUM_(a, "| | | | | a | | | | |");
    _PRINT_BIGNUM_(t_p0_buf, "| | | | | t_p0_buf | | | | |");
    _EC_FN_(fr, mul_bignum_unsigned(t_x2_mul, a, t_p0_buf));
    _EC_FN_(fr, mod_bignum_unsafe(tmp_D, t_x2_mul, bitEx_p1_p));
    _PRINT_BIGNUM_(tmp_D, "| | | | | tmp_D = a * t_p0_buf mod bitEx_p1_p | | | | |");
    // t_p0_buf = X_1^2
    _PRINT_BIGNUM_(X_1, "| | | | | X_1 | | | | |");
    _EC_FN_(fr, mul_bignum_unsigned(t_x2_mul, X_1, X_1));
    _EC_FN_(fr, mod_bignum_unsafe(t_p0_buf, t_x2_mul, bitEx_p1_p));
    _PRINT_BIGNUM_(t_p0_buf, "| | | | |  t_p0_buf = X_1^2 mod bitEx_p1_p | | | | |");
    // t_p1_buf = 2 * X_1^2
    _PRINT_BIGNUM_(t_p0_buf, "| | | | |  t_p0_buf | | | | |");
    _EC_FN_(fr, cpy_bignum_unsigned_unsafe(t_p1_buf, t_p0_buf));
    _EC_FN_(fr, lslb_bignum_self(t_p1_buf, 1UL));
    _PRINT_BIGNUM_(t_p1_buf, "| | | | |  t_p1_buf = 2 * t_p0_buf | | | | |");
    _EC_FN_(fr, aim_bignum_signed_unsafe(t_p1_buf, t_p1_buf, bitEx_p1_p));
    _PRINT_BIGNUM_(t_p1_buf, "| | | | |  t_p1_buf = 2 * t_p0_buf mod bitEx_p1_p | | | | |");
    // t_p0_buf = 3 * X_1^2 = 2 * X_1^2 + X_1^2 = t_p1_buf + t_p0_buf
    _PRINT_BIGNUM_(t_p0_buf, "| | | | |  t_p0_buf | | | | |");
    _PRINT_BIGNUM_(t_p1_buf, "| | | | |  t_p1_buf | | | | |");
    _EC_FN_(fr, add_bignum_unsigned_unsafe(t_p1_buf, t_p1_buf, t_p0_buf));
    _EC_FN_(fr, aim_bignum_signed_unsafe(t_p0_buf, t_p1_buf, bitEx_p1_p));
    _PRINT_BIGNUM_(t_p0_buf, "| | | | |  t_p0_buf = t_p1_buf + t_p0_buf mod bitEx_p1_p | | | | |");
    // tmp_D = (3 * X_1^2) + (a * Z_1^4) = t_p0_buf + tmp_D
    _PRINT_BIGNUM_(t_p0_buf, "| | | | |  t_p0_buf | | | | |");
    _PRINT_BIGNUM_(tmp_D, "| | | | |  tmp_D | | | | |");
    _EC_FN_(fr, add_bignum_unsigned_unsafe(t_p1_buf, t_p0_buf, tmp_D));
    _EC_FN_(fr, aim_bignum_signed_unsafe(tmp_D, t_p1_buf, bitEx_p1_p));
    _PRINT_BIGNUM_(tmp_D, "| | | | |  tmp_D = t_p0_buf + tmp_D mod bitEx_p1_p | | | | |");

    // X_3 = D^2 - 2 * B
    // X_3 = D^2
    _PRINT_BIGNUM_(tmp_D, "| | | | |  tmp_D | | | | |");
    _EC_FN_(fr, mul_bignum_unsigned(t_x2_mul, tmp_D, tmp_D));
    _EC_FN_(fr, mod_bignum_unsafe(X_3, t_x2_mul, bitEx_p1_p));
    _PRINT_BIGNUM_(X_3, "| | | | |  X_3 = tmp_D^2 mod bitEx_p1_p | | | | |");
    // t_p0_buf = 2 * B
    _PRINT_BIGNUM_(tmp_B, "| | | | |  tmp_B | | | | |");
    _EC_FN_(fr, cpy_bignum_unsigned_unsafe(t_p1_buf, tmp_B));
    _EC_FN_(fr, lslb_bignum_self(t_p1_buf, 1UL));
    _EC_FN_(fr, aim_bignum_signed_unsafe(t_p0_buf, t_p1_buf, bitEx_p1_p));
    _PRINT_BIGNUM_(t_p0_buf, "| | | | |  t_p0_buf = 2 * tmp_B mod bitEx_p1_p | | | | |");
    // X_3 =  (D^2) - (2 * B) = X_3 - t_p0_buf
    _PRINT_BIGNUM_(X_3, "| | | | |  X_3 | | | | |");
    _PRINT_BIGNUM_(t_p0_buf, "| | | | |  t_p0_buf | | | | |");
    _EC_FN_(fr, sub_bignum_unsigned_unsafe(t_p1_buf, X_3, t_p0_buf));
    _EC_FN_(fr, aim_bignum_signed_unsafe(X_3, t_p1_buf, bitEx_p1_p));
    _PRINT_BIGNUM_(X_3, "| | | | |  X_3 = X_3 - t_p0_buf mod bitEx_p1_p | | | | |");

    // Y_3 = D * (B - X_3) - C
    // t_p0_buf = (B - X_3)
    _PRINT_BIGNUM_(tmp_B, "| | | | |  tmp_B | | | | |");
    _PRINT_BIGNUM_(X_3, "| | | | |  X_3 | | | | |");
    _EC_FN_(fr, sub_bignum_unsigned_unsafe(t_p1_buf, tmp_B, X_3));
    _EC_FN_(fr, aim_bignum_signed_unsafe(t_p0_buf, t_p1_buf, bitEx_p1_p));
    _PRINT_BIGNUM_(t_p0_buf, "| | | | |  t_p0_buf = tmp_B - X_3 mod bitEx_p1_p | | | | |");
    // t_p0_buf = D * (B - X_3) = D * t_p0_buf
    _PRINT_BIGNUM_(tmp_D, "| | | | |  tmp_D | | | | |");
    _PRINT_BIGNUM_(t_p0_buf, "| | | | |  t_p0_buf | | | | |");
    _EC_FN_(fr, mul_bignum_unsigned(t_x2_mul, tmp_D, t_p0_buf));
    _EC_FN_(fr, mod_bignum_unsafe(t_p0_buf, t_x2_mul, bitEx_p1_p));
    _PRINT_BIGNUM_(t_p0_buf, "| | | | |  t_p0_buf = tmp_D * t_p0_buf mod bitEx_p1_p | | | | |");
    // Y_3 =  (D * (B - X_3)) - C = t_p0_buf - C
    _PRINT_BIGNUM_(t_p0_buf, "| | | | |  t_p0_buf | | | | |");
    _PRINT_BIGNUM_(tmp_C, "| | | | |  tmp_C | | | | |");
    _EC_FN_(fr, sub_bignum_unsigned_unsafe(t_p1_buf, t_p0_buf, tmp_C));
    _EC_FN_(fr, aim_bignum_signed_unsafe(Y_3, t_p1_buf, bitEx_p1_p));
    _PRINT_BIGNUM_(Y_3, "| | | | |  Y_3 = t_p0_buf - tmp_C mod bitEx_p1_p | | | | |");

    // Z_3 = 2 * Y_1 * Z_1
    // t_p0_buf = 2 * Y_1
    _PRINT_BIGNUM_(Y_1, "| | | | |  Y_1 | | | | |");
    if(!nP) {
        // positive P(+P)
        _EC_FN_(fr, cpy_bignum_unsigned_safe(t_p1_buf, Y_1));
        _EC_FN_(fr, aim_bignum_signed_unsafe(t_p1_buf, t_p1_buf, bitEx_p1_p));
        _PRINT_BIGNUM_(t_p1_buf, "| | | | | t_p1_buf = Y_1 mod bitEx_p1_p | | | | |");
    }
    else {
        // negative P(-P)
        _EC_FN_(fr, cpy_bignum_twos_signed_safe(t_p1_buf, Y_1));
        _EC_FN_(fr, aim_bignum_signed_unsafe(t_p1_buf, t_p1_buf, bitEx_p1_p));
        _PRINT_BIGNUM_(t_p1_buf, "| | | | | t_p1_buf = -Y_1 mod bitEx_p1_p | | | | |");
    }
    _EC_FN_(fr, lslb_bignum_self(t_p1_buf, 1UL));
    _EC_FN_(fr, aim_bignum_signed_unsafe(t_p0_buf, t_p1_buf, bitEx_p1_p));
    _PRINT_BIGNUM_(t_p0_buf, "| | | | |  t_p0_buf = 2 * Y_1 | | | | |");
    // Z_3 = (2 * Y_1) * Z_1 = t_p0_buf * Z_1, alias Z_3 = Z_1
    _EC_FN_(fr, mul_bignum_unsigned(t_x2_mul, t_p0_buf, Z_1));
    _EC_FN_(fr, mod_bignum_unsafe(Z_3, t_x2_mul, bitEx_p1_p));

    #undef X_1
    #undef Y_1
    #undef Z_1

    #undef X_3
    #undef Y_3
    #undef Z_3

    rmBigNum(&bitEx_p1_p);

    rmBigNum(&jX1P);
    rmBigNum(&jY1P);
    rmBigNum(&jZ1P);

    rmBigNum(&t_x2_mul);
    rmBigNum(&t_p1_buf);
    rmBigNum(&t_p0_buf);

    rmBigNum(&tmp_A);
    rmBigNum(&tmp_B);
    rmBigNum(&tmp_C);
    rmBigNum(&tmp_D);
}

void ec_calPoint_AffineIntoJacobi_ext(bignum_s* jXR, bignum_s* jYR, bignum_s* jZR, \
        const bignum_s* jXP, const bignum_s* jYP, const bignum_s* jZP, \
        const bool nQ, \
        const bignum_s* xQ, const bignum_s* yQ, \
        const size_t ec_bits, const bignum_s* a, const bignum_s* p)
{
    // added condition Z_1(jZP) != 0
    // added condition that: P != +-Q

    ReturnType fr;

    bignum_s* bitEx_p1_p = mkBigNum(EC_BIT_P1(ec_bits));

    bignum_s* jX1P = mkBigNum(ec_bits);
    bignum_s* jY1P = mkBigNum(ec_bits);
    bignum_s* jZ1P = mkBigNum(ec_bits);

    bignum_s* t_x2_mul = mkBigNum(EC_BIT_X2(ec_bits));
    bignum_s* t_p1_buf = mkBigNum(EC_BIT_P1(ec_bits));
    bignum_s* t_p0_buf = mkBigNum(ec_bits);

    bignum_s* tmp_A = mkBigNum(ec_bits);
    bignum_s* tmp_B = mkBigNum(ec_bits);
    bignum_s* tmp_C = mkBigNum(ec_bits);
    bignum_s* tmp_D = mkBigNum(ec_bits);
    bignum_s* tmp_E = mkBigNum(ec_bits);
    bignum_s* tmp_F = mkBigNum(ec_bits);
    bignum_s* tmp_G = mkBigNum(ec_bits);
    bignum_s* tmp_H = mkBigNum(ec_bits);
    bignum_s* tmp_I = mkBigNum(ec_bits);

    _EC_FN_(fr, cpy_bignum_unsigned_safe(bitEx_p1_p, p));

    _EC_FN_(fr, cpy_bignum_unsigned_safe(jX1P, jXP));
    _EC_FN_(fr, cpy_bignum_unsigned_safe(jY1P, jYP));
    _EC_FN_(fr, cpy_bignum_unsigned_safe(jZ1P, jZP));

    #define X_1 jX1P
    #define Y_1 jY1P
    #define Z_1 jZ1P

    #define X_2 xQ
    #define Y_2 yQ

    #define X_3 jXR
    #define Y_3 jYR
    #define Z_3 jZR

    _PRINT_BIGNUM_(bitEx_p1_p, "| | | | | GF(bitEx_p1_p) | | | | |");

    // A = Z_1^2
    _PRINT_BIGNUM_(Z_1, "| | | | | Z_1 | | | | |");
    _EC_FN_(fr, mul_bignum_unsigned(t_x2_mul, Z_1, Z_1));
    _EC_FN_(fr, mod_bignum_unsafe(tmp_A, t_x2_mul, bitEx_p1_p));
    _PRINT_BIGNUM_(tmp_A, "| | | | | tmp_A = Z_1^2 mod bitEx_p1_p | | | | |");
    // B = Z_1 * A
    _PRINT_BIGNUM_(Z_1, "| | | | | Z_1 | | | | |");
    _PRINT_BIGNUM_(tmp_A, "| | | | | tmp_A | | | | |");
    _EC_FN_(fr, mul_bignum_unsigned(t_x2_mul, Z_1, tmp_A));
    _EC_FN_(fr, mod_bignum_unsafe(tmp_B, t_x2_mul, bitEx_p1_p));
    _PRINT_BIGNUM_(tmp_B, "| | | | | tmp_B = Z_1 * tmp_A mod bitEx_p1_p | | | | |");
    // C = X_2 * A
    _PRINT_BIGNUM_(X_2, "| | | | | X_2 | | | | |");
    _PRINT_BIGNUM_(tmp_A, "| | | | | tmp_A | | | | |");
    _EC_FN_(fr, mul_bignum_unsigned(t_x2_mul, X_2, tmp_A));
    _EC_FN_(fr, mod_bignum_unsafe(tmp_C, t_x2_mul, bitEx_p1_p));
    _PRINT_BIGNUM_(tmp_C, "| | | | | tmp_C = X_2 * tmp_A mod bitEx_p1_p | | | | |");
    // D = Y_2 * B
    // t_p0_buf = Y_2 or -Y_2
    _PRINT_BIGNUM_(Y_2, "| | | | | Y_2 | | | | |");
    if(!nQ) { // add
        _EC_FN_(fr, cpy_bignum_unsigned_safe(t_p1_buf, Y_2));
        _EC_FN_(fr, aim_bignum_signed_unsafe(t_p0_buf, t_p1_buf, bitEx_p1_p));
        _PRINT_BIGNUM_(t_p0_buf, "| | | | | t_p0_buf = Y_2 | | | | |");
    }
    else { // sub
        _EC_FN_(fr, cpy_bignum_twos_signed_safe(t_p1_buf, Y_2));
        _EC_FN_(fr, aim_bignum_signed_unsafe(t_p0_buf, t_p1_buf, bitEx_p1_p));
        _PRINT_BIGNUM_(t_p0_buf, "| | | | | t_p0_buf = -Y_2 | | | | |");
    }
    _EC_FN_(fr, mul_bignum_unsigned(t_x2_mul, t_p0_buf, tmp_B));
    _EC_FN_(fr, mod_bignum_unsafe(tmp_D, t_x2_mul, bitEx_p1_p));
    _PRINT_BIGNUM_(tmp_D, "| | | | | tmp_D = t_p0_buf * tmp_B mod bitEx_p1_p | | | | |");
    // E = C - X_1
    _PRINT_BIGNUM_(tmp_C, "| | | | | tmp_C | | | | |");
    _PRINT_BIGNUM_(X_1, "| | | | | X_1 | | | | |");
    _EC_FN_(fr, sub_bignum_unsigned_unsafe(t_p1_buf, tmp_C, X_1));
    _EC_FN_(fr, aim_bignum_signed_unsafe(tmp_E, t_p1_buf, bitEx_p1_p));
    _PRINT_BIGNUM_(tmp_E, "| | | | | tmp_E = tmp_C - X_1 mod bitEx_p1_p | | | | |");
    // F = D − Y_1
    _PRINT_BIGNUM_(tmp_D, "| | | | | tmp_D | | | | |");
    _PRINT_BIGNUM_(Y_1, "| | | | | Y_1 | | | | |");
    _EC_FN_(fr, sub_bignum_unsigned_unsafe(t_p1_buf, tmp_D, Y_1));
    _EC_FN_(fr, aim_bignum_signed_unsafe(tmp_F, t_p1_buf, bitEx_p1_p));
    _PRINT_BIGNUM_(tmp_F, "| | | | | tmp_F = tmp_D - Y_1 mod bitEx_p1_p | | | | |");
    // G = E^2
    _PRINT_BIGNUM_(tmp_E, "| | | | | tmp_E | | | | |");
    _EC_FN_(fr, mul_bignum_unsigned(t_x2_mul, tmp_E, tmp_E));
    _EC_FN_(fr, mod_bignum_unsafe(tmp_G, t_x2_mul, bitEx_p1_p));
    _PRINT_BIGNUM_(tmp_G, "| | | | | tmp_G = tmp_E^2 mod bitEx_p1_p | | | | |");
    // H = G * E
    _PRINT_BIGNUM_(tmp_G, "| | | | | tmp_G | | | | |");
    _PRINT_BIGNUM_(tmp_E, "| | | | | tmp_E | | | | |");
    _EC_FN_(fr, mul_bignum_unsigned(t_x2_mul, tmp_G, tmp_E));
    _EC_FN_(fr, mod_bignum_unsafe(tmp_H, t_x2_mul, bitEx_p1_p));
    _PRINT_BIGNUM_(tmp_H, "| | | | | tmp_H = tmp_G * tmp_E mod bitEx_p1_p | | | | |");
    // I = X_1 * G
    _PRINT_BIGNUM_(X_1, "| | | | | X_1 | | | | |");
    _PRINT_BIGNUM_(tmp_G, "| | | | | tmp_G | | | | |");
    _EC_FN_(fr, mul_bignum_unsigned(t_x2_mul, X_1, tmp_G));
    _EC_FN_(fr, mod_bignum_unsafe(tmp_I, t_x2_mul, bitEx_p1_p));
    _PRINT_BIGNUM_(tmp_I, "| | | | | tmp_I = X_1 * tmp_G mod bitEx_p1_p | | | | |");

    // X_3 = F^2 − (H + 2 * I)
    // t_p1_buf = I<<1 = 2 * I
    _PRINT_BIGNUM_(tmp_I, "| | | | | tmp_I | | | | |");
    _EC_FN_(fr, cpy_bignum_unsigned_unsafe(t_p1_buf, tmp_I));
    _EC_FN_(fr, lslb_bignum_self(t_p1_buf, 1UL));
    _EC_FN_(fr, aim_bignum_unsigned_unsafe(t_p1_buf, t_p1_buf, bitEx_p1_p));
    _PRINT_BIGNUM_(t_p1_buf, "| | | | | t_p1_buf = 2 * tmp_I mod bitEx_p1_p | | | | |");
    // X_3 = H + (2 * I) = H + t_p1_buf
    _PRINT_BIGNUM_(tmp_H, "| | | | | tmp_H | | | | |");
    _PRINT_BIGNUM_(t_p1_buf, "| | | | | t_p1_buf | | | | |");
    _EC_FN_(fr, add_bignum_unsigned_unsafe(t_p1_buf, tmp_H, t_p1_buf));
    _EC_FN_(fr, aim_bignum_signed_unsafe(X_3, t_p1_buf, bitEx_p1_p));
    _PRINT_BIGNUM_(X_3, "| | | | | X_3 = tmp_H + t_p1_buf mod bitEx_p1_p | | | | |");
    // t_p0_buf = F^2
    _PRINT_BIGNUM_(tmp_F, "| | | | | tmp_F | | | | |");
    _EC_FN_(fr, mul_bignum_unsigned(t_x2_mul, tmp_F, tmp_F));
    _EC_FN_(fr, mod_bignum_unsafe(t_p0_buf, t_x2_mul, bitEx_p1_p));
    _PRINT_BIGNUM_(t_p0_buf, "| | | | | t_p0_buf = tmp_F^2 mod bitEx_p1_p | | | | |");
    // X_3 = (F^2) - (H + 2 * I = H) = t_p0_buf − X_3
    _PRINT_BIGNUM_(t_p0_buf, "| | | | | t_p0_buf | | | | |");
    _PRINT_BIGNUM_(X_3, "| | | | | X_3 | | | | |");
    _EC_FN_(fr, sub_bignum_unsigned_unsafe(t_p1_buf, t_p0_buf, X_3));
    _EC_FN_(fr, aim_bignum_signed_unsafe(X_3, t_p1_buf, bitEx_p1_p));
    _PRINT_BIGNUM_(X_3, "| | | | | X_3 = t_p0_buf - t_p0_buf mod bitEx_p1_p | | | | |");

    // Y_3 = F * (I − X_3) − Y_1 * H
    // t_p0_buf = Y_1 * H
    _PRINT_BIGNUM_(Y_1, "| | | | | Y_1 | | | | |");
    _PRINT_BIGNUM_(tmp_H, "| | | | | tmp_H | | | | |");
    _EC_FN_(fr, mul_bignum_unsigned(t_x2_mul, Y_1, tmp_H));
    _EC_FN_(fr, mod_bignum_unsafe(t_p0_buf, t_x2_mul, bitEx_p1_p));
    _PRINT_BIGNUM_(t_p0_buf, "| | | | | t_p0_buf = Y_1 * tmp_H mod bitEx_p1_p | | | | |");
    // Y_3 = (I − X_3)
    _PRINT_BIGNUM_(tmp_I, "| | | | | tmp_I | | | | |");
    _PRINT_BIGNUM_(X_3, "| | | | | X_3 | | | | |");
    _EC_FN_(fr, sub_bignum_unsigned_unsafe(t_p1_buf, tmp_I, X_3));
    _EC_FN_(fr, aim_bignum_signed_unsafe(Y_3, t_p1_buf, bitEx_p1_p));
    _PRINT_BIGNUM_(Y_3, "| | | | | Y_3 = tmp_I - X_3 mod bitEx_p1_p | | | | |");
    // Y_3 = F * (I − X_3) = F * Y_3
    _PRINT_BIGNUM_(tmp_F, "| | | | | tmp_F | | | | |");
    _PRINT_BIGNUM_(Y_3, "| | | | | Y_3 | | | | |");
    _EC_FN_(fr, mul_bignum_unsigned(t_x2_mul, tmp_F, Y_3));
    _EC_FN_(fr, mod_bignum_unsafe(Y_3, t_x2_mul, bitEx_p1_p));
    _PRINT_BIGNUM_(Y_3, "| | | | | Y_3 = tmp_F * Y_3 mod bitEx_p1_p | | | | |");
    // Y_3 = (F * (I − X_3)) - (Y_1 * H) = Y_3 − t_p0_buf
    _PRINT_BIGNUM_(Y_3, "| | | | | Y_3 | | | | |");
    _PRINT_BIGNUM_(t_p0_buf, "| | | | | t_p0_buf | | | | |");
    _EC_FN_(fr, sub_bignum_unsigned_unsafe(t_p1_buf, Y_3, t_p0_buf));
    _EC_FN_(fr, aim_bignum_signed_unsafe(Y_3, t_p1_buf, bitEx_p1_p));
    _PRINT_BIGNUM_(Y_3, "| | | | | Y_3 = Y_3 - t_p0_buf mod bitEx_p1_p | | | | |");

    // Z_3 = Z_1 * E
    _PRINT_BIGNUM_(Z_1, "| | | | | Z_1 | | | | |");
    _PRINT_BIGNUM_(tmp_E, "| | | | | tmp_E | | | | |");
    _EC_FN_(fr, mul_bignum_unsigned(t_x2_mul, Z_1, tmp_E));
    _EC_FN_(fr, mod_bignum_unsafe(Z_3, t_x2_mul, bitEx_p1_p));
    _PRINT_BIGNUM_(Z_3, "| | | | | Z_3 = Z_1 * tmp_E mod bitEx_p1_p | | | | |");

    #undef X_1
    #undef Y_1
    #undef Z_1

    #undef X_2
    #undef Y_2

    #undef X_3
    #undef Y_3
    #undef Z_3

    rmBigNum(&bitEx_p1_p);

    rmBigNum(&jX1P);
    rmBigNum(&jY1P);
    rmBigNum(&jZ1P);

    rmBigNum(&t_x2_mul);
    rmBigNum(&t_p1_buf);
    rmBigNum(&t_p0_buf);

    rmBigNum(&tmp_A);
    rmBigNum(&tmp_B);
    rmBigNum(&tmp_C);
    rmBigNum(&tmp_D);
    rmBigNum(&tmp_E);
    rmBigNum(&tmp_F);
    rmBigNum(&tmp_G);
    rmBigNum(&tmp_H);
    rmBigNum(&tmp_I);
}

#undef EC_BIT_P1
#undef EC_BIT_X2
