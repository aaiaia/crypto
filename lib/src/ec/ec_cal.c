#include "ec/ec_cal.h"

#include "bignum/bignum_alu.h"

#include "test/test_tool.h"


/*
 * ec_addPoints_ext
 * xR, yR: Result of ec point addition(sum)
 * xP, yP: Operand ec point P
 * xQ, yQ: Operand ec point Q
 * a: coeffient of ec curve, y^2 = x^3 + a*x + b
 * p: prime number for modulo p(mod p)
 */
#if 0 /* ec_addPoints_ext */
#include <stdio.h>
#define _DPRINTF_                   printf
#define _PRINT_BIGNUM_(p, title)    test_print_bignum(p, title)
#else
#define _DPRINTF_
#define _PRINT_BIGNUM_(p, title)
#endif/* ec_addPoints_ext */
void ec_addPoints_ext(bignum_s* xR, bignum_s* yR, \
        const bignum_s* xP, const bignum_s* yP, \
        const bool nQ, \
        const bignum_s* xQ, const bignum_s* yQ, \
        const size_t ec_bits, const bignum_s* a, const bignum_s* p, \
        const bool ign_sign)
{
#define BIT_P1(ec_bits)  (ec_bits+1UL)
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

        bignum_s* bitEx_p1_m = mkBigNum(BIT_P1(ec_bits));
        bignum_s* bitEx_p1_x = mkBigNum(BIT_P1(ec_bits));
        bignum_s* bitEx_p1_y = mkBigNum(BIT_P1(ec_bits));

        bignum_s* bitEx_p1_p = mkBigNum(BIT_P1(ec_bits));
        cpy_bignum_unsigned_unsafe(bitEx_p1_p, p);
        _PRINT_BIGNUM_(bitEx_p1_p, "| | | | | bitEx_p1_p | | | | |");

        if(!((cmp_x == BIGNUM_CMP_EQ) && (cmp_y == BIGNUM_CMP_EQ)))
        {
            /* P != Q */
            _DPRINTF_("P != Q\n");

            bignum_s* bitEx_x2_mul  = mkBigNum(ec_bits<<1U); // bit extended m

            bignum_s* bitEx_p1_dy  = mkBigNum(BIT_P1(ec_bits));// by bit expension, unsigned to signed on addtion
            bignum_s* bitEx_p1_dx  = mkBigNum(BIT_P1(ec_bits));// by bit expension, unsigned to signed on addtion
            bignum_s* bitEx_p1_dxi = mkBigNum(BIT_P1(ec_bits));// by bit expension, unsigned to signed on addtion

            if(!nQ) {
                __RETURN_TYPE_WRAPPING__(fr, sub_bignum_unsigned_unsafe(bitEx_p1_dy, yP, yQ));// bit expended, unsigned to sign
            } else {
                __RETURN_TYPE_WRAPPING__(fr, add_bignum_unsigned_unsafe(bitEx_p1_dy, yP, yQ));// bit expended, unsigned to sign
            }
                _PRINT_BIGNUM_(bitEx_p1_dy, "| | | | | bitEx_p1_dy = yP - yQ | | | | |");
            __RETURN_TYPE_WRAPPING__(fr, aim_bignum_signed_unsafe(bitEx_p1_dy, bitEx_p1_dy, bitEx_p1_p));
            _PRINT_BIGNUM_(bitEx_p1_dy, "| | | | | bitEx_p1_dy = (yP - yQ) mod bitEx_p1_p | | | | |");
            __RETURN_TYPE_WRAPPING__(fr, sub_bignum_unsigned_unsafe(bitEx_p1_dx, xP, xQ));// bit expended, unsigned to sign
            _PRINT_BIGNUM_(bitEx_p1_dx, "| | | | | bitEx_p1_dx = xP - xQ | | | | |");
            __RETURN_TYPE_WRAPPING__(fr, aim_bignum_signed_unsafe(bitEx_p1_dx, bitEx_p1_dx, bitEx_p1_p));
            _PRINT_BIGNUM_(bitEx_p1_dx, "| | | | | bitEx_p1_dx = (xP - xQ) mod bitEx_p1_p | | | | |");

            __RETURN_TYPE_WRAPPING__(fr, mim_bignum_unsafe(bitEx_p1_dxi, bitEx_p1_dx, bitEx_p1_p));
            _PRINT_BIGNUM_(bitEx_p1_dxi, "| | | | | bitEx_p1_dx^(-1) = (xP - xQ)^(-1) mod bitEx_p1_p | | | | |");
            if(fr == E_HAS_NO_VALUE) {
                _DPRINTF_("[WARNING] slope(m) is INFINITE, coordinates have to be set (0, 0)\r\n");
                slope_is_INFINITE = true;
            }

            if(!slope_is_INFINITE) {
                __RETURN_TYPE_WRAPPING__(fr, mul_bignum_unsigned_unsafe(bitEx_x2_mul, bitEx_p1_dy, bitEx_p1_dxi));
                _PRINT_BIGNUM_(bitEx_x2_mul, "| | | | | m = (yP - yQ)(xP - xQ)^(-1) | | | | |");
                __RETURN_TYPE_WRAPPING__(fr, mod_bignum_unsafe(bitEx_p1_m, bitEx_x2_mul, p));
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

            bignum_s* bitEx_x2_mul = mkBigNum(ec_bits<<1U);

            bignum_s* bitEx_p1_pow_x = mkBigNum(BIT_P1(ec_bits));// by bit expension, unsigned to signed on addtion
            bignum_s* bitEx_p1_numer = mkBigNum(BIT_P1(ec_bits));// by bit expension, unsigned to signed on addtion
            bignum_s* bitEx_p1_denom = mkBigNum(BIT_P1(ec_bits));// by bit expension, unsigned to signed on addtion

            // x^2
            __RETURN_TYPE_WRAPPING__(fr, mul_bignum_unsigned(bitEx_x2_mul, xP, xP));
            _PRINT_BIGNUM_(bitEx_x2_mul, "| | | | | xP^2 | | | | |");
            __RETURN_TYPE_WRAPPING__(fr, mod_bignum_unsafe(bitEx_p1_pow_x, bitEx_x2_mul, p));
            _PRINT_BIGNUM_(bitEx_p1_pow_x, "| | | | | (xP^2) mod p  | | | | |");

            // x^2 + a
            __RETURN_TYPE_WRAPPING__(fr, add_bignum_unsigned_unsafe(bitEx_p1_numer, bitEx_p1_pow_x, a));
            _PRINT_BIGNUM_(bitEx_p1_numer, "| | | | | xP^2 + a | | | | |");
            __RETURN_TYPE_WRAPPING__(fr, aim_bignum_signed_unsafe(bitEx_p1_numer, bitEx_p1_numer, bitEx_p1_p));
            _PRINT_BIGNUM_(bitEx_p1_numer, "| | | | | (xP^2 + a) mod bitEx_p1_p | | | | |");
            // 2 * x^2
            __RETURN_TYPE_WRAPPING__(fr, asl1b_bignum_self(bitEx_p1_pow_x, NULL, 0U));
            _PRINT_BIGNUM_(bitEx_p1_pow_x, "| | | | | 2 * xP^2 | | | | |");
            __RETURN_TYPE_WRAPPING__(fr, aim_bignum_signed_unsafe(bitEx_p1_pow_x, bitEx_p1_pow_x, bitEx_p1_p));
            _PRINT_BIGNUM_(bitEx_p1_pow_x, "| | | | | (2 * xP^2) mod bitEx_p1_p | | | | |");
            // (x^2 + a) += (2 * x^2)
            __RETURN_TYPE_WRAPPING__(fr, add_bignum_signed_unsafe(bitEx_p1_numer, bitEx_p1_numer, bitEx_p1_pow_x));
            _PRINT_BIGNUM_(bitEx_p1_numer, "| | | | | (3 * xP^2) + a | | | | |");
            __RETURN_TYPE_WRAPPING__(fr, aim_bignum_signed_unsafe(bitEx_p1_numer, bitEx_p1_numer, bitEx_p1_p));
            _PRINT_BIGNUM_(bitEx_p1_numer, "| | | | | ((3 * xP^2) + a) mod bitEx_p1_p | | | | |");

            // 2 * y
#if 0 /* P_IS_Q_AND_Q_IS_NEGATIVE_DOUBLING */
            __RETURN_TYPE_WRAPPING__(fr, add_bignum_unsigned_unsafe(bitEx_p1_denom, yP, yP));
#else
            if(!nQ) {
                cpy_bignum_unsigned_unsafe(bitEx_p1_denom, yP);
                _PRINT_BIGNUM_(bitEx_p1_denom, "| | | | | bitEx_p1_denom(yP, 1bit extention) | | | | |");
            } else {
                cpy_bignum_twos_signed_unsafe(bitEx_p1_denom, yP);
                _PRINT_BIGNUM_(bitEx_p1_denom, "| | | | | -bitEx_p1_denom(-yP, 1bit extention) | | | | |");
            }
            __RETURN_TYPE_WRAPPING__(fr, asl1b_bignum_self(bitEx_p1_denom, NULL, 0U));
#endif/* P_IS_Q_AND_Q_IS_NEGATIVE_DOUBLING */
            _PRINT_BIGNUM_(bitEx_p1_denom, "| | | | | 2 * yP | | | | |");
            __RETURN_TYPE_WRAPPING__(fr, aim_bignum_signed_unsafe(bitEx_p1_denom, bitEx_p1_denom, bitEx_p1_p));
            _PRINT_BIGNUM_(bitEx_p1_denom, "| | | | | (2 * yP) mod bitEx_p1_p | | | | |");

            __RETURN_TYPE_WRAPPING__(fr, mim_bignum_unsafe(bitEx_p1_denom, bitEx_p1_denom, bitEx_p1_p));
            _PRINT_BIGNUM_(bitEx_p1_denom, "| | | | | (2 * yP)^(-1) mod bitEx_p1_p | | | | |");
            if(fr == E_HAS_NO_VALUE) {
                _DPRINTF_("[WARNING] slope(m) is INFINITE, coordinates have to be set (0, 0)\r\n");
                slope_is_INFINITE = true;
            }

            if(!slope_is_INFINITE) {
                __RETURN_TYPE_WRAPPING__(fr, mul_bignum_unsigned(bitEx_x2_mul, bitEx_p1_numer, bitEx_p1_denom));
                _PRINT_BIGNUM_(bitEx_x2_mul, "| | | | | ((3 * xP^2) + a) * (2 * yP)^(-1) | | | | |");
                __RETURN_TYPE_WRAPPING__(fr, mod_bignum_unsafe(bitEx_p1_m, bitEx_x2_mul, p));
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
            bignum_s* bitEx_x2_mul = mkBigNum(ec_bits<<1U);

            bignum_s* bitEx_p1_pow_m = mkBigNum(BIT_P1(ec_bits));// by bit expension, unsigned to signed on addtion

            // m^2
            __RETURN_TYPE_WRAPPING__(fr, mul_bignum_unsigned(bitEx_x2_mul, bitEx_p1_m, bitEx_p1_m));
            _PRINT_BIGNUM_(bitEx_x2_mul, "| | | | | m^2 | | | | |");
            __RETURN_TYPE_WRAPPING__(fr, mod_bignum_unsafe(bitEx_p1_pow_m, bitEx_x2_mul, p));
            _PRINT_BIGNUM_(bitEx_p1_pow_m, "| | | | | m^2 mod p | | | | |");

            // m^2 - xP
            __RETURN_TYPE_WRAPPING__(fr, sub_bignum_unsigned_unsafe(bitEx_p1_x, bitEx_p1_pow_m, xP));
            _PRINT_BIGNUM_(xP, "| | | | | xP | | | | |");
            _PRINT_BIGNUM_(bitEx_p1_x, "| | | | | m^2 - xP | | | | |");
            __RETURN_TYPE_WRAPPING__(fr, aim_bignum_signed_unsafe(bitEx_p1_x, bitEx_p1_x, bitEx_p1_p));
            _PRINT_BIGNUM_(bitEx_p1_x, "| | | | | (m^2 - xP) mod bitEx_p1_p| | | | |");
            // m(^2 - xP) - xQ
            __RETURN_TYPE_WRAPPING__(fr, sub_bignum_unsigned_unsafe(bitEx_p1_x, bitEx_p1_x, xQ));
            _PRINT_BIGNUM_(xQ, "| | | | | xQ | | | | |");
            _PRINT_BIGNUM_(bitEx_p1_x, "| | | | | m^2 - xP - xQ | | | | |");
            // ( m(^2 - xP) - xQ ) mod bitEx_p1_p
            __RETURN_TYPE_WRAPPING__(fr, aim_bignum_signed_unsafe(bitEx_p1_x, bitEx_p1_x, bitEx_p1_p));
            _PRINT_BIGNUM_(bitEx_p1_x, "| | | | | (m^2 - xP - xQ) mod bitEx_p1_p | | | | |");

            rmBigNum(&bitEx_x2_mul);

            rmBigNum(&bitEx_p1_pow_m);
        }
        _PRINT_BIGNUM_(bitEx_p1_x, "| | | | | xR(bitEx_p1_x) | | | | |");

        /* Get yR */
        {
            bignum_s* bitEx_x2_mul = mkBigNum(ec_bits<<1U);

            __RETURN_TYPE_WRAPPING__(fr, sub_bignum_unsigned_unsafe(bitEx_p1_y, bitEx_p1_x, xP));
            _PRINT_BIGNUM_(xP, "| | | | | xP | | | | |");
            _PRINT_BIGNUM_(bitEx_p1_y, "| | | | | xR - xP | | | | |");
            __RETURN_TYPE_WRAPPING__(fr, aim_bignum_signed_unsafe(bitEx_p1_y, bitEx_p1_y, bitEx_p1_p));
            _PRINT_BIGNUM_(bitEx_p1_y, "| | | | | (xR - xP) mod bitEx_p1_p | | | | |");
            __RETURN_TYPE_WRAPPING__(fr, mul_bignum_unsigned(bitEx_x2_mul, bitEx_p1_m, bitEx_p1_y));
            _PRINT_BIGNUM_(bitEx_x2_mul, "| | | | | m(xR - xP) | | | | |");

            __RETURN_TYPE_WRAPPING__(fr, mod_bignum_unsafe(bitEx_p1_y, bitEx_x2_mul, p));
            _PRINT_BIGNUM_(bitEx_p1_y, "| | | | | m(xR - xP) mod p | | | | |");

            __RETURN_TYPE_WRAPPING__(fr, add_bignum_unsigned_unsafe(bitEx_p1_y, yP, bitEx_p1_y));
            _PRINT_BIGNUM_(yP, "| | | | | yP | | | | |");
            _PRINT_BIGNUM_(bitEx_p1_y, "| | | | | yP + m(xR - xP) | | | | |");
            __RETURN_TYPE_WRAPPING__(fr, aim_bignum_signed_unsafe(bitEx_p1_y, bitEx_p1_y, bitEx_p1_p));
            _PRINT_BIGNUM_(bitEx_p1_y, "| | | | | ( yP + m(xR - xP) ) mod bitEx_p1_p | | | | |");

            rmBigNum(&bitEx_x2_mul);
        }
        _PRINT_BIGNUM_(bitEx_p1_y, "| | | | | yR | | | | |");

        // -yR
        __RETURN_TYPE_WRAPPING__(fr, cpy_bignum_twos_signed_safe(bitEx_p1_y, bitEx_p1_y));
        _PRINT_BIGNUM_(bitEx_p1_y, "| | | | | (-yR) | | | | |");

        // (-yR) mod bitEx_p1_p
        __RETURN_TYPE_WRAPPING__(fr, aim_bignum_signed_unsafe(bitEx_p1_y, bitEx_p1_y, bitEx_p1_p));
        _PRINT_BIGNUM_(bitEx_p1_y, "| | | | | (-yR) mod bitEx_p1_p | | | | |");

        if(!slope_is_INFINITE) {
            __RETURN_TYPE_WRAPPING__(fr, cpy_bignum_unsigned_unsafe(xR, bitEx_p1_x));
            __RETURN_TYPE_WRAPPING__(fr, cpy_bignum_unsigned_unsafe(yR, bitEx_p1_y));
        } else {
            _DPRINTF_("[WARNING] slope(m) is INFINITE, coordinates have to be set (0, 0)\r\n");
            _PRINT_BIGNUM_(bitEx_p1_x, "| | | | | x (INFINITE, clear to 0) | | | | |");
            _PRINT_BIGNUM_(bitEx_p1_y, "| | | | | y (INFINITE, clear to 0) | | | | |");
            __RETURN_TYPE_WRAPPING__(fr, clr_bignum(xR));
            __RETURN_TYPE_WRAPPING__(fr, clr_bignum(yR));
        }

        rmBigNum(&bitEx_p1_m);
        rmBigNum(&bitEx_p1_x);
        rmBigNum(&bitEx_p1_y);

        rmBigNum(&bitEx_p1_p);
    } else {
        _DPRINTF_("[INFO] Point P or Q was Identity Elements, just adding two points\r\n");
        __RETURN_TYPE_WRAPPING__(fr, add_bignum_unsigned_unsafe(xR, xP, xQ));
        __RETURN_TYPE_WRAPPING__(fr, add_bignum_unsigned_unsafe(yR, yP, yQ));
    }
#undef BIT_P1
}
#ifdef _DPRINTF_
#undef _DPRINTF_
#endif /* _DPRINTF_ */
#ifdef _PRINT_BIGNUM_
#undef _PRINT_BIGNUM_
#endif /* _PRINT_BIGNUM_ */
