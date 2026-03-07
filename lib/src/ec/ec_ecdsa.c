#if 1 /* USE_SYSTEM_RANDOM */
#include <time.h>
#endif/* USE_SYSTEM_RANDOM */
#include <string.h>

#include "ec/ec_ecdsa.h"

#include "bignum/bignum_alu.h"
#include "bignum/bignum_wnaf.h"

#include "ec/ec_cal.h"

#if 0 /* ENABLE_BIGNUM_LOG */
#ifndef ENABLE_BIGNUM_LOG
#define ENABLE_BIGNUM_LOG
#endif/* ENABLE_BIGNUM_LOG */
#endif/* ENABLE_BIGNUM_LOG */

#ifdef ENABLE_BIGNUM_LOG
#include <stdio.h>
#include "test/test_tool.h"
#define _ECDSA_FN_CALL_(RV, FN)         __RETURN_TYPE_WRAPPING__(RV, FN)

#define _ECDSA_DPRINTF_(...)            printf(...)
#define _ECDSA_PRINT_BIGNUM_(p, title)  test_print_bignum(p, title)
#define _ECDSA_PRINT_CMP_(cmp)          test_print_bignum_cmp(cmp)
#else
#define _ECDSA_FN_CALL_(RV, FN)         ((RV) = (FN))

#define _ECDSA_DPRINTF_(...)
#define _ECDSA_PRINT_BIGNUM_(p, title)
#define _ECDSA_PRINT_CMP_(cmp)
#endif/* ENABLE_BIGNUM_LOG */

void ecdsa_sign_ext(bignum_s* sign_r, bignum_s* sign_s, \
        const bignum_s* nonce, const bignum_s* hash, const bignum_s* privateKey, \
        const bignum_s* xG, const bignum_s* yG, \
        const size_t ec_bits, const bignum_s* a, const bignum_s* p, const bignum_s* n)
{
    ReturnType fr;

    const bool ign_sign = true;
    const uwnaf w = 5U;

    const bignum_s* scalar_z = hash;
    const bignum_s* scalar_d = privateKey;

    bignum_s* scalar_add =  mkBigNum(ec_bits+1U);
    bignum_s* scalar_mul =  mkBigNum(ec_bits<<1U);

    bignum_s* scalar_k = mkBigNum(ec_bits);

    bignum_s* scalar_r = mkBigNum(ec_bits);
    bignum_s* scalar_s = mkBigNum(ec_bits);

    bignum_s* xkG = mkBigNum(ec_bits);
    bignum_s* ykG = mkBigNum(ec_bits);

    bignum_cmp_e cmp_non_zero = BIGNUM_CMP_NU;

    _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(xG, "xG");
    _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(yG, "yG");

    _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(scalar_d, "scalar_d");
    _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(scalar_z, "scalar_z");

#if 1 /* USE_SYSTEM_RANDOM */
    srand(time(NULL));
#endif/* USE_SYSTEM_RANDOM */
    while(1)
    {
        if(nonce == NULL)
        {
            // random k
#if 1 /* USE_SYSTEM_RANDOM */
            for(size_t i = 0UL; i < scalar_k->nlen; i++)
            {
                bignum_t rand_num = 0UL;
                for(size_t j = 0UL; j < sizeof(bignum_t); j++)  rand_num |= (bignum_t)((rand()&0xFF)<<(j*8));
                scalar_k->nums[i] = rand_num;
            }
#endif/* USE_SYSTEM_RANDOM */
        }
        else
        {
            _ECDSA_FN_CALL_(fr, cpy_bignum_unsigned_safe(scalar_k, nonce));
        }
        _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(scalar_k, "scalar_k");

        ec_scalarMul_WNAF(xkG, ykG, scalar_k, xG, yG, ec_bits, a, p, w, ign_sign);
        _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(xkG, "xkG");
        _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(ykG, "ykG");

        /* xP of k*G is scalar r */
        /* r mod n(curve order) */
        _ECDSA_FN_CALL_(fr, aim_bignum_unsigned_unsafe(scalar_r, xkG, n));

        /* r = 0: retry */
        cmp_non_zero = cmp0_bignum(scalar_r);
        _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_CMP_(cmp_non_zero);
        if(cmp_non_zero == BIGNUM_CMP_ZO)       if(nonce == NULL)   continue;
        else if(cmp_non_zero == BIGNUM_CMP_NZ)  /* Acceptable Cases */;
        else                                    /* HAS_ERROR */;
        _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(scalar_r, "scalar_r");

        _ECDSA_FN_CALL_(fr, mim_bignum(scalar_k, scalar_k, n));
        if(fr == E_OK)                          /* Acceptable Cases */;
        else if(fr == E_HAS_NO_VALUE)           if(nonce == NULL)   continue;
        else                                    /* HAS_ERROR */;
        _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(scalar_k, "scalar_k, k^(-1)");

        _ECDSA_FN_CALL_(fr, ec_mul_bignum_unsigned_unsafe(scalar_mul, scalar_r, scalar_d));
        _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(scalar_mul, "scalar_mul, r * d");
        _ECDSA_FN_CALL_(fr, mod_bignum_unsafe(scalar_s, scalar_mul, n));
        _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(scalar_s, "scalar_s, (r * d) mod n");
        _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(scalar_z, "scalar_z");
        _ECDSA_FN_CALL_(fr, add_bignum_unsigned_unsafe(scalar_add, scalar_z, scalar_s));
        _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(scalar_add, "scalar_add, z + (r * d)");
        _ECDSA_FN_CALL_(fr, aim_bignum_unsigned_unsafe(scalar_s, scalar_add, n));
        _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(scalar_s, "scalar_s, (z + (r * d)) mod n");

        _ECDSA_FN_CALL_(fr, ec_mul_bignum_unsigned_unsafe(scalar_mul, scalar_k, scalar_s));
        _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(scalar_mul, "scalar_mul, (k^(-1)) * (z + (r * d))");
        _ECDSA_FN_CALL_(fr, mod_bignum_unsafe(scalar_s, scalar_mul, n));
        _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(scalar_s, "scalar_s, s = ((k^(-1)) * (z + (r * d))) mod n");

        /* s = 0: retry */
        cmp_non_zero = cmp0_bignum(scalar_s);
        _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_CMP_(cmp_non_zero);
        if(cmp_non_zero == BIGNUM_CMP_ZO)       if(nonce == NULL)   continue;
        else if(cmp_non_zero == BIGNUM_CMP_NZ)  /* Acceptable Cases */;
        else                                    /* HAS_ERROR */;

        break;
    }

    _ECDSA_FN_CALL_(fr, cpy_bignum_unsigned_safe(sign_r, scalar_r));
    _ECDSA_FN_CALL_(fr, cpy_bignum_unsigned_safe(sign_s, scalar_s));
    _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(sign_r, "signature r");
    _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(sign_s, "signature s");

    rmBigNum(&scalar_add);
    rmBigNum(&scalar_mul);

    rmBigNum(&scalar_k);

    rmBigNum(&scalar_r);
    rmBigNum(&scalar_s);

    rmBigNum(&xkG);
    rmBigNum(&ykG);

    return;
}

bool ecdsa_veri_ext(bignum_s* calc_r, const bignum_s* sign_r, const bignum_s* sign_s, \
        const bignum_s* hash,
        const bignum_s* xPublic, const bignum_s* yPublic, \
        const bignum_s* xG, const bignum_s* yG, \
        const size_t ec_bits, const bignum_s* a, const bignum_s* p, const bignum_s* n)
{
    ReturnType fr;

    const bool ign_sign = true;
    const uwnaf w = 5U;

    const bignum_s* scalar_z = hash;

    bignum_s* scalar_s = mkBigNum(ec_bits);
    bignum_s* scalar_u = mkBigNum(ec_bits);

    bignum_s* scalar_mul =  mkBigNum(ec_bits<<1U);

    bignum_s* xT = mkBigNum(ec_bits);
    bignum_s* yT = mkBigNum(ec_bits);

    bignum_s* xP = mkBigNum(ec_bits);
    bignum_s* yP = mkBigNum(ec_bits);

    const bignum_s* veri_r = xP;

    bool verified = true;

    _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(xG, "xG");
    _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(yG, "yG");
    _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(xPublic, "xPublic");
    _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(yPublic, "yPublic");

    _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(sign_r, "sign_r");
    _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(sign_s, "sign_s");
    _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(scalar_z, "scalar_z");

    // s^(-1)
    _ECDSA_FN_CALL_(fr, mim_bignum(scalar_s, sign_s, n));

    // (s^(-1) * z) mod n
    _ECDSA_FN_CALL_(fr, ec_mul_bignum_unsigned_unsafe(scalar_mul, scalar_s, scalar_z));
    _ECDSA_FN_CALL_(fr, mod_bignum_unsafe(scalar_u, scalar_mul, n));
    // u1 * G
    ec_scalarMul_WNAF(xT, yT, scalar_u, xG, yG, ec_bits, a, p, w, ign_sign);
    _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(xNG, "xNG");
    _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(yNG, "yNG");

    // P = u1 * G
    _ECDSA_FN_CALL_(fr, cpy_bignum_unsigned_safe(xP, xT));
    _ECDSA_FN_CALL_(fr, cpy_bignum_unsigned_safe(yP, yT));

    // (s^(-1) * r) mod n
    _ECDSA_FN_CALL_(fr, ec_mul_bignum_unsigned_unsafe(scalar_mul, scalar_s, sign_r));
    _ECDSA_FN_CALL_(fr, mod_bignum_unsafe(scalar_u, scalar_mul, n));
    // u_2 * H_a
    ec_scalarMul_WNAF(xT, yT, scalar_u, xPublic, yPublic, ec_bits, a, p, w, ign_sign);
    _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(xNPublic, "xNPublic");
    _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(yNPublic, "yNPublic");

    // P = u1 * G + u_2 * H_a
    // P(= u1 * G) += u_2 * H_a
    ec_addPoints(xP, yP, xP, yP, xT, yT, ec_bits, a, p, ign_sign);
    _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(xP, "xP");
    _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(yP, "yP");

    _ECDSA_DPRINTF_("@%s:%u, ", __func__, __LINE__); _ECDSA_PRINT_BIGNUM_(veri_r, "veri r");

    verified &= (memcmp(veri_r->nums, sign_r->nums, sign_r->size) == 0);

    if(calc_r != NULL)  _ECDSA_FN_CALL_(fr, cpy_bignum_unsigned_safe(calc_r, veri_r));

    rmBigNum(&scalar_s);
    rmBigNum(&scalar_u);

    rmBigNum(&scalar_mul);

    rmBigNum(&xT);
    rmBigNum(&yT);

    rmBigNum(&xP);
    rmBigNum(&yP);

    return verified;
}
