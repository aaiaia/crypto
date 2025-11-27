
#ifndef BIGNUM_MONT_H
#define BIGNUM_MONT_H

#include <stdint.h>
#include <stddef.h> // size_t, NULL

#include "common/util.h"
#include "bignum/bignum.h"

#ifdef SET_BIGNUM_TYPE
#if(SET_BIGNUM_TYPE == 64)
typedef uint128_t   mont_t;// not implements yet
#define MONT_BASE_BIT           64UL    // is same size with bignum_t
#define MONT_BASE_VAL           (1UL<<MONT_BASE_BIT)
#define MONT_BASE_MOD           0xFFFFFFFFFFFFFFFFUL

#define MONT_LEN_BITS(idx)      U64L2BIT(idx)
#elif(SET_BIGNUM_TYPE == 32)
typedef uint64_t    mont_t;
#define MONT_BASE_BIT           32UL    // is same size with bignum_t
#define MONT_BASE_VAL           (1UL<<MONT_BASE_BIT)
#define MONT_BASE_MOD           0xFFFFFFFFU

#define MONT_LEN_BITS(idx)      U32L2BIT(idx)
#else
#error "NOT_IMPLEMENTS_YET"
#endif
// added monnon defines
#else
#error "SET PRE-DEFINE VALUE -> SET_BIGNUM_TYPE"
#endif /* SET_BIGNUM_TYPE */

/*
 * Mongomery Reduction and Multiplication
 * Ref: Handbook of Applied Cryptography, 1996, CRC press
 * 14.3.2 Montgomery reduction in Chapter14
 * Study at https://blog.naver.com/aaiaia/224087676346
 */
/*
 * base is fixed, b = 2^32
 * R is fixed, R = b^n = 2^32n, ex: secp256k1 need 256bit, n is 8
 * R^(-1) is fixed, R^(-1) = 1
 * m is fixed, m = b^n - 1 = 2^32n - 1,
 *      ex: secp256k1 needs 256 bit, n = 8
 *          x^256 -1 == 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
 * m' is fixed, m' = -m^(-1) mod R = 1
 */
typedef struct {
    size_t bitsOfn;
    size_t nlen;
    size_t bitsOfm;
    bignum_s* m;
    bignum_s* mu;   // to reduce u_i * m, mu = (m_n-2 m_n-3 ... m_1 m_0)_2^32
}mont_conf_s;

mont_conf_s* mkMontConf(const size_t bits);
int rmMontConf(mont_conf_s** conf);
#endif/* BIGNUM_MONT_H */
