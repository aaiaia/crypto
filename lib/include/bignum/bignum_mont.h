
#ifndef BIGNUM_MONT_H
#define BIGNUM_MONT_H

#include <stdint.h>
#include <stddef.h> // size_t, NULL

#include "common/returnType.h"
#include "common/util.h"
#include "bignum/bignum.h"

#ifdef SET_BIGNUM_TYPE
#if(SET_BIGNUM_TYPE == 64)
typedef uint128_t   mont_t;// not implements yet
#define MONT_BASE_BIT           64UL    // is same size with bignum_t
#define MONT_BASE_VAL           (1UL<<MONT_BASE_BIT)
#define MONT_BASE_b2L(bits)     QUOBITU64(bits)
#define MONT_BASE_bREM(bits)    REMBITU64(bits)
#elif(SET_BIGNUM_TYPE == 32)
typedef uint64_t    mont_t;
#define MONT_BASE_BIT           32UL    // is same size with bignum_t
#define MONT_BASE_VAL           (1UL<<MONT_BASE_BIT)
#define MONT_BASE_b2L(bits)     QUOBITU32(bits)
#define MONT_BASE_bREM(bits)    REMBITU32(bits)
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
 * b : base is fixed to 2^32
 * R : shift left value to converting to Montgomery Form.
 *     base is fixed, so represent R = b^n using n to (2^32)^n
 *     n has means that number of digit in looooong number.
 *     ex: secp256k1 need 256bit, n is 8
 * m : modulus, (like, prime of secp256k1)
 * m': -m^(-1) mod R
 */
typedef struct {
    //size_t baseBits;  // b : unit of processs(radix of basis), like symbol in montgomery form(space).
    size_t baseLen;     // n : b^n, number of base, converting normal to montgomery form, it will be number of iteration.
    size_t radixBits;   // R : R = 2^radixBit
    bignum_s* modulus;  // m : montgomery space is one of finite field. To make a number in finite fied, needs prime.
    bignum_s* nModInv;  // m': m' = -m^(-1) mod R
}mont_conf_s;

mont_conf_s* mkMontConf(const bignum_s* modulus);
int rmMontConf(mont_conf_s** conf);

/*
 * Mongomery Reduction and Multiplication
 * Ref: Handbook of Applied Cryptography, 1996, CRC press
 * 14.3.2 Montgomery reduction in Chapter14
 * Study at https://blog.naver.com/aaiaia/224087676346
 */
typedef ReturnType (*mont_mul_bignum_t)(bignum_s*, const bignum_t, const bignum_s*);
extern const mont_mul_bignum_t mont_mul1w_bignum_unsigned_unsafe;

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
#endif/* BIGNUM_MONT_H */
