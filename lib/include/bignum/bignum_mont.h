
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
#define MONT_BASE_b2L(bits)     QUOBITU64(bits)
#elif(SET_BIGNUM_TYPE == 32)
typedef uint64_t    mont_t;
#define MONT_BASE_BIT           32UL    // is same size with bignum_t
#define MONT_BASE_VAL           (1UL<<MONT_BASE_BIT)
#define MONT_BASE_b2L(bits)     QUOBITU32(bits)
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
#endif/* BIGNUM_MONT_H */
