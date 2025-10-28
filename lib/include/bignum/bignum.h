#ifndef BIGNUM_H
#define BIGNUM_H

#include <stdint.h>
#include <stddef.h> // size_t, NULL

#include "common/util.h"

#ifdef SET_BIGNUM_TYPE
#if(SET_BIGNUM_TYPE == 64)
typedef uint64_t    bignum_t;
#define BIGNUM_MAX              UINT64_MAX
#define BIGNUM_BITS 64U
#define BIGNUM_SIZE 8U
#define BIGNUM_LEN_BITS(idx)    U64L2BIT(idx)
#define BIGNUM_BITS_LEN(bits)   BIT2U64L(bits)
#define BIGNUM_BITS_IDX(bits)   QUOBITU64(bits)
#define BIGNUM_BITS_REM(bits)   REMBITU64(bits)
#elif(SET_BIGNUM_TYPE == 32)
typedef uint32_t    bignum_t;
#define BIGNUM_MAX              UINT32_MAX
#define BIGNUM_BITS 32U
#define BIGNUM_SIZE 4U
#define BIGNUM_LEN_BITS(idx)    U32L2BIT(idx)
#define BIGNUM_BITS_LEN(bits)   BIT2U32L(bits)
#define BIGNUM_BITS_IDX(bits)   QUOBITU32(bits)
#define BIGNUM_BITS_REM(bits)   REMBITU32(bits)
#else
#error "NOT_IMPLEMENTS_YET"
#endif
#define BIGNUM_SIGN_BIT(v)      ((v)>>(BIGNUM_BITS-1UL))
#define BIGNUM_MSB_MASK         (1UL<<(BIGNUM_BITS-1UL))
#define BIGNUM_LSB_MASK         (1UL)
#else
#error "SET PRE-DEFINE VALUE -> SET_BIGNUM_TYPE"
#endif /* SET_BIGNUM_TYPE */

typedef struct {
    size_t          bits;    // bit width length
    size_t          size;    // size
    size_t          nlen;    // type length
    bignum_t        lmsk;
    bignum_t*       nums;
}bignum_s;

bignum_s* mkBigNum(const size_t bits);
int rmBigNum(bignum_s** p);

#endif/* BIGNUM_H */
