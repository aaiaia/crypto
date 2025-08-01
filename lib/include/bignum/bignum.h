#ifndef BIGNUM_H
#define BIGNUM_H

#include <stdint.h>
#include <stddef.h> // size_t, NULL

typedef uint32_t    bignum_t;
#define bignum_bits 32U

typedef struct {
    size_t  bits;    // bit width length
    size_t  size;    // size
    size_t  nlen;    // type length
    bignum_t    lmsk;
    bignum_t*   nums;
}bignum_s;

bignum_s* mkBigNum(size_t bits);
int rmBitNum(bignum_s** p);

#endif/* BIGNUM_H */
