#ifndef EC_CAL_H
#define EC_CAL_H
#include <stdint.h>
#include <stdbool.h>

#include "common/returnType.h"
#include "bignum/bignum.h"

void ec_addPoints_ext(bignum_s* xR, bignum_s* yR, \
        const bignum_s* xP, const bignum_s* yP, \
        const bool nQ, \
        const bignum_s* xQ, const bignum_s* yQ, \
        const size_t ec_bits, const bignum_s* a, const bignum_s* p, \
        const bool ign_sign);
static inline void ec_doublePoints(bignum_s* xP, bignum_s* yP, \
        const size_t ec_bits, const bignum_s* a, const bignum_s* p, \
        const bool ign_sign)
{
    const bool nQ = false;
    ec_addPoints_ext(xP, yP, xP, yP, nQ, xP, yP, ec_bits, a, p, ign_sign);
}
static inline void ec_addPoints(bignum_s* xR, bignum_s* yR, \
        const bignum_s* xP, const bignum_s* yP, \
        const bignum_s* xQ, const bignum_s* yQ, \
        const size_t ec_bits, const bignum_s* a, const bignum_s* p, \
        const bool ign_sign)
{
    const bool nQ = false;
    ec_addPoints_ext(xR, yR, xP, yP, nQ, xQ, yQ, ec_bits, a, p, ign_sign);
}
static inline void ec_subPoints(bignum_s* xR, bignum_s* yR, \
        const bignum_s* xP, const bignum_s* yP, \
        const bignum_s* xQ, const bignum_s* yQ, \
        const size_t ec_bits, const bignum_s* a, const bignum_s* p, \
        const bool ign_sign)
{
    const bool nQ = true;
    ec_addPoints_ext(xR, yR, xP, yP, nQ, xQ, yQ, ec_bits, a, p, ign_sign);
}
#endif /* EC_CAL_H */
