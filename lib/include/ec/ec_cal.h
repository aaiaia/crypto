#ifndef EC_CAL_H
#define EC_CAL_H
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "common/returnType.h"
#include "bignum/bignum.h"

#include "bignum/bignum_wnaf.h"
void ec_calPoints_ext(bignum_s* xR, bignum_s* yR, \
        const bignum_s* xP, const bignum_s* yP, \
        const bool nQ, \
        const bignum_s* xQ, const bignum_s* yQ, \
        const size_t ec_bits, const bignum_s* a, const bignum_s* p, \
        const bool ign_sign);
static inline void ec_doublePoints_self(bignum_s* xP, bignum_s* yP, \
        const size_t ec_bits, const bignum_s* a, const bignum_s* p, \
        const bool ign_sign)
{
    const bool nQ = false;
    ec_calPoints_ext(xP, yP, xP, yP, nQ, xP, yP, ec_bits, a, p, ign_sign);
}
static inline void ec_doublePoints(bignum_s* xR, bignum_s* yR, \
        const bignum_s* xP, const bignum_s* yP, \
        const size_t ec_bits, const bignum_s* a, const bignum_s* p, \
        const bool ign_sign)
{
    const bool nQ = false;
    ec_calPoints_ext(xR, yR, xP, yP, nQ, xP, yP, ec_bits, a, p, ign_sign);
}
static inline void ec_addPoints(bignum_s* xR, bignum_s* yR, \
        const bignum_s* xP, const bignum_s* yP, \
        const bignum_s* xQ, const bignum_s* yQ, \
        const size_t ec_bits, const bignum_s* a, const bignum_s* p, \
        const bool ign_sign)
{
    const bool nQ = false;
    ec_calPoints_ext(xR, yR, xP, yP, nQ, xQ, yQ, ec_bits, a, p, ign_sign);
}
static inline void ec_subPoints(bignum_s* xR, bignum_s* yR, \
        const bignum_s* xP, const bignum_s* yP, \
        const bignum_s* xQ, const bignum_s* yQ, \
        const size_t ec_bits, const bignum_s* a, const bignum_s* p, \
        const bool ign_sign)
{
    const bool nQ = true;
    ec_calPoints_ext(xR, yR, xP, yP, nQ, xQ, yQ, ec_bits, a, p, ign_sign);
}

typedef struct {
    uwnaf       w;  // window
    uwnaf       l;  // length
    bignum_s**  x;
    bignum_s**  y;
}wnaf_pre_compute_ec_s;

/*
 * mkWNAF_preCompute_ec
 * w: wNAF window size
 * ec_bits: ec_point bit length
 */
wnaf_pre_compute_ec_s* mkWNAF_preCompute_ec(const uwnaf w, const size_t ec_bits);
int rmWNAF_preCompute_ec(wnaf_pre_compute_ec_s** p);

/*
 * ec_preCompute_WNAF
 * pc: pre-computation
 * xP, yP: Result of ec point doubling
 * ec_bits: bit length of ec point
 * a: coeffient of ec curve, y^2 = x^3 + a*x + b
 * p: prime number for modulo p(mod p)
 * w: window length of wNAF
 */
void ec_preCompute_WNAF(wnaf_pre_compute_ec_s* pc, \
        const bignum_s* xP, const bignum_s* yP, \
        const size_t ec_bits, const bignum_s* a, const bignum_s* p, \
        const uwnaf w, const bool ign_sign);

/*
 * ec_scalarMul_WNAF
 * xdP, ydP: Result of ec point doubling
 * d: scalar multiplier
 * xP, yP: ec point to be multiplicand
 * ec_bits: bit length of ec point
 * a: coeffient of ec curve, y^2 = x^3 + a*x + b
 * p: prime number for modulo p(mod p)
 * w: window length of wNAF
 */
void ec_scalarMul_WNAF(
        bignum_s* xdP, bignum_s* ydP, \
        const bignum_s* d, \
        const bignum_s* xP, const bignum_s* yP, \
        const size_t ec_bits, const bignum_s* a, const bignum_s* p, \
        const uwnaf w, const bool ign_sign);
#endif /* EC_CAL_H */
