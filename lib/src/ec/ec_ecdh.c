#include "ec/ec_ecdh.h"

#include "bignum/bignum_wnaf.h"
#include "ec/ec_cal.h"

void ecdh_getSharedKey(bignum_s* xShared, bignum_s* yShared, \
        const bignum_s* privateKey, \
        const bignum_s* xPublic, const bignum_s* yPublic,
        const size_t ec_bits, const bignum_s* a, const bignum_s* p)
{
    const bool ign_sign = true;
    const uwnaf w = 5U;
    ec_scalarMul_WNAF(xShared, yShared, privateKey, xPublic, yPublic, ec_bits, a, p, w, ign_sign);
}
