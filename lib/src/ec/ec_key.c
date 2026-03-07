#include "ec/ec_key.h"

#include "bignum/bignum_wnaf.h"
#include "ec/ec_cal.h"

void eckey_getPublicKey(bignum_s* xPublic, bignum_s* yPublic, \
        const bignum_s* privateKey, \
        const bignum_s* xG, const bignum_s* yG, \
        const size_t ec_bits, const bignum_s* a, const bignum_s* p)
{
    const bool ign_sign = true;
    const uwnaf w = 5U;
    ec_scalarMul_WNAF(xPublic, yPublic, privateKey, xG, yG, ec_bits, a, p, w, ign_sign);
}
