#ifndef EC_ECDH_H
#define EC_ECDH_H
#include <stddef.h>

#include "bignum/bignum.h"

void ecdh_getSharedKey(bignum_s* xShared, bignum_s* yShared, \
        const bignum_s* privateKey, \
        const bignum_s* xPublic, const bignum_s* yPublic,
        const size_t ec_bits, const bignum_s* a, const bignum_s* p);

#endif /* EC_ECDH_H */
