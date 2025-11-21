#ifndef EC_KEY_H
#define EC_KEY_H
#include <stddef.h>

#include "bignum/bignum.h"

void eckey_getPublicKey(bignum_s* xPublic, bignum_s* yPublic, \
        const bignum_s* privateKey, \
        const bignum_s* xG, const bignum_s* yG, \
        const size_t ec_bits, const bignum_s* a, const bignum_s* p);

#endif /* EC_KEY_H */
