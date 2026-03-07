#ifndef EC_ECDSA_H
#define EC_ECDSA_H
#include <stddef.h>
#include <stdbool.h>

#include "bignum/bignum.h"

void ecdsa_sign_ext(bignum_s* sign_r, bignum_s* sign_s, \
        const bignum_s* nonce, const bignum_s* hash, const bignum_s* privateKey, \
        const bignum_s* xG, const bignum_s* yG, \
        const size_t ec_bits, const bignum_s* a, const bignum_s* p, const bignum_s* n);

static inline void ecdsa_sign(bignum_s* sign_r, bignum_s* sign_s, \
        const bignum_s* hash, const bignum_s* privateKey, \
        const bignum_s* xG, const bignum_s* yG, \
        const size_t ec_bits, const bignum_s* a, const bignum_s* p, const bignum_s* n)
{
    const bignum_s* nonce = NULL;
    ecdsa_sign_ext(sign_r, sign_s, nonce, hash, privateKey, xG, yG, ec_bits, a, p, n);
}
static inline void ecdsa_sign_nonce(bignum_s* sign_r, bignum_s* sign_s, \
        const bignum_s* nonce, const bignum_s* hash, const bignum_s* privateKey, \
        const bignum_s* xG, const bignum_s* yG, \
        const size_t ec_bits, const bignum_s* a, const bignum_s* p, const bignum_s* n)
{
    ecdsa_sign_ext(sign_r, sign_s, nonce, hash, privateKey, xG, yG, ec_bits, a, p, n);
}

bool ecdsa_veri_ext(bignum_s* calc_r, const bignum_s* sign_r, const bignum_s* sign_s, \
        const bignum_s* hash, \
        const bignum_s* xPublic, const bignum_s* yPublic, \
        const bignum_s* xG, const bignum_s* yG, \
        const size_t ec_bits, const bignum_s* a, const bignum_s* p, const bignum_s* n);
static inline bool ecdsa_veri(const bignum_s* sign_r, const bignum_s* sign_s, \
        const bignum_s* hash, \
        const bignum_s* xPublic, const bignum_s* yPublic, \
        const bignum_s* xG, const bignum_s* yG, \
        const size_t ec_bits, const bignum_s* a, const bignum_s* p, const bignum_s* n)
{
    bignum_s* calc_r = NULL;
    return ecdsa_veri_ext(calc_r, sign_r, sign_s, hash, xPublic, yPublic, xG, yG, ec_bits, a, p, n);
}
static inline bool ecdsa_veri_calc_r(bignum_s* calc_r, const bignum_s* sign_r, const bignum_s* sign_s, \
        const bignum_s* hash, \
        const bignum_s* xPublic, const bignum_s* yPublic, \
        const bignum_s* xG, const bignum_s* yG, \
        const size_t ec_bits, const bignum_s* a, const bignum_s* p, const bignum_s* n)
{
    return ecdsa_veri_ext(calc_r, sign_r, sign_s, hash, xPublic, yPublic, xG, yG, ec_bits, a, p, n);
}

#endif /* EC_ECDSA_H */
