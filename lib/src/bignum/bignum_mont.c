#include <stdlib.h>
#include <stdint.h>

#include "bignum/bignum_mont.h"

#include "bignum/bignum.h"
#include "bignum/bignum_alu.h"
#include "common/util.h"

#ifdef ENABLE_BIGNUM_LOG
#include <stdio.h>
#include "test/test_tool.h"
#define _FUNC_WRAP_(RV, FN)         __RETURN_TYPE_WRAPPING__(RV, FN)

#define _DPRINTF_                   printf
#define _PRINT_BIGNUM_(p, title)    test_print_bignum(p, title)
#else
#define _FUNC_WRAP_(RV, FN)         ((RV) =  (FN))

#define _DPRINTF_
#define _PRINT_BIGNUM_(p, title)
#endif /* ENABLE_BIGNUM_LOG */
mont_conf_s* mkMontConf(const bignum_s* modulus)
{
    if(modulus == NULL)             return NULL;
    if(modulus->bits%MONT_BASE_BIT) return NULL;    // modulus length have to be multiple of bit length of base

    const size_t mont_n = MONT_BASE_b2L(modulus->bits);
    bignum_s* baseRadix = mkBigNum(modulus->bits + 1UL);
    bignum_s* nModInv_p1b = mkBigNum(modulus->bits + 1UL);
    (void)clr_bignum(baseRadix);
    (void)set1b_bignum(baseRadix, MONT_BASE_BIT);
     _PRINT_BIGNUM_(baseRadix, "baseRadix");

    mont_conf_s* conf = (mont_conf_s*)malloc(sizeof(mont_conf_s));
    conf->baseLen = MONT_BASE_b2L(modulus->bits);
    conf->radixBits = modulus->bits;

    conf->modulus = mkBigNum(modulus->bits);
    (void)cpy_bignum_unsigned_safe(conf->modulus, modulus);
     _PRINT_BIGNUM_(conf->modulus, "conf->modulus");

    conf->nModInv = mkBigNum(modulus->bits);
    (void)cpy_bignum_unsigned_unsafe(nModInv_p1b, modulus);
    (void)inv_bignum(nModInv_p1b);
    (void)add_bignum_carry_loc_unsigned(nModInv_p1b, 1U, 0U);
     _PRINT_BIGNUM_(nModInv_p1b, "nModInv_p1b");
    (void)mim_bignum(nModInv_p1b, nModInv_p1b, baseRadix);  // nModInv = m' = -m^-1 mod b
     _PRINT_BIGNUM_(nModInv_p1b, "nModInv_p1b");
    (void)cpy_bignum_unsigned_unsafe(conf->nModInv, nModInv_p1b);
     _PRINT_BIGNUM_(conf->nModInv, "conf->nModInv");

    rmBigNum(&baseRadix);
    rmBigNum(&nModInv_p1b);

    return conf;
}
int rmMontConf(mont_conf_s** conf)
{
    int fs = 0;
    if((void*)conf != NULL) {
        if((void*)(*conf) != NULL) {
            fs = rmBigNum((&(*conf)->modulus));
            fs = rmBigNum((&(*conf)->nModInv));
        }
        else {
            fs = -1;
        }
    }
    else {
        fs = -1;
    }
    return fs;
}

