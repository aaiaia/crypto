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
    if(modulus == NULL)                 return NULL;
    if(MONT_BASE_bREM(modulus->bits))   return NULL;    // modulus length have to be multiple of bit length of base
    if(modulus->bits<MONT_BASE_BIT)     return NULL;

    const size_t mont_n = MONT_BASE_b2L(modulus->bits);
    bignum_s* baseRadix = mkBigNum(modulus->bits);
    bignum_s* nModInv = mkBigNum(modulus->bits);
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
    (void)cpy_bignum_twos_signed_safe(nModInv, modulus);
     _PRINT_BIGNUM_(nModInv, "nModInv(=2's of modulus)");
    (void)mim_bignum_unsigned_safe(nModInv, nModInv, baseRadix);  // nModInv = m' = -m^-1 mod b
     _PRINT_BIGNUM_(nModInv, "nModInv(Multiplicative inverse modulo");
    (void)cpy_bignum_unsigned_safe(conf->nModInv, nModInv);
     _PRINT_BIGNUM_(conf->nModInv, "conf->nModInv");

    rmBigNum(&baseRadix);
    rmBigNum(&nModInv);

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

const mont_mul_bignum_t mont_mul1w_bignum_unsigned_unsafe = mul1w_bignum_unsigned_x2wMul_unsafe;

ReturnType swapMontToBignum_unsigned_safe(bignum_s* dst, const bignum_s* src, const mont_conf_s* conf)
{
#define BIT_X2(BITS)    ((BITS)<<1UL)
    _DPRINTF_(">>%s:%d\r\n", __func__, __LINE__);
    if(conf == NULL || src == NULL)     return E_ERROR_NULL;
    ReturnType fr = E_NOT_OK;
    // x' = xR mod m
    _DPRINTF_("conf->radixBits: %ld(0x%lx)\r\n", conf->radixBits, conf->radixBits);
    bignum_s* t_x2 = mkBigNum(BIT_X2(conf->radixBits));

    _PRINT_BIGNUM_(src, "src");
    _FUNC_WRAP_(fr, cpy_bignum_unsigned_unsafe(t_x2, src));
    _PRINT_BIGNUM_(t_x2, "t_x2");
    _DPRINTF_("logical shift left: %ld\r\n",  conf->radixBits);
    // x' = xR mod m, R = 2^256
    _FUNC_WRAP_(fr, lslb_bignum_self(t_x2, conf->radixBits));
    _PRINT_BIGNUM_(t_x2, "t_x2 << radixBits");
    // x' = xR mod m, R = 2^256
    _PRINT_BIGNUM_(t_x2, "t_x2");
    _PRINT_BIGNUM_(conf->modulus, "conf->modulus");
    _FUNC_WRAP_(fr, mod_bignum_nbsDiv_unsafe(dst, t_x2, conf->modulus));
    _PRINT_BIGNUM_(dst, "dst");

    rmBigNum(&t_x2);

    _DPRINTF_("<<%s:%d\r\n", __func__, __LINE__);
    return fr;
#undef BIT_X2
}
ReturnType mod_mont_unsigned_safe(bignum_s* mont, const bignum_s* n_x2bit, const mont_conf_s* conf)
{
    _DPRINTF_(">>%s:%d\r\n", __func__, __LINE__);
    if(conf == NULL || n_x2bit == NULL) return E_ERROR_NULL;

    ReturnType fr = E_NOT_OK;

    bignum_s* a_x2bit = mkBigNum(n_x2bit->bits);
    bignum_s* mul_x2b = mkBigNum(n_x2bit->bits);
    bignum_cmp_e cmp = BIGNUM_CMP_NU;

    _FUNC_WRAP_(fr, cpy_bignum_unsigned_unsafe(a_x2bit, n_x2bit));
    for(size_t i = 0UL; i < conf->baseLen; i++)
    {
        const bignum_t a0 = a_x2bit->nums[0];
        const bignum_t nmi0 = conf->nModInv->nums[0];
        bignum_t ui;
        // ui = a_0 * m' mod b, MONT_BASE_BIT
        // when b = 2^32, ui = a_0 * m' mod b is represent to a_0 * m_0
        ui = (a0 * nmi0);
        // ui * m
        if(ui != 0)
        {
            _FUNC_WRAP_(fr, mont_mul1w_bignum_unsigned_unsafe(mul_x2b, ui, conf->modulus));
            _FUNC_WRAP_(fr, add_bignum_unsigned_unsafe(a_x2bit, a_x2bit, mul_x2b));
        }
        else
        {
            /* DO_NOTHING */
        }
        // A / b
        _FUNC_WRAP_(fr, lsrb_bignum_self(a_x2bit, MONT_BASE_BIT));                  _DPRINTF_("||%s:%d\n", __func__, __LINE__);
    }
    // signed modulo
    cmp = cmp_bignum_logical_unsigned_unsafe(a_x2bit, conf->modulus);
    if(cmp == BIGNUM_CMP_GT || cmp == BIGNUM_CMP_EQ)
    {
        _FUNC_WRAP_(fr, sub_bignum_unsigned_unsafe(a_x2bit, a_x2bit, conf->modulus));
    }
    _FUNC_WRAP_(fr, cpy_bignum_unsigned_unsafe(mont, a_x2bit));                     _DPRINTF_("||%s:%d\n", __func__, __LINE__);
    _FUNC_WRAP_(fr, cpy_bignum_unsigned_unsafe(mont, a_x2bit));

    rmBigNum(&a_x2bit);
    rmBigNum(&mul_x2b);

    _DPRINTF_("<<%s:%d\r\n", __func__, __LINE__);
    return fr;
}
ReturnType mul_mont_unsigned_safe(bignum_s* mont, const bignum_s* x, const bignum_s* y, const mont_conf_s* conf)
{
#define BIT_X2(BITS)    ((BITS)<<1UL)
    _DPRINTF_(">>%s:%d\n", __func__, __LINE__);
    if(conf == NULL)    { _DPRINTF_("<<%s:%d\n", __func__, __LINE__); return E_ERROR_NULL; }

    ReturnType fr = E_NOT_OK;

    bignum_s* a_x2bit = mkBigNum(BIT_X2(mont->bits));
    bignum_s* mul_x2b = mkBigNum(BIT_X2(mont->bits));
    bignum_cmp_e cmp = BIGNUM_CMP_NU;

    _FUNC_WRAP_(fr, clr_bignum(a_x2bit));

    for(size_t i = 0UL; i < conf->baseLen; i++)
    {
        _DPRINTF_("step = %lu/%lu\r\n", i, conf->baseLen);
        const bignum_t a0 = a_x2bit->nums[0];
        const bignum_t xi = x->nums[i];
        const bignum_t y0 = y->nums[0];
        const bignum_t nmi0 = conf->nModInv->nums[0];
        bignum_t ui;

        // ui = ((a_0 + x_i * y_0) * m') mod b
        // when b = 2^32, ui = ((a_0 + x_i * y_0) * m') mod b represent to ui = ((a_0 + x_i * y_0) * m_0)
        ui = (a0+(xi*y0))*nmi0;
        _DPRINTF_("ui=(a0+(xi*y0))*nmi0 mod b(=0x100000000)\r\n");
        _DPRINTF_("0x%08x=(0x%08x+(0x%08x*0x%08x))*0x%08x mod 0x100000000\r\n", ui, a0, xi, y0, nmi0);
        // A = (A + x_i * y + u_i * m)
        // A = (A + x_i * y)
        _DPRINTF_("xi= 0x%08x\r\n", xi);
        _PRINT_BIGNUM_(y, "y");
        _FUNC_WRAP_(fr, mont_mul1w_bignum_unsigned_unsafe(mul_x2b, xi, y));         _DPRINTF_("||%s:%d\n", __func__, __LINE__);
        _PRINT_BIGNUM_(mul_x2b, "mul_x2b = xi * y");
        _PRINT_BIGNUM_(a_x2bit, "a_x2bit");
        _PRINT_BIGNUM_(mul_x2b, "mul_x2b");
        _FUNC_WRAP_(fr, add_bignum_unsigned_unsafe(a_x2bit, a_x2bit, mul_x2b));     _DPRINTF_("||%s:%d\n", __func__, __LINE__);
        _PRINT_BIGNUM_(a_x2bit, "a_x2bit = a_x2bit + mul_x2b");
        // A = (A + x_i * y) + (u_i * m)
        _DPRINTF_("ui= 0x%08x\r\n", ui);
        _PRINT_BIGNUM_(conf->modulus, "conf->modulus");
        _FUNC_WRAP_(fr, mont_mul1w_bignum_unsigned_unsafe(mul_x2b, ui, conf->modulus));  _DPRINTF_("||%s:%d\n", __func__, __LINE__);
        _PRINT_BIGNUM_(mul_x2b, "mul_x2b = ui * m");
        _PRINT_BIGNUM_(a_x2bit, "a_x2bit");
        _PRINT_BIGNUM_(mul_x2b, "mul_x2b");
        _FUNC_WRAP_(fr, add_bignum_unsigned_unsafe(a_x2bit, a_x2bit, mul_x2b));     _DPRINTF_("||%s:%d\n", __func__, __LINE__);
        _PRINT_BIGNUM_(a_x2bit, "a_x2bit = a_x2bit + mul_x2b");
        // A = A/b
        _FUNC_WRAP_(fr, lsrb_bignum_self(a_x2bit, MONT_BASE_BIT));                  _DPRINTF_("||%s:%d\n", __func__, __LINE__);
        _PRINT_BIGNUM_(a_x2bit, "a_x2bit = a_x2bit / b");
    }
    // signed modulo
    cmp = cmp_bignum_logical_unsigned_unsafe(a_x2bit, conf->modulus);
    if(cmp == BIGNUM_CMP_GT || cmp == BIGNUM_CMP_EQ)
    {
        _FUNC_WRAP_(fr, sub_bignum_unsigned_unsafe(a_x2bit, a_x2bit, conf->modulus));
        _PRINT_BIGNUM_(a_x2bit, "a_x2bit = a_x2bit - conf->modulus");
    }
    else
    {
        _PRINT_BIGNUM_(a_x2bit, "a_x2bit = a_x2bit");
    }
    _FUNC_WRAP_(fr, cpy_bignum_unsigned_unsafe(mont, a_x2bit));                     _DPRINTF_("||%s:%d\n", __func__, __LINE__);

    rmBigNum(&a_x2bit);
    rmBigNum(&mul_x2b);

    _DPRINTF_("<<%s:%d\n", __func__, __LINE__);
    return fr;
#undef BIT_X2
}
