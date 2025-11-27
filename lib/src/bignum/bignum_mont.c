#include <stdlib.h>
#include <stdint.h>

#include "bignum/bignum_mont.h"

#include "bignum/bignum.h"
#include "bignum/bignum_alu.h"
#include "common/util.h"

mont_conf_s* mkMontConf(const size_t bits)
{
    mont_conf_s* conf = (mont_conf_s*)malloc(sizeof(mont_conf_s));
    conf->bitsOfn = bits;
    conf->nlen = MONT_LEN_BITS(bits);
    conf->bitsOfm = bits;

    conf->m = mkBigNum(bits);
    (void)set_bignum(conf->m);  // m = 2^32n - 1

    conf->mu = mkBigNum(bits);  // mu = 2^32(n-1) - 1
    for(size_t i = 0UL; i < conf->mu->nlen-1UL; i++)
    {
        (void)set1w_bignum(conf->mu, i);
    }
    (void)clr1w_bignum(conf->mu, conf->mu->nlen - 1UL);
    (void)clr1w_bignum(conf->mu, 0UL);

    return conf;
}
int rmMontConf(mont_conf_s** conf)
{
    int fs = 0;
    if((void*)conf != NULL) {
        if((void*)(*conf) != NULL) {
            fs = rmBigNum((&(*conf)->m));
            fs = rmBigNum((&(*conf)->mu));
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

