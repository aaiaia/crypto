#include <stdlib.h>

#include "bignum/bignum_wnaf.h"
#include "bignum/bignum_alu.h"

#if 0 /* ENABLE_BIGNUM_WNAF_LOG */
#ifndef ENABLE_BIGNUM_WNAF_LOG
#define ENABLE_BIGNUM_WNAF_LOG
#endif/* ENABLE_BIGNUM_WNAF_LOG */
#endif/* ENABLE_BIGNUM_WNAF_LOG */

#ifdef ENABLE_BIGNUM_WNAF_LOG
#include <stdio.h>
#include "test/test_tool.h"
#define _WNAF_FN_(RV, FN)           __RETURN_TYPE_WRAPPING__(RV, FN)

#define _DPRINTF_                   printf
#define _PRINT_wNAF_INFO_(p, title) test_print_wNAF_info(p, title)
#define _PRINT_BIGNUM_(p, title)    test_print_bignum(p, title)
#else
#define _WNAF_FN_(RV, FN)           ((RV) = (FN))

#define _DPRINTF_
#define _PRINT_wNAF_INFO_
#define _PRINT_BIGNUM_(p, title)
#endif/* ENABLE_BIGNUM_WNAF_LOG */

wnaf_s* mkWNAF(const uwnaf w, const size_t bits)
{
    if(!chkWNAF_window_lenth(w))    return NULL;
    wnaf_s* p = (wnaf_s*)malloc(sizeof(wnaf_s));
    p->bits = (bits+1U);
    p->size = (sizeof(uwnaf)*(p->bits));
    p->vLen = 0UL;
    p->window = w;
    p->signMsk = signMsk_WNAF(w);
    p->signExt = signExt_WNAF(w);
    p->wNafMsk = bitMask_WNAF(w);
    p->wnaf.ui = (uwnaf*)calloc(bits, sizeof(uwnaf));
}

int rmWNAF(wnaf_s** p)
{
    if((void*)p == NULL)   return -1;
    if((void*)(*p) == NULL)return -1;

    free((*p)->wnaf.ui);
    free((*p));
    (*p) = (wnaf_s*)NULL;
    return 0;
}

void convBigNum_wNAF(wnaf_s* dst, const bignum_s* src)
{
    ReturnType fr;
    size_t clrIdx = SIZE_MAX;

    if(!((dst != NULL) && (src != NULL)))   return; // NULL
    if(!(dst->bits == (src->bits + 1U)))    return; // bit length must fit with source(src)

    bignum_s* tmp_d = mkBigNum(dst->bits);
    _WNAF_FN_(fr, cpy_bignum_unsigned_safe(tmp_d, src));

    _PRINT_wNAF_INFO_(dst, "convBigNum_wNAF");

    const uwnaf wNafMsk = dst->wNafMsk;
    const uwnaf signMsk = dst->signMsk;
    const uwnaf signExt = dst->signExt;
    for(size_t i = 0UL; i < tmp_d->bits; i++)
    {
        bignum_cmp_e cmp_d;

        _DPRINTF_("[%lu] ", i); _PRINT_BIGNUM_(tmp_d, "tmp_d");
        if(tmp_d->nums[0]&0x1U) {
            const uwnaf vWNAF = (((uwnaf)tmp_d->nums[0])&wNafMsk);
            // d mods 2^w
            const uwnaf pWNAF = vWNAF;
            //(d mod 2^w) - 2^w
            const uwnaf nWNAF = vWNAF | signExt;
            _DPRINTF_("pWNAF: 0x%02x, nWNAF: 0x%02x\r\n", pWNAF, nWNAF);

            // (d mod 2^w) >= 2^(w−1) -> means that negative
            if((pWNAF & signMsk) == 0x0U)
            {
                // Positive in Masked Value
                // d mods 2^w: just masking MASK_VAL[w:0] has all 1'1 bits
                dst->wnaf.ui[i] = pWNAF;
                _DPRINTF_("Positive in masked value, d mods 2^w: 0x%02x, ", dst->wnaf.ui[i]);
            }
            else
            {
                // Negative in Masked Value
                // (d mod 2^w) - 2^w : means that extends sign bits
                dst->wnaf.ui[i] = nWNAF;
                _DPRINTF_("Negative in masked value, (d mod 2^w) - 2^w: 0x%02x \r\n", dst->wnaf.ui[i]);
            }
            _DPRINTF_("[%lu] 0x%08x\t\n", i, ((bignum_t)dst->wnaf.si[i]));
            sub_bignum_carry_loc_signed(tmp_d, ((bignum_t)dst->wnaf.si[i]), 0U);
            _DPRINTF_("[%lu] ", i); _PRINT_BIGNUM_(tmp_d, "substracted tmp_d");
        }
        else {
            dst->wnaf.ui[i] = 0U;
        }
        _WNAF_FN_(fr, lsrb_bignum_self(tmp_d, 1U));
        _DPRINTF_("[%lu] ", i); _PRINT_BIGNUM_(tmp_d, "tmp_d>>1");
        cmp_d = cmp0_bignum(tmp_d);
        if(cmp_d == BIGNUM_CMP_ZO) {
            dst->vLen = (i + 1UL);
            break;
        }
        else if(cmp_d == BIGNUM_CMP_NZ) {
            continue;
        } else {
            /* has error or invalid cases */
            dst->vLen = 0UL;
            break;
        }
    }
    _DPRINTF_("[end] ");
    _PRINT_BIGNUM_(tmp_d, "tmp_d");

    for(size_t i = dst->vLen; i < tmp_d->bits; i++) {
        dst->wnaf.ui[i] = 0U;
    }

    rmBigNum(&tmp_d);
}

