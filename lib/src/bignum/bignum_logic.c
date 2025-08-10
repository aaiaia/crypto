#ifdef DEBUG
#include <stdio.h>
#endif /* DEBUG */

#include "bignum/bignum_logic.h"

#define _XSB_MASK_(VAL)  ((VAL)&1U)
/* MSB: Most Significant Bit */
size_t find_bignum_MSBL(const bignum_s* bignum)
{
    size_t wdidx = SIZE_MAX; // word index used in bignum_s
    size_t msblw = SIZE_MAX; // Most Significant Bit Location at word(not 1'b0)
    size_t msbln = SIZE_MAX; // Most Significant Bit Location at bignum(return value)

    for(size_t i = bignum->nlen; i > 0UL ; i--)
    {
        if(bignum->nums[i - 1UL] != 0x0UL)
        {
            wdidx = i - 1UL;
            break;
        }
    }

    if(wdidx != SIZE_MAX)
    {
        for(bignum_t l = BIGNUM_BITS; l > 0U; l--)
        {
            if(_XSB_MASK_(bignum->nums[wdidx] >> (l - 1U)) == 0x1U)
            {
                msblw = (l - 1U);
                break;
            }
        }
    }

    if(msblw != SIZE_MAX)
    {
        msbln = BIGNUM_IDX_BITS(wdidx) + msblw;
    }

    return msbln;
}

/* LSB: Least Significant Bit */
size_t find_bignum_LSBL(const bignum_s* bignum)
{
    size_t wdidx = SIZE_MAX; // word index used in bignum_s
    size_t lsblw = SIZE_MAX; // Least Significant Bit Location at word(not 1'b0)
    size_t lsbln = SIZE_MAX; // Least Significant Bit Location at bignum(return value)

    for(size_t i = 0UL; i < bignum->nlen; i++)
    {
        if(bignum->nums[i] != 0x0UL)
        {
            wdidx = i;
            break;
        }
    }

    if(wdidx != SIZE_MAX)
    {
        for(bignum_t l = 0U; l < BIGNUM_BITS; l++)
        {
            if(_XSB_MASK_(bignum->nums[wdidx] >> l) == 0x1U)
            {
                lsblw = l;
                break;
            }
        }
    }

    if(lsblw != SIZE_MAX)
    {
        lsbln = BIGNUM_IDX_BITS(wdidx) + lsblw;
    }

    return lsbln;
}
#undef _XSB_MASK_

ReturnType lslb_bignum(bignum_s* d, const size_t blen)
{
    if(d != NULL)
    {
        const size_t lml = BIGNUM_QUO_BITS(blen); // logical move left bitnum
        const size_t lsl = BIGNUM_REM_BITS(blen); // logical shift left bits in bitnum
#ifdef DEBUG
        printf("blen=%lu,lml=%lu,lsl=%lu\n", blen, lml, lsl);
#endif /* DEBUG */

        if(d->nlen > lml)
        {
            /* Not shift out condition */
            if(lml != 0UL)
            {
                /* Move condition */
                /* dii: destination inverse index, sii: source inverse index */
                for(size_t dii=(d->nlen-1UL), sii=(d->nlen-lml-1UL); dii>=lml; dii--, sii--)
                {
                    d->nums[dii] = d->nums[sii];
                }
                /* clear forward index */
                for(size_t cfi=0UL; cfi<lml; cfi++)
                {
                    d->nums[cfi] = 0x0UL;    // clear right side
                }
            }
            else
            {
                /* Not move condition */
            }

            if(lsl != 0UL)
            {
                /* Shift condition */
                return lslnb_bignum(d, NULL, 0U, lsl);
            }
            else
            {
                /* Not shift condition */
            }
        }
        else
        {
            /* Shift out, set to all zero */
            for(size_t idx=0UL; idx<d->nlen; idx++)
            {
                d->nums[idx] = 0x0UL;
            }
        }
    }
    else
    {
        return E_ERROR_NULL;
    }

    return E_OK;
}

ReturnType lsrb_bignum(bignum_s* d, const size_t blen)
{
    if(d != NULL)
    {
        const size_t lmr = BIGNUM_QUO_BITS(blen); // logical move right bitnum
        const size_t lsr = BIGNUM_REM_BITS(blen); // logical shift right bits in bitnum
#ifdef DEBUG
        printf("blen=%lu,lmr=%lu,lsr=%lu\n", blen, lmr, lsr);
#endif /* DEBUG */

        if(d->nlen > lmr)
        {
            /* Not shift out condition */
            if(lmr != 0UL)
            {
                /* Move condition */
                /* dfi: destination forward index, sfi: source forward index */
                for(size_t dfi=0UL, sfi=lmr; sfi<(d->nlen); dfi++, sfi++)
                {
                    d->nums[dfi] = d->nums[sfi];
                }
                /* cii: clear inverse index */
                for(size_t cii=(d->nlen-1U); cii>(d->nlen-lmr-1U); cii--)
                {
                    d->nums[cii] = 0x0UL;    // clear left side
                }
            }
            else
            {
                /* Not move condition */
            }

            if(lsr != 0UL)
            {
                /* Shift condition */
                return lsrnb_bignum(d, NULL, 0U, lsr);
            }
            else
            {
                /* Not shift condition */
            }
        }
        else
        {
            /* Shift out, set to all zero */
            for(size_t idx=0UL; idx<d->nlen; idx++)
            {
                d->nums[idx] = 0x0UL;
            }
        }
    }
    else
    {
        return E_ERROR_NULL;
    }

    return E_OK;
}

ReturnType lslnb_bignum(bignum_s* d, bignum_t* co, const bignum_t ci, const size_t lslb)
{
    if(d != NULL)
    {
        if(BIGNUM_BITS > lslb)
        {
            const size_t lsrb = BIGNUM_BITS - lslb;
            bignum_t c = ci;

            for(size_t fi = 0U; fi != d->nlen; fi++)
            {
                bignum_t tmp = d->nums[fi];
                d->nums[fi] = ((d->nums[fi] << lslb) | c);
                c = (tmp >> lsrb);
            }

            if(co != NULL)
            {
                *co = c;
            }
            else
            {
                /* Do nothing */
            }
        }
        else
        {
            return E_ERROR_ARGS;
        }
    }
    else
    {
        return E_ERROR_NULL;
    }
    return E_OK;
}

ReturnType lsrnb_bignum(bignum_s* d, bignum_t* co, const bignum_t ci, const size_t lsrb)
{
    if(d != NULL)
    {
        if(BIGNUM_BITS > lsrb)
        {
            const size_t lslb = BIGNUM_BITS - lsrb;
            bignum_t c = ci;

            for(size_t ii = d->nlen-1U; ii != SIZE_MAX ; ii--)
            {
                bignum_t tmp = d->nums[ii];
                d->nums[ii] = ((d->nums[ii] >> lsrb) | c);
                c = (tmp << lslb);
            }

            if(co != NULL)
            {
                *co = c;
            }
            else
            {
                /* Do nothing */
            }
        }
        else
        {
            return E_ERROR_ARGS;
        }
    }
    else
    {
        return E_ERROR_NULL;
    }
    return E_OK;
}
