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
        //const size_t lsr = BIGNUM_BITS - BIGNUM_REM_BITS(blen); // logical shift right bits to next bitnum
        printf("blen=%lu,lml=%lu,lsl=%lu\n", blen, lml, lsl);

        if(d->nlen > lml)
        {
            /* Not shift out condition */
            if(lml != 0UL)
            {
                /* Move condition */
                for(size_t dstIdx=d->nlen-1UL, srcIdx=d->nlen-1UL-lml; dstIdx>=lml; dstIdx--, srcIdx--)
                {
                    d->nums[dstIdx] = d->nums[srcIdx];
                }
                for(size_t clrIdx=0UL; clrIdx<lml; clrIdx++)
                {
                    d->nums[clrIdx] = 0x0UL;    // clear right side
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

ReturnType lslnb_bignum(bignum_s* d, bignum_t* co, const bignum_t ci, const size_t lslb)
{
    if(d != NULL)
    {
        if(BIGNUM_BITS > lslb)
        {
            const size_t lsrb = BIGNUM_BITS - lslb;
            bignum_t c = ci;

            for(size_t i = 0U; i < d->nlen; i++)
            {
                bignum_t tmp = d->nums[i];
                d->nums[i] = ((d->nums[i] << lslb) | c);
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
