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

ReturnType lsl1b_bignum(bignum_s* d, bignum_t* o, bignum_t c)
{
    if(d != NULL)
    {
        for(size_t i = 0U; i < d->nlen; i++)
        {
            bignum_t tmp = d->nums[i];
            d->nums[i] = ((d->nums[i] << 1U) | c);
            c = ((tmp >> (BIGNUM_BITS-1U)) != 0U)?(1U):(0U);
        }

        if(o != NULL)
        {
            *o = c;
        }
        else
        {
            /* Do nothing */
        }
    }
    else
    {
        return E_ERROR_NULL;
    }
    return E_OK;
}
