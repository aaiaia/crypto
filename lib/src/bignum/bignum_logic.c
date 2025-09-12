#ifdef DEBUG
#include <stdio.h>
#endif /* DEBUG */

#include "bignum/bignum_logic.h"

ReturnType inv_bignum(bignum_s* n)
{
    if(n != NULL)
    {
        for(size_t i = 0UL; i < n->nlen; i++)
        {
            n->nums[i] = ~n->nums[i];
        }
    }
    else
    {
        return E_ERROR_NULL;
    }
    return E_OK;
}

ReturnType set_bignum(bignum_s* n)
{
    if(n != NULL)
    {
        for(size_t i = 0UL; i < n->nlen; i++)
        {
            n->nums[i] = BIGNUM_MAX;
        }
    }
    else
    {
        return E_ERROR_NULL;
    }
    return E_OK;
}

ReturnType clr_bignum(bignum_s* n)
{
    if(n != NULL)
    {
        for(size_t i = 0UL; i < n->nlen; i++)
        {
            n->nums[i] = 0U;
        }
    }
    else
    {
        return E_ERROR_NULL;
    }
    return E_OK;
}

ReturnType set1b_bignum(bignum_s* n, const size_t bloc)
{
    const size_t widx = BIGNUM_BITS_IDX(bloc);
    const bignum_t bitMask = ( (1U<<BIGNUM_BITS_REM(bloc)));

    if(n == NULL)       return E_ERROR_NULL;
    if(n->nlen <= widx) return E_ERROR_ARGS;

    n->nums[widx] |= bitMask;

    return E_OK;
}
ReturnType clr1b_bignum(bignum_s* n, const size_t bloc)
{
    const size_t widx = BIGNUM_BITS_IDX(bloc);
    const bignum_t bitMask = (~(1U<<BIGNUM_BITS_REM(bloc)));

    if(n == NULL)       return E_ERROR_NULL;
    if(n->nlen <= widx) return E_ERROR_ARGS;

    n->nums[widx] &= bitMask;

    return E_OK;
}

#define _XSB_MASK_(VAL)  ((VAL)&1U)
/* MSB: Most Significant Bit */
size_t find_bignum_MSBL(const bignum_s* bignum)
{
    size_t wdidx = SIZE_MAX; // word index used in bignum_s
    size_t msblw = SIZE_MAX; // Most Significant Bit Location at word(not 1'b0)
    size_t msbln = SIZE_MAX; // Most Significant Bit Location at bignum(return value)

    for(size_t i = (bignum->nlen - 1UL); i < SIZE_MAX; i--)
    {
        if(bignum->nums[i] != 0x0UL)
        {
            wdidx = i;
            break;
        }
    }

    if(wdidx != SIZE_MAX)
    {
        for(bignum_t l = (BIGNUM_BITS - 1UL); l < BIGNUM_MAX; l--)
        {
            if(_XSB_MASK_(bignum->nums[wdidx] >> l) == 0x1U)
            {
                msblw = l;
                break;
            }
        }
    }

    if(msblw != SIZE_MAX)
    {
        msbln = BIGNUM_LEN_BITS(wdidx) + msblw;
    }

    return msbln;
}

/* MSB: Most Significant Bit */
size_t find_bignum_MSBL_bitLoc(const bignum_s* bignum, const size_t bitloc)
{
#define _WD_MSK_(bl)    (BIGNUM_MAX>>((BIGNUM_BITS-1U)-BIGNUM_BITS_REM(bl)))
    size_t find_wdidx = SIZE_MAX; // word index used in bignum_s
    size_t find_msblw = SIZE_MAX; // Most Significant Bit Location at word(not 1'b0)
    size_t find_msbln = SIZE_MAX; // Most Significant Bit Location at bignum(return value)
    size_t idx;
    bignum_t loc;
    if(bignum == NULL)          return SIZE_MAX;
    if(bitloc >= bignum->bits)  return SIZE_MAX;    // start bit location is over bit width

    // 0 -> 0, 31 -> 0, 32 -> 1, 63 -> 1, 64 -> 2, 95 -> 2, 96 -> 3 , ...
    idx = BIGNUM_BITS_IDX(bitloc);
    if((bignum->nums[idx] & _WD_MSK_(bitloc)) != 0x0UL)
    {
        find_wdidx = idx;
    }
    else
    {
        idx = (BIGNUM_BITS_IDX(bitloc) - 1U);
        while(idx < SIZE_MAX)
        {
            if(bignum->nums[idx] != 0x0UL)
            {
                find_wdidx = idx;
                break;
            }
            idx--;
        }
    }

    if(find_wdidx != SIZE_MAX)
    {
        if(find_wdidx == BIGNUM_BITS_IDX(bitloc))   loc = BIGNUM_BITS_REM(bitloc);
        else                                        loc = (BIGNUM_BITS - 1UL);
        while(loc < BIGNUM_MAX)
        {
            if(_XSB_MASK_(bignum->nums[find_wdidx] >> loc) == 0x1U)
            {
                find_msblw = loc;
                break;
            }
            loc--;
        }
    }

    if(find_msblw != SIZE_MAX)
    {
        find_msbln = BIGNUM_LEN_BITS(find_wdidx) + find_msblw;
    }

    return find_msbln;
#undef _WD_MSK_
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
        lsbln = BIGNUM_LEN_BITS(wdidx) + lsblw;
    }

    return lsbln;
}

/* LSB: Least Significant Bit */
size_t find_bignum_LSBL_bitLoc(const bignum_s* bignum, const size_t bitloc)
{
#define _WD_MSK_(bl)    (BIGNUM_MAX<<(BIGNUM_BITS_REM(bl)))
    size_t find_wdidx = SIZE_MAX; // word index used in bignum_s
    size_t find_lsblw = SIZE_MAX; // Least Significant Bit Location at word(not 1'b0)
    size_t find_lsbln = SIZE_MAX; // Least Significant Bit Location at bignum(return value)
    size_t idx;
    bignum_t loc;
    if(bignum == NULL)          return SIZE_MAX;
    if(bitloc >= bignum->bits)  return SIZE_MAX;    // start bit location is over bit width

    // 0 -> 0, 31 -> 0, 32 -> 1, 63 -> 1, 64 -> 2, 95 -> 2, 96 -> 3 , ...
    idx = BIGNUM_BITS_IDX(bitloc);
    if((bignum->nums[idx] & _WD_MSK_(bitloc)) != 0x0UL)
    {
        find_wdidx = idx;
    }
    else
    {
        idx = (BIGNUM_BITS_IDX(bitloc) + 1U);
        while(idx < bignum->nlen)
        {
            if(bignum->nums[idx] != 0x0UL)
            {
                find_wdidx = idx;
                break;
            }
            idx++;
        }
    }

    if(find_wdidx != SIZE_MAX)
    {
        if(find_wdidx == BIGNUM_BITS_IDX(bitloc))   loc = BIGNUM_BITS_REM(bitloc);
        else                                        loc = 0UL;
        while(loc < BIGNUM_BITS)
        {
            if(_XSB_MASK_(bignum->nums[find_wdidx] >> loc) == 0x1U)
            {
                find_lsblw = loc;
                break;
            }
            loc++;
        }
    }

    if(find_lsblw != SIZE_MAX)
    {
        find_lsbln = BIGNUM_LEN_BITS(find_wdidx) + find_lsblw;
    }

    return find_lsbln;
#undef _WD_MSK_
}
#undef _XSB_MASK_

ReturnType lslb_bignum_self(bignum_s* d, const size_t blen)
{
    const size_t lml = BIGNUM_BITS_IDX(blen); // logical move left bitnum
    const size_t lsl = BIGNUM_BITS_REM(blen); // logical shift left bits in bitnum
    ReturnType fr = E_NOT_OK;
#ifdef DEBUG
    printf("blen=%lu,lml=%lu,lsl=%lu\n", blen, lml, lsl);
#endif /* DEBUG */

    if(d->nlen > lml)
    {
        /* Move left word */
        fr = lmlw_bignum_self(d, lml);
        if(fr != E_OK)  return fr;
        /* Shift left bits */
        fr = lslnb_bignum_self(d, NULL, 0U, lsl);
        if(fr != E_OK)  return fr;
    }
    else
    {
        /* Shift out, set to all zero */
        fr = clr_bignum(d);
        if(fr != E_OK)  return fr;
    }

    return E_OK;
}

ReturnType lsrb_bignum_self(bignum_s* d, const size_t blen)
{
    const size_t lmr = BIGNUM_BITS_IDX(blen); // logical move right bitnum
    const size_t lsr = BIGNUM_BITS_REM(blen); // logical shift right bits in bitnum
    ReturnType fr = E_NOT_OK;
#ifdef DEBUG
    printf("blen=%lu,lmr=%lu,lsr=%lu\n", blen, lmr, lsr);
#endif /* DEBUG */

    if(d->nlen > lmr)
    {
        /* Move right word */
        fr = lmrw_bignum_self(d, lmr);
        if(fr != E_OK)  return fr;
        /* Shift right bits */
        fr = lsrnb_bignum_self(d, NULL, 0U, lsr);
        if(fr != E_OK)  return fr;
    }
    else
    {
        /* Shift out, set to all zero */
        fr = clr_bignum(d);
        if(fr != E_OK)  return fr;
    }

    return E_OK;
}

ReturnType lmlw_bignum_self(bignum_s* d, const size_t lml)
{
    if(d != NULL)
    {
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
        return E_OK;
    }
    else
    {
        return E_ERROR_NULL;
    }
}
ReturnType lmrw_bignum_self(bignum_s* d, const size_t lmr)
{
    if(d != NULL)
    {
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
        return E_OK;
    }
    else
    {
        return E_ERROR_NULL;
    }
}

ReturnType lslnb_bignum_self(bignum_s* d, bignum_t* co, const bignum_t ci, const size_t lslb)
{
    if(d != NULL)
    {
        if(lslb == 0UL)
        {
            /* no shift */
            return E_OK;
        }
        if(BIGNUM_BITS > lslb)
        {
            const size_t lsrb = BIGNUM_BITS - lslb;
            bignum_t c;

            if(lslb != 0U)
            {
                c = ci;
                for(size_t fi = 0U; fi != d->nlen; fi++)
                {
                    bignum_t tmp = d->nums[fi];
                    d->nums[fi] = ((d->nums[fi] << lslb) | c);
                    c = (tmp >> lsrb);
                }
            }
            else
            {
                c = 0U;
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

ReturnType lsrnb_bignum_self(bignum_s* d, bignum_t* co, const bignum_t ci, const size_t lsrb)
{
    if(d != NULL)
    {
        if(lsrb == 0UL)
        {
            /* no shift */
            return E_OK;
        }
        if(BIGNUM_BITS > lsrb)
        {
            const size_t lslb = BIGNUM_BITS - lsrb;
            bignum_t c;

            if(lsrb != 0U)
            {
                c = ci;
                for(size_t ii = d->nlen-1U; ii != SIZE_MAX ; ii--)
                {
                    bignum_t tmp = d->nums[ii];
                    d->nums[ii] = ((d->nums[ii] >> lsrb) | c);
                    c = (tmp << lslb);
                }
            }
            else
            {
                c = 0U;
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
