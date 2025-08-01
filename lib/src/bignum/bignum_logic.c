#include "bignum/bignum_logic.h"

ReturnType lsl1b_bignum(bignum_s* d, bignum_t* o, bignum_t c)
{
    if(d != NULL)
    {
        for(size_t i = 0U; i < d->nlen; i++)
        {
            bignum_t tmp = d->nums[i];
            d->nums[i] = ((d->nums[i] << 1U) | c);
            c = ((tmp >> (bignum_bits-1U)) != 0U)?(1U):(0U);
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
