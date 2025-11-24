#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "bignum/bignum_alu.h"

#if 0 /* ENABLE_BIGNUM_LOG */
#ifndef ENABLE_BIGNUM_LOG
#define ENABLE_BIGNUM_LOG
#endif/* ENABLE_BIGNUM_LOG */
#endif/* ENABLE_BIGNUM_LOG */

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

#define BIGNUM_SIGN_MASK(N, IGN)    ((((N)->nums[(N)->nlen-1U]&BIGNUM_MSB_MASK)&&(!(IGN)))?(BIGNUM_MAX):(0U))
#define BIGNUM_PRC_LEN(D, S)        (((D)->nlen > (S)->nlen)?((S)->nlen):((D)->nlen))
#define BIGNUM_EXT_LEN(D, S)        ((D)->nlen)
#define BIGNUM_SAME_LEN(D, S)       ((D)->nlen == (S)->nlen)
#define BIGNUM_SAME_BIT(D, S)       ((D)->bits == (S)->bits)

ReturnType inv_bignum(bignum_s* n)
{
    if(!(n != NULL))    return E_ERROR_NULL;

    for(size_t i = 0UL; i < n->nlen; i++)
    {
        n->nums[i] = ~n->nums[i];
    }
    return E_OK;
}

ReturnType set_bignum(bignum_s* n)
{
    if(!(n != NULL))    return E_ERROR_NULL;

    for(size_t i = 0UL; i < n->nlen; i++)
    {
        n->nums[i] = BIGNUM_MAX;
    }
    return E_OK;
}

ReturnType clr_bignum(bignum_s* n)
{
    if(!(n != NULL))    return E_ERROR_NULL;

    for(size_t i = 0UL; i < n->nlen; i++)
    {
        n->nums[i] = 0U;
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
bignum_t chk1b_bignum(const bignum_s* n, const size_t bloc)
{
    const size_t widx = BIGNUM_BITS_IDX(bloc);
    const bignum_t bitMask = ( (1U<<BIGNUM_BITS_REM(bloc)));

    if(n == NULL)               return BIGNUM_MAX;
    if(n->nlen <= widx)         return BIGNUM_MAX;

    return (n->nums[widx] & bitMask);
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

ReturnType slb_bitnum_self_ext(bignum_s* d, const size_t blen, const bool arith)
{
    const size_t lml = BIGNUM_BITS_IDX(blen); // logical move left bitnum
    const size_t lsl = BIGNUM_BITS_REM(blen); // logical shift left bits in bitnum
    ReturnType fr = E_NOT_OK;
    _DPRINTF_("blen=%lu,lml=%lu,lsl=%lu\n", blen, lml, lsl);

    if(d->nlen > lml)
    {
        /* Move left word */
        fr = mlw_bignum_self_ext(d, lml, arith);
        if(fr != E_OK)  return fr;
        /* Shift left bits */
        fr = slnb_bignum_self_ext(d, NULL, 0U, lsl, arith);
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

ReturnType srb_bignum_self_ext(bignum_s* d, const size_t blen, const bool arith)
{
    const size_t lmr = BIGNUM_BITS_IDX(blen); // logical move right bitnum
    const size_t lsr = BIGNUM_BITS_REM(blen); // logical shift right bits in bitnum
    ReturnType fr = E_NOT_OK;
    _DPRINTF_("blen=%lu,lmr=%lu,lsr=%lu\n", blen, lmr, lsr);

    if(d->nlen > lmr)
    {
        /* Move right word */
        fr = mrw_bignum_self_ext(d, lmr, arith);
        if(fr != E_OK)  return fr;
        /* Shift right bits */
        fr = srnb_bignum_self_ext(d, NULL, 0U, lsr, arith);
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

ReturnType mlw_bignum_self_ext(bignum_s* d, const size_t lml, const bool arith)
{
    if(!(d != NULL))    return E_ERROR_NULL;

    if(lml != 0UL)
    {
        const bignum_t signBitMask = d->nums[d->nlen-1ul] & (1u<<(BIGNUM_BITS-1u));

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

        if(arith)
        {
            if((d->nums[d->nlen] & (1u<<(BIGNUM_BITS-1u))) != signBitMask)
            {
                return E_ERROR_BIGNUM_SIGNBIT;
            }
        }
    }
    else
    {
        /* Not move condition */
    }
    return E_OK;
}
ReturnType mrw_bignum_self_ext(bignum_s* d, const size_t lmr, const bool arith)
{
    if(!(d != NULL))    return E_ERROR_NULL;

    if(lmr != 0UL)
    {
        bignum_t signBitMask;

        if(!arith)
        {
            signBitMask = 0U;
        }
        else
        {
            if(d->nums[d->nlen-1ul] & (1u<<(BIGNUM_BITS-1u)))
            {
                signBitMask = BIGNUM_MAX;
            }
            else
            {
                signBitMask = 0u;
            }
        }
        /* Move condition */
        /* dfi: destination forward index, sfi: source forward index */
        for(size_t dfi=0UL, sfi=lmr; sfi<(d->nlen); dfi++, sfi++)
        {
            d->nums[dfi] = d->nums[sfi];
        }
        /* cii: clear inverse index */
        for(size_t cii=(d->nlen-1U); cii>(d->nlen-lmr-1U); cii--)
        {
            d->nums[cii] = signBitMask;    // clear left side
        }
    }
    else
    {
        /* Not move condition */
    }
    return E_OK;
}

ReturnType slnb_bignum_self_ext(bignum_s* d, bignum_t* co, const bignum_t ci, const size_t lslb, const bool arith)
{
    if(!(d != NULL))            return E_ERROR_NULL;
    if(!(BIGNUM_BITS > lslb))   return E_ERROR_ARGS;

    const size_t lsrb = BIGNUM_BITS - lslb;
    bignum_t c;
    const bignum_t signBitMask = d->nums[d->nlen-1ul] & (1u<<(BIGNUM_BITS-1u));

    if(lslb != 0U)
    {
        c = ci;
        for(size_t fi = 0U; fi != d->nlen; fi++)
        {
            bignum_t tmp = d->nums[fi];
            d->nums[fi] = ((d->nums[fi] << lslb) | c);
            c = (tmp >> lsrb);
        }

        if(arith)
        {
            if((d->nums[d->nlen] & (1u<<(BIGNUM_BITS-1u))) != signBitMask)
            {
                return E_ERROR_BIGNUM_SIGNBIT;
            }
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
    return E_OK;
}

ReturnType srnb_bignum_self_ext(bignum_s* d, bignum_t* co, const bignum_t ci, const size_t lsrb, const bool arith)
{
    if(!(d != NULL))            return E_ERROR_NULL;
    if(!(BIGNUM_BITS > lsrb))   return E_ERROR_ARGS;

    const size_t lslb = BIGNUM_BITS - lsrb;
    bignum_t c;
    bignum_t signBitMask;

    if(!arith)
    {
        signBitMask = 0x0U;
    }
    else
    {
        if(d->nums[d->nlen-1UL] & (1U<<(BIGNUM_BITS-1U)))
        {
            signBitMask = (BIGNUM_MAX << lslb);
        }
        else
        {
            signBitMask = 0U;
        }
    }

    if(lsrb != 0U)
    {
        c = ci;
        for(size_t ii = d->nlen-1U; ii != SIZE_MAX ; ii--)
        {
            bignum_t tmp = d->nums[ii];
            d->nums[ii] = ((d->nums[ii] >> lsrb) | c);
            c = (tmp << lslb);
        }
        d->nums[d->nlen-1U] |= signBitMask; // arith matic shift
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
    return E_OK;
}

ReturnType cpy_bignum_mode_ext(bignum_s* d, const bignum_s* s, const bool inverse, const bool ign_sign, const bool ign_len) {
    if(!((d != NULL) && (s != NULL))) {
        _DPRINTF_("[ERROR] @%s:%d, d:0x%p, s:0x%p\n", __func__, __LINE__, d, s);
        return E_ERROR_NULL;
    }
    if(!((d->nums != NULL) && (s->nums != NULL))) {
        _DPRINTF_("[ERROR] @%s:%d, d->nums:0x%p, s->nums:0x%p\n", __func__, __LINE__, d->nums, s->nums);
        return E_ERROR_NULL;
    }

    const bignum_t signBit = BIGNUM_SIGN_MASK(s, ign_sign);
    const size_t cpyLen = BIGNUM_PRC_LEN(d, s);
    const size_t extLen = BIGNUM_EXT_LEN(d, s);

    _DPRINTF_("@%s:%d, signBit=0x%x, cpyLen=%ld, extLen=%ld\n", __func__, __LINE__, signBit, cpyLen, extLen);
    _DPRINTF_("@%s:%d, signBit=0x%x, d->nlen=%ld, s->nlen=%ld\n", __func__, __LINE__, signBit, d->nlen, s->nlen);
    if((d->nlen < s->nlen) && (!ign_len)) {
        _DPRINTF_("[ERROR] @%s:%d, d->nlen=%ld, s->nlen=%ld\n", __func__, __LINE__, d->nlen, s->nlen);
        // Accept only same length
        return E_ERROR_BIGNUM_LENGTH;
    }

    for(size_t i = cpyLen; i < extLen; i++) {
        if(!inverse)    d->nums[i] =  (signBit);
        else            d->nums[i] = ~(signBit);
    }
    for(size_t i = 0; i < cpyLen; i++) {
        if(!inverse)    d->nums[i] =  (s->nums[i]);
        else            d->nums[i] = ~(s->nums[i]);
    }

    return E_OK;
}

ReturnType cpy_bignum_twos_ext(bignum_s* d, const bignum_s* s, const bool ign_sign, const bool ign_len)
{
    ReturnType ret = E_NOT_OK;

    ret = cpy_bignum_inverse_ext(d, s, ign_sign, ign_len);
    if(ret != E_OK) return ret;

    (void)add_bignum_carry_loc_unsigned(d, 1UL, 0UL);

    ret = E_OK;

    return ret;
}

ReturnType cpy_bignum_abs_safe_ext(bignum_s* d, const bignum_s* s, const bool ign_sign)
{
    if((d == NULL) || (s == NULL))  return E_ERROR_NULL;

    if(!BIGNUM_SIGN_MASK(s, ign_sign)) // positive
    {
        return cpy_bignum_ext(d, s, ign_sign, false);
    }
    else // negative
    {
        return cpy_bignum_twos_ext(d, s, ign_sign, false);
    }
}

bignum_sign_e sign_bignum_ext(const bignum_s* s, const bool ign_sign)
{
    if(!(s != NULL))                            return BIGNUM_SIGN_ERR;
    if(!(s->nlen != 0UL))                       return BIGNUM_SIGN_ERR;
    if(!(s->nums != NULL))                      return BIGNUM_SIGN_ERR;

    if(!(BIGNUM_SIGN_MASK(s, ign_sign)))        return BIGNUM_SIGN_POS;
    else                                        return BIGNUM_SIGN_NEG;
}

bignum_cmp_e cmp0_bignum(const bignum_s* s) {
    if(!(s != NULL))    return BIGNUM_CMP_ER;

    for(size_t i = 0UL; i < s->nlen; i++)
    {
        if(s->nums[i] != 0U)    return BIGNUM_CMP_NZ;
    }
    return BIGNUM_CMP_ZO;
}

bignum_cmp_e cmp1_bignum(const bignum_s* s) {
    if(!(s != NULL))    return BIGNUM_CMP_ER;

    if(s->nlen >= 1UL)
    {
        if(s->nums[0] != 1U)    return BIGNUM_CMP_NO;
    }

    for(size_t i = 1UL; i < s->nlen; i++)
    {
        if(s->nums[i] != 0U)    return BIGNUM_CMP_NO;
    }
    return BIGNUM_CMP_ON;
}
/* +1: s0  > s1
 *  0: s0 == s1
 * -1: s0  < s1
 */
bignum_cmp_e cmp_bignum_with_sub_add_twos(const bignum_s* s0, const bignum_s* s1) {
    bignum_cmp_e cmp = BIGNUM_CMP_ER;
    bignum_s* tmp;    // 2's compliment...?...
                        //
    if(s0->bits > s1->bits) tmp = mkBigNum(s0->bits);
    else                    tmp = mkBigNum(s1->bits);

    if(sub_bignum_with_add_twos(tmp, s0, s1) == E_OK)
    {
        bignum_sign_e zero = cmp0_bignum(tmp);
        bignum_sign_e sign = sign_bignum_signed(tmp);

        if(zero == BIGNUM_CMP_ZO)               cmp = BIGNUM_CMP_EQ; // zero
        else if(zero == BIGNUM_CMP_NZ)
        {
            if(sign == BIGNUM_SIGN_POS)         cmp = BIGNUM_CMP_GT; // positive
            else if(sign == BIGNUM_SIGN_NEG)    cmp = BIGNUM_CMP_LT; // negative
            else                                cmp = BIGNUM_CMP_ER;
        }
        else                                    cmp = BIGNUM_CMP_ER; // zero
    }
    else
    {
        cmp = BIGNUM_CMP_ER; // error
    }

    rmBigNum(&tmp);

    return cmp;
}

bignum_cmp_e cmp_bignum_logical_ext(const bignum_s* s0, const bignum_s* s1, const bool ign_len, const bool ign_sign) {
    bignum_sign_e sig_s0 = sign_bignum_ext(s0, ign_sign);
    bignum_sign_e sig_s1 = sign_bignum_ext(s1, ign_sign);
    _DPRINTF_("@%s:%d, ign_len:%u, ign_sign:%u\r\n", __func__, __LINE__, ign_len, ign_sign);
    _DPRINTF_("@%s:%d, sig_s0:%u\r\n", __func__, __LINE__, sig_s0);
    _DPRINTF_("@%s:%d, sig_s1:%u\r\n", __func__, __LINE__, sig_s1);

    _DPRINTF_("@%s:%d, ", __func__, __LINE__); _PRINT_BIGNUM_(s0, "s0");
    _DPRINTF_("@%s:%d, ", __func__, __LINE__); _PRINT_BIGNUM_(s1, "s1");
    /* sign_bignum_signed() is checking invalid case of input arguments 's0' and 's1' */
    if((sig_s0 == BIGNUM_SIGN_ERR) || (sig_s1 == BIGNUM_SIGN_ERR))
	{
		_DPRINTF_("@%s:%d, BIGNUM_CMP_ERR, sig_s0: %d\r\n", __func__, __LINE__, sig_s0);
		_DPRINTF_("@%s:%d, BIGNUM_CMP_ERR, sig_s1: %d\r\n", __func__, __LINE__, sig_s1);
        return BIGNUM_CMP_ER;
	}
    if((!BIGNUM_SAME_LEN(s0, s1) || !BIGNUM_SAME_BIT(s0, s1)) && (!ign_len))
	{
		_DPRINTF_("@%s:%d, BIGNUM_CMP_ERR, sig_s0: %d\r\n", __func__, __LINE__, sig_s0);
		_DPRINTF_("@%s:%d, BIGNUM_CMP_ERR, sig_s1: %d\r\n", __func__, __LINE__, sig_s1);
        return BIGNUM_CMP_ER;
	}

    // 1's compiment comparing
    //  b0000_0000_0001 (positive b0000_0000_0001)b1111_1111_1110+b1 -> (2's) b1111_1111_1111 => (1's) b0000_0000_0000
    //  b0000_0000_0010 (positive b0000_0000_0010)b1111_1111_1101+b1 -> (2's) b1111_1111_1110 => (1's) b0000_0000_0001
    //  b0111_1111_1110 (positive b0111_1111_1110)b1000_0000_0001+b1 -> (2's) b1000_0000_0010 => (1's) b0111_1111_1101
    //  b0111_1111_1111 (positive b0111_1111_1111)b1000_0000_0000+b1 -> (2's) b1000_0000_0001 => (1's) b0111_1111_1110
    if(sig_s0 == sig_s1) /* s0 and s1 has same significant bit */
    {
        const size_t cmp_nlen = BIGNUM_PRC_LEN(s0, s1);
        const size_t cmp_elen = BIGNUM_EXT_LEN(s0, s1);

        const bignum_t s0_signBit = BIGNUM_SIGN_MASK(s0, ign_sign);
        const bignum_t s1_signBit = BIGNUM_SIGN_MASK(s1, ign_sign);
        _DPRINTF_("@%s:%d, s0_signBit:0x%x\r\n", __func__, __LINE__, s0_signBit);
        _DPRINTF_("@%s:%d, s1_signBit:0x%x\r\n", __func__, __LINE__, s1_signBit);

        _DPRINTF_("@%s:%d, cmp_nlen: %lu, cmp_elen: %lu\r\n", __func__, __LINE__, cmp_nlen, cmp_elen);
        if(s0->nlen > s1->nlen)
        {
            _DPRINTF_("@%s:%d, s0->nlen:%lu > s1->nlen:%lu\r\n", __func__, __LINE__, s0->nlen, s1->nlen);
            for(size_t idx = cmp_elen - 1UL; idx > cmp_nlen - 1UL; idx--)
            {
                if(s0->nums[idx] > s1_signBit)  return BIGNUM_CMP_GT;
                if(s0->nums[idx] < s1_signBit)  return BIGNUM_CMP_LT;
            }
        }
        else if((s0->nlen < s1->nlen))
        {
            _DPRINTF_("@%s:%d, s0->nlen:%lu < s1->nlen:%lu\r\n", __func__, __LINE__, s0->nlen, s1->nlen);
            for(size_t idx = cmp_elen - 1UL; idx > cmp_nlen - 1UL; idx--)
            {
                if(s0_signBit > s1->nums[idx])  return BIGNUM_CMP_GT;
                if(s0_signBit < s1->nums[idx])  return BIGNUM_CMP_LT;
            }
        }
        else
        {
            _DPRINTF_("@%s:%d, s0->nlen:%lu == s1->nlen:%lu\r\n", __func__, __LINE__, s0->nlen, s1->nlen);
            /* s0->nlen == s1->nlen Case */
            /* Continues belows */
        }

        for(size_t idx = cmp_nlen - 1UL; idx < SIZE_MAX; idx--)
        {
            if(s0->nums[idx] > s1->nums[idx])   return BIGNUM_CMP_GT;
            if(s0->nums[idx] < s1->nums[idx])   return BIGNUM_CMP_LT;
        }

                                                return BIGNUM_CMP_EQ;
    }
    else if(sig_s0 == BIGNUM_SIGN_POS)          return BIGNUM_CMP_GT;
    else if(sig_s1 == BIGNUM_SIGN_POS)          return BIGNUM_CMP_LT;
    else                                        return BIGNUM_CMP_ER; /* Unreachable */
}

/* Return carry out, it can be only FALSE / TRUE, the others are error */
ReturnType add_bignum_ext(bignum_t* co, bignum_s* d, const bignum_s* s0, const bignum_s* s1, const bignum_t ci, const bool ign_sign) {
    if(!((d != NULL) && (s0 != NULL) && (s1 != NULL)))
        return E_ERROR_NULL;

    if(!((d->nlen >= s0->nlen) && (d->nlen >= s1->nlen)))
        return E_ERROR_BIGNUM_LENGTH;

    bignum_t _c = ci;

    /* just Consider Condition(d->nlen == s1->nlen == s0->nlen) */
    const bignum_t _bf0_ = BIGNUM_SIGN_MASK(s0, ign_sign);  // _bfN_: bit fill sN
    const bignum_t _bf1_ = BIGNUM_SIGN_MASK(s1, ign_sign);  // _bfN_: bit fill sN

    for(size_t i=0ul; i<d->nlen; i++) {
        bignum_t _ts0_, _ss0_;   // _tsN_: temp sN, _ssN_: selecte sN
        bignum_t _ts1_, _ss1_;

        if(i < s0->nlen)    _ss0_ = s0->nums[i];
        else                _ss0_ = _bf0_;
        _ts0_ = _ss0_ + _c;
        _c = (_ts0_ < _ss0_);

        if(i < s1->nlen)    _ss1_ = s1->nums[i];
        else                _ss1_ = _bf1_;
        _ts1_ = _ts0_ + _ss1_;
        _c |= (_ts1_ < _ts0_);
        d->nums[i] = _ts1_;
    }

    if(co != NULL)  (*co) = _c;

    return E_OK;
}

bignum_t add_bignum_carry_loc_ext(bignum_s* d, const bignum_t v, const size_t idx, const bool ign_sign) {
    bignum_t _s;
    bignum_t _c = v;
    bignum_t SIGN_EXT = ((BIGNUM_SIGN_BIT(v) != 0U) && (!ign_sign))?(BIGNUM_MAX):(0U);

    for(size_t i = idx; i < d->nlen; i++) {
        _s = d->nums[i] + _c;
        _c = (_s < d->nums[i]);
        _c += SIGN_EXT;  // sign bits
        d->nums[i] = _s;
        if(_c != 0UL) {
            continue;
        }
        else {
            break;
        }
    }

    return _c;
}

#if 0 /* sub_bignum_carry_loc_ext */
#   ifndef ENABLE_BIGNUM_LOG
#      ifdef _DPRINTF_
#          undef _DPRINTF_
#          define _DPRINTF_                   printf
#      endif
#      ifdef _PRINT_BIGNUM_
#          undef _PRINT_BIGNUM_
#          define _PRINT_BIGNUM_(p, title)    test_print_bignum(p, title)
#      endif
#   endif /*ENABLE_BIGNUM_LOG*/
#endif/* sub_bignum_carry_loc_ext */
bignum_t sub_bignum_carry_loc_ext(bignum_s* d, const bignum_t v, const size_t idx, const bool ign_sign) {
    bignum_t _s;
    bignum_t _c = v;
    const bignum_t SIGN_EXT = ((BIGNUM_SIGN_BIT(v) != 0U) && (!ign_sign))?(BIGNUM_MAX):(0U);;

    _DPRINTF_("[INFO] @%s:%d, ", __func__, __LINE__); _PRINT_BIGNUM_(d, "d");
    _DPRINTF_("[INFO] @%s:%d, ", __func__, __LINE__); _DPRINTF_("v: 0x%08x\r\n", v);
    _DPRINTF_("[INFO] @%s:%d, ", __func__, __LINE__); _DPRINTF_("SIGN_EXT: 0x%08x\r\n", SIGN_EXT);
    for(size_t i = idx; i < d->nlen; i++) {
        _DPRINTF_("[%lu]_ci:0x%08x, d->nums:0x%08x, ", i, _c, d->nums[i]);
        _s = d->nums[i] - _c;
        _c = (_s > d->nums[i]);
        _c += SIGN_EXT;  // sign bits
        d->nums[i] = _s;
        _DPRINTF_("_s:0x%08x, _co:0x%08x\r\n", _s, _c);
        if(_c != 0UL) {
            continue;
        }
        else {
            break;
        }
    }

    return _c;
}
#if 0 /* sub_bignum_carry_loc_ext */
#   ifndef ENABLE_BIGNUM_LOG
#      ifdef _DPRINTF_
#          undef _DPRINTF_
#          define _DPRINTF_
#      endif
#      ifdef _PRINT_BIGNUM_
#          undef _PRINT_BIGNUM_
#          define _PRINT_BIGNUM_
#      endif
#   endif/* ENABLE_BIGNUM_LOG */
#endif/* sub_bignum_carry_loc_ext */

/* Return carry out, it can be only FALSE / TRUE, the others are error */
#if 0 /* sub_bignum_ext */
#   ifndef ENABLE_BIGNUM_LOG
#      ifdef _DPRINTF_
#          undef _DPRINTF_
#          define _DPRINTF_                   printf
#      endif
#      ifdef _PRINT_BIGNUM_
#          undef _PRINT_BIGNUM_
#          define _PRINT_BIGNUM_(p, title)    test_print_bignum(p, title)
#      endif
#   endif /*ENABLE_BIGNUM_LOG*/
#endif/* sub_bignum_ext */
ReturnType sub_bignum_ext(bignum_t* co, bignum_s* d, const bignum_s* s0, const bignum_s* s1, const bignum_t ci, const bool ign_sign) {
    if(!((d != NULL) && (s0 != NULL) && (s1 != NULL)))
        return E_ERROR_NULL;

    if(!((d->nlen >= s0->nlen) && (d->nlen >= s1->nlen)))
        return E_ERROR_BIGNUM_LENGTH;

    {
        bignum_t _c = ci;

        const bignum_t _bf0_ = BIGNUM_SIGN_MASK(s0, ign_sign);  // _bfN_: bit fill sN
        const bignum_t _bf1_ = BIGNUM_SIGN_MASK(s1, ign_sign);  // _bfN_: bit fill sN

        _DPRINTF_("@%s:%d, _bf0_:0x%x, _bf1_:0x%x\r\n",  __func__, __LINE__, _bf0_, _bf1_);

        for(size_t i=0UL; i<d->nlen; i++) {
            bignum_t _ts0_, _ss0_;
            bignum_t _ts1_, _ss1_;

            if(i < s0->nlen)    _ss0_ = s0->nums[i];
            else                _ss0_ = _bf0_;
            _ts0_ = _ss0_ - _c;
            _c = (_ts0_ > _ss0_);

            if(i < s1->nlen)    _ss1_ = s1->nums[i];
            else                _ss1_ = _bf1_;
            _ts1_ = _ts0_ - _ss1_;
            _c |= (_ts1_ > _ts0_);
            d->nums[i] = _ts1_;
        }

        if(co != NULL)  (*co) = _c;
    }
    return E_OK;
}
#if 0 /* sub_bignum_ext */
#   ifndef ENABLE_BIGNUM_LOG
#      ifdef _DPRINTF_
#          undef _DPRINTF_
#          define _DPRINTF_
#      endif
#      ifdef _PRINT_BIGNUM_
#          undef _PRINT_BIGNUM_
#          define _PRINT_BIGNUM_
#      endif
#   endif/* ENABLE_BIGNUM_LOG */
#endif/* sub_bignum_ext */

ReturnType sub_bignum_with_add_twos_ext(bignum_t* co, bignum_s* d, const bignum_s* s0, const bignum_s* s1, const bignum_t ci) {
    if(!((d != NULL) && (s0 != NULL) && (s1 != NULL)))
        return E_ERROR_NULL;

    if(!((d->nlen >= s0->nlen) && (d->nlen >= s1->nlen)))
        return E_ERROR_BIGNUM_LENGTH;

    {
        bignum_t _c = ci + 1U;  // 2's compliment

        /* just Consider Condition(d->nlen == s1->nlen == s0->nlen) */
        const bignum_t _bf0_ = BIGNUM_SIGN_MASK(s0, true);  // _bfN_: bit fill sN
        const bignum_t _bf1_ = BIGNUM_SIGN_MASK(s1, false);   // _bfN_: bit fill sN

        for(size_t i=0ul; i<d->nlen; i++) {
            bignum_t _ts0_, _ss0_;   // _tsN_: temp sN, _ssN_: selecte sN
            bignum_t _ts1_, _ss1_;

            if(i < s0->nlen)    _ss0_ = ( (s0->nums[i]));
            else                _ss0_ = _bf0_;
            _ts0_ = _ss0_ + _c;
            _c = (_ts0_ < _ss0_);

            if(i < s1->nlen)    _ss1_ = (~(s1->nums[i]));
            else                _ss1_ = _bf1_;
            _ts1_ = _ts0_ + _ss1_;
            _c |= (_ts1_ < _ts0_);
            d->nums[i] = _ts1_;
        }

        if(co != NULL)  (*co) = _c;
    }

    return E_OK;
}

// idea notes.
// s0 accumulates then shift left
// s1 checks inclease nums index and shift likes bit witth
ReturnType mul_bignum_1bs_ext(bignum_s* d, const bignum_s* s1, const bignum_s* s0, const bool ign_len) {
    if(!((d != NULL) && (s1 != NULL) && (s0 != NULL)))  return E_ERROR_NULL;
    if((!(s1->bits == s0->bits)) && (!ign_len))         return E_ERROR_BIGNUM_LENGTH;
    if((!(d->bits >= s0->bits)) && (!ign_len))          return E_ERROR_BIGNUM_LENGTH;
    if((!(d->bits >= s1->bits)) && (!ign_len))          return E_ERROR_BIGNUM_LENGTH;

    bignum_s* acc = mkBigNum(d->bits);
    bignum_s* es0 = mkBigNum(d->bits);
    bignum_s* es1 = mkBigNum(d->bits);

    clr_bignum(acc);
    cpy_bignum_signed_unsafe(es0, s0);
    cpy_bignum_signed_unsafe(es1, s1);

    size_t nSftBit = es0->bits;
    const bool ign_sign = true;
    for(size_t i = 0U; i < es1->nlen; i++) {
        size_t sftBit = (nSftBit >= BIGNUM_BITS)?(BIGNUM_BITS):(nSftBit);
        for(size_t sft = 0U; sft < sftBit; sft++) {
            if(((es1->nums[i] >> sft) & 0x1U) != 0x0u) {
                bignum_t co = BIGNUM_MAX;
                if(add_bignum_ext(&co, acc, acc, es0, 0U, ign_sign) != E_OK) // unsigned
                {
                    return E_ERROR_RUNTIME;
                }
            } else { /* Do nothing */}
            asl1b_bignum_self(es0, NULL, 0U);
        }
        nSftBit-=sftBit;
    }
    cpy_bignum_unsigned_unsafe(d, acc);

    rmBigNum(&acc);
    rmBigNum(&es0);

    if(nSftBit != 0U) {
        return E_ERROR_RUNTIME;
    } else { /* Do nothing */ }

    return E_OK;
}

ReturnType mul_bignum_nbs_dn2up_ext(bignum_s* d, const bignum_s* s1, const bignum_s* s0, const bool ign_sign, const bool ign_len) {
    if(!((d != NULL) && (s1 != NULL) && (s0 != NULL)))  return E_ERROR_NULL;
    if((!(s1->bits == s0->bits)) && (!ign_len))         return E_ERROR_BIGNUM_LENGTH;
    if((!(d->bits >= s0->bits)) && (!ign_len))          return E_ERROR_BIGNUM_LENGTH;
    if((!(d->bits >= s1->bits)) && (!ign_len))          return E_ERROR_BIGNUM_LENGTH;

    _DPRINTF_("s1->bits = %lu\n", s1->bits);
    _DPRINTF_("s0->bits = %lu\n", s0->bits);

    if(cmp0_bignum(s0) != BIGNUM_CMP_ZO)
    {
        ReturnType _fr_ = E_OK;

        bignum_s* _es0_;
        bignum_s* _es1_;
        bignum_s* _acc_;

        size_t _es1_lsbl_;

        _es0_ = mkBigNum(d->bits);
        _es1_ = mkBigNum(d->bits);
        _acc_ = mkBigNum(d->bits);

        _fr_ = cpy_bignum_safe(_es0_, s0, ign_sign);
        if(_fr_ != E_OK) { /* has error */ _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };

        _fr_ = cpy_bignum_safe(_es1_, s1, ign_sign);
        if(_fr_ != E_OK) { /* has error */ _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };

        _fr_ = clr_bignum(_acc_);
        if(_fr_ != E_OK) { /* has error */ _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };

        _es1_lsbl_ = find_bignum_LSBL(s1);

        _PRINT_BIGNUM_(_es0_, "[init] _es0_");
        _DPRINTF_("[init] _es1_lsbl_ = %ld\r\n", _es1_lsbl_);
        if(lslb_bignum_self(_es0_, _es1_lsbl_) != E_OK) { /* has error */ _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
        _PRINT_BIGNUM_(_es0_, "[init] _es0_<<_es1_lsbl_");

        while(_es1_->bits > _es1_lsbl_)
        {
            _DPRINTF_("_es1_lsbl_ = %lu\n", _es1_lsbl_);
            _PRINT_BIGNUM_(_es0_, "_es0_");
            bignum_t _bits_ = chk1b_bignum(_es1_, _es1_lsbl_);
            if(_bits_ != SIZE_MAX)
            {
                size_t _lsbl_, _asll_;

                if(_bits_ != 0U)
                {
                    _fr_ = add_bignum_unsafe(_acc_, _acc_, _es0_, ign_sign);
                    _PRINT_BIGNUM_(_acc_, "_acc_ += _es0_");
                    if(_fr_ != E_OK) { /* has error */ _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_); break; };
                }

                _lsbl_ = find_bignum_LSBL_bitLoc(_es1_, _es1_lsbl_+1UL);
                _asll_ = (_lsbl_ - _es1_lsbl_ );
                _DPRINTF_("_lsbl_ = %lu\n", _lsbl_);
                _DPRINTF_("_asll_ = %lu\n", _asll_);

                if(_lsbl_ != SIZE_MAX)
                {
                    if(_lsbl_ >= _es1_lsbl_)
                    {
                        _fr_ = lslb_bignum_self(_es0_ , _asll_);
                        if(_fr_ != E_OK) { /* has error */ _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_); break; };
                        _es1_lsbl_ = _lsbl_;
                    }
                    else
                    {
                        /* It could be unreacherable? */
                        _fr_ = E_ERROR_RUNTIME;
                        break;
                    }
                }
                else
                {
                    /* not found bit location, is end */
                    break;
                }
            }
            else
            {
                /* has error */
                _fr_ = E_ERROR_RUNTIME;
                _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_);
                break;
            }
        }

        if(_fr_ == E_OK)
        {
            /* _quot_ is quotient */
            _fr_ = cpy_bignum_unsigned_safe(d, _acc_);
            if(_fr_ != E_OK) { /* has error */ _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
        }

        if(rmBigNum(&_es0_) != 0)  { /* Memory leakage? */ };
        if(rmBigNum(&_es1_) != 0)  { /* Memory leakage? */ };
        if(rmBigNum(&_acc_) != 0)  { /* Memory leakage? */ };
    }
    else
    {
        /* s0 is zero */
        return clr_bignum(d);
    }

    return E_OK;
}
/* Divide with Modulo: 'n'umerator = 'q'uotient * 'd'enominator + 'r'emainder */
/* Divide with Modulo: ('n'umerator - 'r'emainder) / 'd'enominator = 'q'uotient  */
//__FUNC_RETURN_WRAPPING__(fr, mod_bignum_unsafe(pow_x, t_mul, p));
#if 0 /* div_bignum_with_mod_nbs_ext */
#include <stdio.h>
#include "test/test_tool.h"
#   ifndef ENABLE_BIGNUM_LOG
#      ifdef _DPRINTF_
#          undef _DPRINTF_
#          define _DPRINTF_                   printf
#      endif
#      ifdef _PRINT_BIGNUM_
#          undef _PRINT_BIGNUM_
#          define _PRINT_BIGNUM_(p, title)    test_print_bignum(p, title)
#      endif
#   endif /*ENABLE_BIGNUM_LOG*/
#endif/* div_bignum_with_mod_nbs_ext */
ReturnType div_bignum_with_mod_nbs_ext(bignum_s* q, bignum_s* r, const bignum_s* n, const bignum_s* d, const bool ign_len) {
    _DPRINTF_(">>%s:%d\r\n", __func__, __LINE__);
    if(!((n != NULL) && (d != NULL))) {
        _DPRINTF_("[ERROR]@%s:%d, n: 0x%p, d: 0x%p\n", __func__, __LINE__, n, d);
        _DPRINTF_("<<%s:%d\r\n", __func__, __LINE__);
        return E_ERROR_NULL;
    }
    /* output was selecable, all output are NULL check */
    if(!((q != NULL) || (r != NULL))) {
        _DPRINTF_("<<%s:%d\r\n", __func__, __LINE__);
        _DPRINTF_("[ERROR]@%s:%d, q: 0x%p, r: 0x%p\n", __func__, __LINE__, q, r);
        return E_ERROR_NULL;
    }
    if(!(n->bits) >= (d->bits)) {
        _DPRINTF_("[ERROR]@%s:%d, n->bits: 0x%lu, d->bits: 0x%lu\n", __func__, __LINE__, n->bits, d->bits);
        _DPRINTF_("<<%s:%d\r\n", __func__, __LINE__);
        return E_ERROR_BIGNUM_LENGTH;
    }
    if(q != NULL) {
        /* worst case: if 'd' is d1, 'q'uotient has same length with 'n'umerator */
        if(!((q->bits) >= (n->bits)) && (!ign_len)) {
            _DPRINTF_("[ERROR]@%s:%d, q->bits: 0x%lu, n->bits: 0x%lu\n", __func__, __LINE__, q->bits, n->bits);
            _DPRINTF_("<<%s:%d\r\n", __func__, __LINE__);
            return E_ERROR_BIGNUM_LENGTH;
        }
    }
    if(r != NULL) {
        /* worst case: if 'q'uotient become 0d0, 'r'emainder has same length with 'n'umerator */
        if(!((r->bits) >= (n->bits)) && (!ign_len)) {
            _DPRINTF_("[ERROR]@%s:%d, r->bits: 0x%lu, n->bits: 0x%lu\n", __func__, __LINE__, r->bits, n->bits);
            _DPRINTF_("<<%s:%d\r\n", __func__, __LINE__);
            return E_ERROR_BIGNUM_LENGTH;
        }
    }

    if(cmp0_bignum(d) != BIGNUM_CMP_ZO)
    {
        ReturnType _fr_ = E_OK;

        bignum_s* _temp_;
        bignum_s* _d_m2_;
        bignum_s* _quot_;
        bignum_cmp_e _cmp_;

        size_t _n_msbl_ = find_bignum_MSBL(n);
        size_t _d_msbl_ = find_bignum_MSBL(d);
        size_t _d_lsbl_ = SIZE_MAX; // default, not enter in while loops

        _temp_ = mkBigNum(n->bits);  // _temp_ is init to n
        _d_m2_ = mkBigNum(n->bits);  // _d_m2_ is multiple of d
        _quot_ = mkBigNum(n->bits);
        _fr_ = cpy_bignum_unsigned_safe(_temp_, n);
        if(_fr_ != E_OK) { /* has error */ _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
        _fr_ = cpy_bignum_unsigned_safe(_d_m2_, d);
        if(_fr_ != E_OK) { /* has error */ _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
        _fr_ = clr_bignum(_quot_);
        if(_fr_ != E_OK) { /* has error */ _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };

        _PRINT_BIGNUM_(n, "[in] n");
        _PRINT_BIGNUM_(d, "[in] d");

        _DPRINTF_("@%s:%d, _cmp_:%d\r\n", __func__, __LINE__, _cmp_);
        _d_lsbl_ = (_n_msbl_ - _d_msbl_);
        _d_msbl_ = _n_msbl_;
        _PRINT_BIGNUM_(_d_m2_, "_d_m2_");
        if(lslb_bignum_self(_d_m2_, _d_lsbl_) != E_OK) { /* has error */ _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
        _DPRINTF_("_d_lsbl_ = %lu\n", _d_lsbl_);
        _PRINT_BIGNUM_(_d_m2_, "_d_m2_<<_d_lsbl_");

        _DPRINTF_("[init] _n_msbl_ = %lu\n", _n_msbl_);
        _DPRINTF_("[init] _d_msbl_ = %lu\n", _d_msbl_);
        _DPRINTF_("[init] _d_lsbl_ = %lu\n", _d_lsbl_);

        _PRINT_BIGNUM_(_temp_, "[init] _temp_");
        _PRINT_BIGNUM_(_d_m2_, "[init] _d_m2_");

        while(_d_lsbl_ < (_quot_->bits))
        {
            _DPRINTF_("_n_msbl_ = %lu\n", _n_msbl_);
            _DPRINTF_("_d_msbl_ = %lu\n", _d_msbl_);
            _DPRINTF_("_d_lsbl_ = %lu\n", _d_lsbl_);
            _PRINT_BIGNUM_(_temp_, "_temp_");
            _PRINT_BIGNUM_(_d_m2_, "_d_m2_");
            _cmp_ = cmp_bignum_logical_unsigned_safe(_temp_, _d_m2_);
            _DPRINTF_("@%s:%d, _cmp_: %d\n", __func__, __LINE__, _cmp_);
            if((_cmp_ == BIGNUM_CMP_GT) || (_cmp_ == BIGNUM_CMP_EQ))
            {
                size_t _msbl_, _lsrl_;
                /* set bit q at lsb of d(N'th bit) */
                _fr_ = set1b_bignum(_quot_, _d_lsbl_);
                _PRINT_BIGNUM_(_quot_, "_quot_");
                if(_fr_ != E_OK) { /* has error */ _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_); break; };
                /* n = n - (d<<N) */
                _fr_ = sub_bignum_unsigned_unsafe(_temp_, _temp_, _d_m2_);
                _PRINT_BIGNUM_(_temp_, "_temp_ -= _d_m2_");
                if(_fr_ != E_OK) { /* has error */ _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_); break; };

                _msbl_ = find_bignum_MSBL(_temp_);
                _lsrl_ = (_d_msbl_ - _msbl_);
                _DPRINTF_("_msbl_ = %lu\n", _msbl_);
                _DPRINTF_("_lsrl_ = %lu\n", _lsrl_);

                if(_msbl_ != SIZE_MAX)
                {
                    /* found next bit loction */
                    if(_d_lsbl_ >= _lsrl_)
                    {
                        _fr_ = lsrb_bignum_self(_d_m2_, _lsrl_);
                        if(_fr_ != E_OK) { /* has error */ _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_); break; };
                        _n_msbl_ = _msbl_;
                        _d_msbl_ -= _lsrl_;
                        _d_lsbl_ -= _lsrl_;
                    }
                    else
                    {
                        /* logical shift right(lsr) of d is end, has remainder */
                        _DPRINTF_("logical shift right(lsr) of d is end, has remainder, %s:%d, _fr_: %d\n", __func__, __LINE__, _fr_);
                        break;
                    }
                }
                else
                {
                    /* not found bit location, is end */
                    break;
                }
            }
            else if(_cmp_ == BIGNUM_CMP_LT)
            {
                _fr_ = lsr1b_bignum_self(_d_m2_, NULL, 0UL);
                if(_fr_ != E_OK) { /* has error */ _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_); break; };
                _d_msbl_--;
                _d_lsbl_--;
            }
            else
            {
                /* unreachable */
                _fr_ = E_ERROR_RUNTIME;
                _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_);
                break;
            }
        }

        if(_fr_ == E_OK)
        {
            /* _temp_ has remainder */
            if(r != NULL)   _fr_ = cpy_bignum_unsigned_unsafe(r, _temp_);
            /* _quot_ is quotient */
            if(q != NULL)   _fr_ = cpy_bignum_unsigned_unsafe(q, _quot_);
        }

        if(rmBigNum(&_temp_) != 0)  { /* Memory leakage? */ };
        if(rmBigNum(&_d_m2_) != 0)  { /* Memory leakage? */ };
        if(rmBigNum(&_quot_) != 0)  { /* Memory leakage? */ };

        _DPRINTF_("<<%s:%d\r\n", __func__, __LINE__);
        return _fr_;
    }
    else
    {
        /* NOT_FOUND_MSB: denominator is 0 */
        _DPRINTF_("<<%s:%d\r\n", __func__, __LINE__);
        return E_ERROR_DIVIDE_ZERO;
    };

    _DPRINTF_("<<%s:%d\r\n", __func__, __LINE__);
    return E_OK;
}
#if 0 /* div_bignum_with_mod_nbs_ext */
#   ifndef ENABLE_BIGNUM_LOG
#      ifdef _DPRINTF_
#          undef _DPRINTF_
#          define _DPRINTF_
#      endif
#      ifdef _PRINT_BIGNUM_
#          undef _PRINT_BIGNUM_
#          define _PRINT_BIGNUM_
#      endif
#   endif/* ENABLE_BIGNUM_LOG */
#endif/* div_bignum_with_mod_nbs_ext */

#if 0 /* aim_bignum_ext */
#   ifndef ENABLE_BIGNUM_LOG
#      ifdef _DPRINTF_
#          undef _DPRINTF_
#          define _DPRINTF_                   printf
#      endif
#      ifdef _PRINT_BIGNUM_
#          undef _PRINT_BIGNUM_
#          define _PRINT_BIGNUM_(p, title)    test_print_bignum(p, title)
#      endif
#   endif /*ENABLE_BIGNUM_LOG*/
#endif/* aim_bignum_ext */
ReturnType DIS_CARDED_aim_bignum_ext(bignum_s* x, const bignum_s* n, const bignum_s* p, const bool ign_len, const bool ign_sign)
{
    _DPRINTF_("@%s:%d, ign_len:%u, ign_sign:%u\n", __func__, __LINE__, ign_len, ign_sign);
    _PRINT_BIGNUM_(x, "x");
    _PRINT_BIGNUM_(n, "n");
    _PRINT_BIGNUM_(p, "p");

    if(!((x != NULL) && (n != NULL) && (p != NULL)))                            return E_ERROR_NULL;
    if(!(((n->bits) == (p->bits)) && ((x->bits) == (p->bits))) && (!ign_len))   return E_ERROR_BIGNUM_LENGTH;

    bool errFlags;
    bignum_sign_e signOf_n = BIGNUM_SIGN_NU;
    bignum_cmp_e cmp_n_with_p = BIGNUM_CMP_NU;
    bignum_s* abs_n = mkBigNum(n->bits);

    cpy_bignum_abs_safe_ext(abs_n, n, ign_sign);
    cmp_n_with_p = cmp_bignum_logical_unsafe_ext(abs_n, p, ign_sign);
    signOf_n = sign_bignum_ext(n, ign_sign);

    _PRINT_BIGNUM_(abs_n, "abs_n");
    _DPRINTF_("@%s:%d, cmp_n_with_p:%d\n", __func__, __LINE__, cmp_n_with_p);
    _DPRINTF_("@%s:%d, signOf_n:%d\n", __func__, __LINE__, signOf_n);
    if(signOf_n  == BIGNUM_SIGN_POS) {
        if((cmp_n_with_p == BIGNUM_CMP_GT) || (cmp_n_with_p == BIGNUM_CMP_EQ)) {
            _DPRINTF_("@%s:%d, call:sub_bignum_signed_unsafe()\n", __func__, __LINE__); sub_bignum_signed_unsafe(x, abs_n, p);
        } else {
            _DPRINTF_("@%s:%d, call:cpy_bignum_signed_safe()\n", __func__, __LINE__); cpy_bignum_signed_safe(x, abs_n);
        }
    } else if(signOf_n  == BIGNUM_SIGN_NEG) {
        if((cmp_n_with_p == BIGNUM_CMP_GT) || (cmp_n_with_p == BIGNUM_CMP_EQ)) {
            _DPRINTF_("@%s:%d, call:add_bignum_signed_unsafe()\n", __func__, __LINE__); add_bignum_signed_unsafe(x, n, p);
            _DPRINTF_("@%s:%d, call:add_bignum_signed_unsafe()\n", __func__, __LINE__); add_bignum_signed_unsafe(x, n, p);
        } else {
            _DPRINTF_("@%s:%d, call:add_bignum_signed_unsafe()\n", __func__, __LINE__); add_bignum_signed_unsafe(x, n, p);
        }
    } else {
        _DPRINTF_("[ERROR] %s:%d, signOf_n:%d\n", __func__, __LINE__, signOf_n);
        rmBigNum(&abs_n);
        return E_ERROR_RUNTIME;
    }

    rmBigNum(&abs_n);

    return E_OK;
}
ReturnType aim_bignum_ext(bignum_s* x, const bignum_s* n, const bignum_s* p, const bool ign_len, const bool ign_sign)
{
    _DPRINTF_("@%s:%d, ign_len:%u, ign_sign:%u\n", __func__, __LINE__, ign_len, ign_sign);
    _PRINT_BIGNUM_(x, "x");
    _PRINT_BIGNUM_(n, "n");
    _PRINT_BIGNUM_(p, "p");

    if(!((x != NULL) && (n != NULL) && (p != NULL)))                            return E_ERROR_NULL;
    if(!(((n->bits) == (p->bits)) && ((x->bits) == (p->bits))) && (!ign_len))   return E_ERROR_BIGNUM_LENGTH;

    bool errFlags;
    bignum_sign_e signOf_n = BIGNUM_SIGN_NU;
    bignum_sign_e signOf_p = BIGNUM_SIGN_NU;
    bignum_sign_e signOf_signed_t = BIGNUM_SIGN_NU;

    bignum_s* signed_t = NULL;

    // find largest bits
    {
        size_t longestBits = 0UL;
        if(longestBits < x->bits)   longestBits = x->bits;
        if(longestBits < n->bits)   longestBits = n->bits;
        if(longestBits < p->bits)   longestBits = p->bits;

        signed_t = mkBigNum(longestBits + 1UL);
    }

    signOf_n = sign_bignum_ext(n, ign_sign);
    signOf_p = sign_bignum_ext(p, ign_sign);
    _DPRINTF_("@%s:%d, signOf_n:%d, signOf_p:%d\n", __func__, __LINE__, signOf_n, signOf_p);
    if(!((signOf_n == BIGNUM_SIGN_POS) || (signOf_n == BIGNUM_SIGN_NEG)))
    {
        _DPRINTF_("[ERROR]%s:%d, E_ERROR_BIGNUM_SIGNBIT\r\n", __func__, __LINE__);
        rmBigNum(&signed_t);
        return E_ERROR_BIGNUM_SIGNBIT;
    }
    if(!((signOf_p == BIGNUM_SIGN_POS) || (signOf_p == BIGNUM_SIGN_NEG)))
    {
        _DPRINTF_("[ERROR]%s:%d, E_ERROR_BIGNUM_SIGNBIT\r\n", __func__, __LINE__);
        rmBigNum(&signed_t);
        return E_ERROR_BIGNUM_SIGNBIT;
    }

    // extends bits by belows...
    if(signOf_n == signOf_p) // both are positive or negative
    {
        _DPRINTF_("@%s:%d, signed_t = n - p\r\n", __func__, __LINE__);
        sub_bignum_unsafe(signed_t, n, p, ign_sign);
    }
    else // one is positive and other is negative
    {
        _DPRINTF_("@%s:%d, signed_t = n + p\r\n", __func__, __LINE__);
        add_bignum_unsafe(signed_t, n, p, ign_sign);
    }

    signOf_signed_t = sign_bignum_signed(signed_t);
    _DPRINTF_("@%s:%d, signOf_signed_t:%d\n", __func__, __LINE__, signOf_signed_t);
    if(!((signOf_signed_t == BIGNUM_SIGN_POS) || (signOf_signed_t == BIGNUM_SIGN_NEG)))
    {
        _DPRINTF_("[ERROR]%s:%d, E_ERROR_BIGNUM_SIGNBIT\r\n", __func__, __LINE__);
        rmBigNum(&signed_t);
        return E_ERROR_BIGNUM_SIGNBIT;
    }
    if(signOf_signed_t != BIGNUM_SIGN_POS)
    {
        _DPRINTF_("@%s:%d, signed_t += p\r\n", __func__, __LINE__);
        add_bignum_unsigned_unsafe(signed_t, signed_t, p);
    }
    else
    {
        /* DO_NOTHING */
    }
    cpy_bignum_unsigned_unsafe(x, signed_t);

    rmBigNum(&signed_t);

    return E_OK;
}
#if 0 /* aim_bignum_ext */
#   ifndef ENABLE_BIGNUM_LOG
#      ifdef _DPRINTF_
#          undef _DPRINTF_
#          define _DPRINTF_
#      endif
#      ifdef _PRINT_BIGNUM_
#          undef _PRINT_BIGNUM_
#          define _PRINT_BIGNUM_
#      endif
#   endif/* ENABLE_BIGNUM_LOG */
#endif/* aim_bignum_ext */

/* 
 * Note. This function implements to application for getting multiplicative inverse(reciprocal)
 *
 * link: https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
 * Title : Extended Euclidean algorithm, WIKIPEDIA
 * Chapter. Polynomial extended Euclidean algorithm: as + bt = gcd(a,b)
 * Chapter. Pseudocode(Not Optimized)
 */
/* r: gcd, s and t: coefficient(optional), a and b: number */
/* 
 * Value Example: https://ko.wikipedia.org/wiki/%EC%9C%A0%ED%81%B4%EB%A6%AC%EB%93%9C_%ED%98%B8%EC%A0%9C%EB%B2%95
 *            GLUE     SEQ     SEQ     SEQ     SEQ    GLUE      GLUE     SEQ     SEQ    GLUE      GLUE
 * | index |     q | old r |     r | old s |     s |    qs | olds-qs | old t |     t |    qt | oldt-qt |
 * |  init |     - | 78696 | 19332 |     1 |     0 |     0 |       1 |     0 |     1 |     4 |      -4 |
 * |     0 |     4 | 19332 |  1368 |     0 |     1 |    14 |     -14 |     1 |    -4 |    -5 |      57 |
 * |     1 |    14 |  1368 |   180 |     1 |   -14 |   -98 |      99 |    -4 |    57 |   399 |    -403 |
 * |     2 |     7 |   180 |   108 |   -14 |    99 |    99 |    -113 |    57 |  -403 |  -403 |     460 |
 * |     3 |     1 |   108 |    72 |    99 |  -113 |  -113 |     212 |  -403 |   460 |   460 |    -863 |
 * |     4 |     1 |    72 |    36 |  -113 |   212 |   424 |    -537 |   460 |  -863 | -1726 |    2186 |
 * |     5 |     2 |    36 |     0 |   212 |  -537 |     0 |     212 |  -863 |  2186 |     0 |    -863 |
 * a       :     78696
 * s(old_s):       212
 * b       :     19332
 * t(old_t):      -863
 * as      :  16683552
 *      bt : -16683516
 * as + bt :        36
 */
ReturnType gcd_bignum_ext(bignum_s* r, bignum_s* s, bignum_s* t, const bignum_s* a, const bignum_s* b, const bool ign_len) {
    if(!((r != NULL) && (a != NULL) && (b != NULL))) {
        return E_ERROR_NULL;
    }
    if(!(((a->bits) == (b->bits)) && ((a->bits) == (r->bits))) && (!ign_len)) {
        return E_ERROR_BIGNUM_LENGTH;
    }

    ReturnType _fr_;

    bignum_s* _tmp_ = mkBigNum(r->bits); /* temp */
    bignum_s* _quo_ = mkBigNum(r->bits); /* quotient */
    bignum_s* _o_r_ = mkBigNum(r->bits); /* p: previous(old) */
    bignum_s* ___r_ = mkBigNum(r->bits); /* c: current */
    bignum_s* _o_s_ = mkBigNum(r->bits); /* p: previous(old) */
    bignum_s* ___s_ = mkBigNum(r->bits); /* c: current */
    bignum_s* _o_t_ = mkBigNum(r->bits); /* p: previous(old) */
    bignum_s* ___t_ = mkBigNum(r->bits); /* c: current */

    // (old_r, r) := (a, b)
    if(cpy_bignum_signed_safe(_o_r_, a) != E_OK) { /* has error */ _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
    if(cpy_bignum_signed_safe(___r_, b) != E_OK) { /* has error */ _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
    // (old_s, s) := (1, 0)
    if(clr_bignum(_o_s_) != E_OK)         { /* has error */ _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
    if(set1b_bignum(_o_s_, 0UL) != E_OK)  { /* has error */ _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
    if(clr_bignum(___s_) != E_OK)         { /* has error */ _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
    // (old_t, t) := (0, 1)
    if(clr_bignum(_o_t_) != E_OK)         { /* has error */ _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
    if(clr_bignum(___t_) != E_OK)         { /* has error */ _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
    if(set1b_bignum(___t_, 0UL) != E_OK)  { /* has error */ _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };

    _PRINT_BIGNUM_(_o_r_, "[init] _o_r_");
    _PRINT_BIGNUM_(___r_, "[init] ___r_");
    _PRINT_BIGNUM_(_o_s_, "[init] _o_s_");
    _PRINT_BIGNUM_(___s_, "[init] ___s_");
    _PRINT_BIGNUM_(_o_t_, "[init] _o_t_");
    _PRINT_BIGNUM_(___t_, "[init] ___t_");
    while(cmp0_bignum(___r_) != BIGNUM_CMP_ZO)
    {
        _FUNC_WRAP_(_fr_, cpy_bignum_signed_safe(_tmp_, ___r_));

        // quotient := old_r div r
        _FUNC_WRAP_(_fr_, div_bignum_with_mod(_quo_, ___r_, _o_r_, ___r_));
        _FUNC_WRAP_(_fr_, cpy_bignum_signed_safe(_o_r_, _tmp_));
        // (old_r, r) := (r, old_r − quotient × r)
        // note: 'old_r − quotient × r' is maen that remainder
        _PRINT_BIGNUM_(_quo_, "_quo_");
        _PRINT_BIGNUM_(_o_r_, "_o_r_");
        _PRINT_BIGNUM_(___r_, "___r_");

        // (old_s, s) := (s, old_s − quotient × s)
        _FUNC_WRAP_(_fr_, cpy_bignum_signed_safe(_tmp_, ___s_));
        _FUNC_WRAP_(_fr_, mul_bignum_signed_unsafe(_tmp_, _quo_, _tmp_));
        _FUNC_WRAP_(_fr_, sub_bignum_signed_unsafe(_tmp_, _o_s_, _tmp_));
        _FUNC_WRAP_(_fr_, cpy_bignum_signed_safe(_o_s_, ___s_));
        _FUNC_WRAP_(_fr_, cpy_bignum_signed_safe(___s_, _tmp_));
        _PRINT_BIGNUM_(_o_s_, "_o_s_");
        _PRINT_BIGNUM_(___s_, "___s_");

        // (old_t, t) := (t, old_t − quotient × t)
        _FUNC_WRAP_(_fr_, cpy_bignum_signed_safe(_tmp_, ___t_));
        _FUNC_WRAP_(_fr_, mul_bignum_signed_unsafe(_tmp_, _quo_, _tmp_));
        _FUNC_WRAP_(_fr_, sub_bignum_signed_unsafe(_tmp_, _o_t_, _tmp_));
        _FUNC_WRAP_(_fr_, cpy_bignum_signed_safe(_o_t_, ___t_));
        _FUNC_WRAP_(_fr_, cpy_bignum_signed_safe(___t_, _tmp_));
        _PRINT_BIGNUM_(_o_t_, "_o_t_");
        _PRINT_BIGNUM_(___t_, "___t_");
    }

    if(s != NULL) {
        if(cpy_bignum_signed_safe(s, _o_s_) != E_OK) { /* has error */ _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
    }
    if(t != NULL) {
        if(cpy_bignum_signed_safe(t, _o_t_) != E_OK) { /* has error */ _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
    }
    _PRINT_BIGNUM_(_o_s_, "Bézout coefficients: s");
    _PRINT_BIGNUM_(_o_t_, "Bézout coefficients: t");

    if(cpy_bignum_signed_safe(r, _o_r_) != E_OK) { /* has error */ _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
    _PRINT_BIGNUM_(_o_r_, "greatest common divisor");

    if(rmBigNum(&_tmp_) != 0)  { /* Memory leakage? */ };
    if(rmBigNum(&_quo_) != 0)  { /* Memory leakage? */ };
    if(rmBigNum(&_o_r_) != 0)  { /* Memory leakage? */ };
    if(rmBigNum(&___r_) != 0)  { /* Memory leakage? */ };
    if(rmBigNum(&_o_s_) != 0)  { /* Memory leakage? */ };
    if(rmBigNum(&___s_) != 0)  { /* Memory leakage? */ };
    if(rmBigNum(&_o_t_) != 0)  { /* Memory leakage? */ };
    if(rmBigNum(&___t_) != 0)  { /* Memory leakage? */ };

    return E_OK;
}

ReturnType mim_bignum_ext(bignum_s* t, bignum_s* r, const bignum_s* a, const bignum_s* n, const bool ign_sign) {
    if(!((t != NULL) && (a != NULL) && (n != NULL))) {
        return E_ERROR_NULL;
    }
    if(!(((a->bits) == (n->bits)) && ((a->bits) == (t->bits))) && (!ign_sign)) {
        return E_ERROR_BIGNUM_LENGTH;
    }

    bool has_value;
    ReturnType _fr_;
    bignum_sign_e _sign_of_o_t_;
    bignum_sign_e _sign_of_o_r_;
    bignum_cmp_e _o_r_is_0_;
    bignum_cmp_e _o_r_is_1_;
    bignum_s* _tmp_ = mkBigNum(t->bits); /* temp */
    bignum_s* _quo_ = mkBigNum(t->bits); /* quotient */
    bignum_s* _o_r_ = mkBigNum(t->bits); /* p: previous(old) */
    bignum_s* _n_r_ = mkBigNum(t->bits); /* c: current */
    bignum_s* _o_t_ = mkBigNum(t->bits); /* p: previous(old) */
    bignum_s* _n_t_ = mkBigNum(t->bits); /* c: current */

    // r := n;     newr := a
    _FUNC_WRAP_(_fr_, cpy_bignum_signed_safe(_o_r_, n));
    _FUNC_WRAP_(_fr_, cpy_bignum_signed_safe(_n_r_, a));
    // t := 0;     newt := 1
    if(clr_bignum(_o_t_) != E_OK)         { /* has error */ _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
    if(clr_bignum(_n_t_) != E_OK)         { /* has error */ _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
    if(set1b_bignum(_n_t_, 0UL) != E_OK)  { /* has error */ _DPRINTF_("@%s:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };

    _PRINT_BIGNUM_(_o_r_, "[init] _o_r_");
    _PRINT_BIGNUM_(_n_r_, "[init] _n_r_");
    _PRINT_BIGNUM_(_o_t_, "[init] _o_t_");
    _PRINT_BIGNUM_(_n_t_, "[init] _n_t_");
    while(cmp0_bignum(_n_r_) != BIGNUM_CMP_ZO)
    {
        _FUNC_WRAP_(_fr_, cpy_bignum_signed_safe(_tmp_, _n_r_));

        // quotient := r div newr
        _FUNC_WRAP_(_fr_, div_bignum_with_mod(_quo_, _n_r_, _o_r_, _n_r_));
        _FUNC_WRAP_(_fr_, cpy_bignum_signed_safe(_o_r_, _tmp_));
        // (r, newr) := (newr, r − quotient × newr)
        // note: 'old_r − quotient × r' is maen that remainder
        _PRINT_BIGNUM_(_quo_, "_quo_");
        _PRINT_BIGNUM_(_o_r_, "_o_r_");
        _PRINT_BIGNUM_(_n_r_, "_n_r_");

        // (t, newt) := (newt, t − quotient × newt)
        _FUNC_WRAP_(_fr_, cpy_bignum_signed_safe(_tmp_, _n_t_));
        _FUNC_WRAP_(_fr_, mul_bignum_signed_unsafe(_tmp_, _quo_, _tmp_));
        _FUNC_WRAP_(_fr_, sub_bignum_signed_unsafe(_tmp_, _o_t_, _tmp_));
        _FUNC_WRAP_(_fr_, cpy_bignum_signed_safe(_o_t_, _n_t_));
        _FUNC_WRAP_(_fr_, cpy_bignum_signed_safe(_n_t_, _tmp_));
        _PRINT_BIGNUM_(_o_t_, "_o_t_");
        _PRINT_BIGNUM_(_n_t_, "_n_t_");
    }

    _o_r_is_0_ = cmp0_bignum(_o_r_);
    _o_r_is_1_ = cmp1_bignum(_o_r_);
    _sign_of_o_t_ = sign_bignum_signed(_o_r_);
#if 0 /* OLD_R_IS_UNSIGNED_NUMBER_BECAUSE_REMAINDER_CAN_NOT_BE_NEGATIVE_VALUES */
    if(((_o_r_is_0_ == BIGNUM_CMP_ZO) || (_o_r_is_1_ == BIGNUM_CMP_ON)) || (_sign_of_o_t_ == BIGNUM_SIGN_NEG))
#else
    // _o_r_ is remainder, positive value
    if((_o_r_is_0_ == BIGNUM_CMP_ZO) || (_o_r_is_1_ == BIGNUM_CMP_ON))
#endif/* OLD_R_IS_UNSIGNED_NUMBER_BECAUSE_REMAINDER_CAN_NOT_BE_NEGATIVE_VALUES */
    {
        // if t < 0 then
        //     t := t + n
        _PRINT_BIGNUM_(_o_t_, "Bézout coefficients: t");
        _sign_of_o_t_ = sign_bignum_signed(_o_t_);
        if(_sign_of_o_t_ == BIGNUM_SIGN_NEG)
        {
            /*  added with n */
            _DPRINTF_("add_bignum_signed_unsafe(t, _o_t_, n)\r\n");
            _FUNC_WRAP_(_fr_, add_bignum_signed_unsafe(t, _o_t_, n));
        }
        else if(_sign_of_o_t_ == BIGNUM_SIGN_POS)
        {
            _DPRINTF_("cpy_bignum_signed_safe(t, _o_t_)\r\n");
            _FUNC_WRAP_(_fr_, cpy_bignum_signed_safe(t, _o_t_));
        }
        else
        {
            /* has error */ _DPRINTF_("@%s:%d, _sign_of_o_t_: %d\n", __func__, __LINE__, _sign_of_o_t_);
        }
        has_value = true;
    }
    else
    {
        _DPRINTF_("clr_bignum(t)\r\n");
        _FUNC_WRAP_(_fr_, clr_bignum(t));
        has_value = false;
    }

    if(r != NULL)   _FUNC_WRAP_(_fr_, cpy_bignum_signed_safe(r, _o_r_));

    if(rmBigNum(&_tmp_) != 0)  { /* Memory leakage? */ };
    if(rmBigNum(&_quo_) != 0)  { /* Memory leakage? */ };
    if(rmBigNum(&_o_r_) != 0)  { /* Memory leakage? */ };
    if(rmBigNum(&_n_r_) != 0)  { /* Memory leakage? */ };
    if(rmBigNum(&_o_t_) != 0)  { /* Memory leakage? */ };
    if(rmBigNum(&_n_t_) != 0)  { /* Memory leakage? */ };

    if(!has_value)  return E_HAS_NO_VALUE;
    else            return E_OK;
}
#undef _DPRINTF_

