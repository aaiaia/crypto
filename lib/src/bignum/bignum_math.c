#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "bignum/bignum_math.h"
#include "bignum/bignum_logic.h"

ReturnType cpy_bignum_math(bignum_s* d, const bignum_s* s) {
    if((d != NULL) && (s != NULL)) {
        if((d->nums != NULL) && (s->nums != NULL)) {
            bignum_t signBit;
            if(s->nums[s->nlen-1U]&BIGNUM_MSB_MASK) signBit = BIGNUM_MAX;
            else                                    signBit = 0U;

            if(d->nlen >= s->nlen) {
                for(size_t i = s->nlen; i < d->nlen; i++)
                {
                    d->nums[i] = signBit;
                }
                for(size_t i = 0; i < s->nlen; i++)
                {
                    d->nums[i] = s->nums[i];
                }
            } else {
                for(size_t i = s->nlen - 1U; i >= d->nlen; i--)
                {
                    if(s->nums[i] != signBit)   return E_ERROR_ARGS;
                }
                for(size_t i = d->nlen - 1U; i < SIZE_MAX; i--)
                {
                    d->nums[i] = s->nums[i];
                }
            }
        } else {
            return E_ERROR_NULL;
        }
    } else {
        return E_ERROR_NULL;
    }

    return E_OK;
}

ReturnType twos_bignum(bignum_s* d, const bignum_s* s)
{
    ReturnType ret = E_NOT_OK;
    ret = cpy_bignum_math(d, s);
    if(ret != E_OK) return ret;

    ret = inv_bignum(d);
    if(ret != E_OK) return ret;

    (void)add_bignum_loc(d, 1UL, 0UL);

    ret = E_OK;

    return ret;
}

ReturnType abs_bignum(bignum_s* d, const bignum_s* s)
{
    if((d == NULL) || (s == NULL))  return E_ERROR_NULL;

    if(s->nums[s->nlen-1Ul]&BIGNUM_MSB_MASK) // negative
    {
        return twos_bignum(d, s);
    }
    else
    {
        return cpy_bignum_math(d, s);
    }
}

bignum_sign_e sign_bignum(const bignum_s* s)
{
    if(!(s != NULL))                            return BIGNUM_SIGN_ERR;
    if(!(s->nlen != 0UL))                       return BIGNUM_SIGN_ERR;
    if(!(s->nums != NULL))                      return BIGNUM_SIGN_ERR;

    if(!(s->type != BIGNUM_TYPE_UNSIGNED))      return BIGNUM_SIGN_POS;
    if(!(s->nums[s->nlen-1U]&BIGNUM_MSB_MASK))  return BIGNUM_SIGN_POS;
    else                                        return BIGNUM_SIGN_NEG;
}

bignum_sign_e NOT_IMPLEMENT_signbit_bignum(const bignum_s* s, const size_t bits, const bignum_sign_e sign)
{
#if 0 /* NOW_WORKING... */
    const size_t swidx = BIGNUM_BITS_LEN(msbl);
    const size_t sbloc = BIGNUM_BITS_REM(msbl)
    const bignum_t bmsk = 
#endif/* NOW_WORKING... */
}

bignum_cmp_e cmp0_bignum(const bignum_s* s) {
    if(s != NULL)
    {
        for(size_t i = 0UL; i < s->nlen; i++)
        {
            if(s->nums[i] != 0U)    return BIGNUM_CMP_NZ;
        }
        return BIGNUM_CMP_ZO;
    }
    return BIGNUM_CMP_ER;
}
/* +1: s0  > s1
 *  0: s0 == s1
 * -1: s0  < s1
 */
bignum_cmp_e NOT_IMPLEMENT_cmp_bignum_with_sub(const bignum_s* s0, const bignum_s* s1) {
    bignum_cmp_e cmp = BIGNUM_CMP_ER;
    bignum_s* tmp;    // 2's compliment...?...
                        //
    if(s0->bits > s1->bits) tmp = mkBigNum(s0->bits);
    else                    tmp = mkBigNum(s1->bits);

    if(sub_bignum(NULL, tmp, s0, s1, 0U) == E_OK)
    {
        bignum_sign_e zero = cmp0_bignum(tmp);
        bignum_sign_e sign = sign_bignum(tmp);

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

    rmBitNum(&tmp);

    return cmp;
}

bignum_cmp_e cmp_bignum_logical(const bignum_s* s0, const bignum_s* s1) {
    bignum_sign_e sig_s0 = sign_bignum(s0);
    bignum_sign_e sig_s1 = sign_bignum(s1);

    /* sign_bignum() is checking invalid case of input arguments 's0' and 's1' */
    if((sig_s0 == BIGNUM_SIGN_ERR) || (sig_s0 == BIGNUM_SIGN_ERR))
        return BIGNUM_CMP_ER;
    if((s0->nlen != s1->nlen) || (s0->bits != s1->bits))
        return BIGNUM_CMP_ER;

    // 1's compiment comparing
    //  b0000_0000_0001 (positive b0000_0000_0001)b1111_1111_1110+b1 -> (2's) b1111_1111_1111 => (1's) b0000_0000_0000
    //  b0000_0000_0010 (positive b0000_0000_0010)b1111_1111_1101+b1 -> (2's) b1111_1111_1110 => (1's) b0000_0000_0001
    //  b0111_1111_1110 (positive b0111_1111_1110)b1000_0000_0001+b1 -> (2's) b1000_0000_0010 => (1's) b0111_1111_1101
    //  b0111_1111_1111 (positive b0111_1111_1111)b1000_0000_0000+b1 -> (2's) b1000_0000_0001 => (1's) b0111_1111_1110
    if(sig_s0 == sig_s1) /* s0 and s1 has same significant bit */
    {
        for(size_t i = 0UL; i < s0->nlen; i++)
        {
            if(s0->nums[i] > s1->nums[i])   return BIGNUM_CMP_GT;
            if(s0->nums[i] < s1->nums[i])   return BIGNUM_CMP_LT;
        }
                                            return BIGNUM_CMP_EQ;
    }
    else if(sig_s0 == BIGNUM_SIGN_POS)      return BIGNUM_CMP_GT;
    else if(sig_s1 == BIGNUM_SIGN_POS)      return BIGNUM_CMP_LT;
    else                                    return BIGNUM_CMP_ER; /* Unreachable */
}

/* Return carry out, it can be only FALSE / TRUE, the others are error */
ReturnType add_bignum(bignum_t* co, bignum_s* d, const bignum_s* s0, const bignum_s* s1, const bignum_t ci) {
    if(!((d != NULL) && (s0 != NULL) && (s1 != NULL)))
        return E_ERROR_NULL;

    if(!((d->nlen >= s0->nlen) && (d->nlen >= s1->nlen)))
        return E_ERROR_ARGS;

    {
        bignum_t _c = ci;

        /* just Consider Condition(d->nlen == s1->nlen == s0->nlen) */
        const bignum_t _ms0_ = ((s0->nums[(s0->nlen-1U)]&BIGNUM_MSB_MASK)?BIGNUM_MAX:0U);  // _msN_: magnitude sN
        const bignum_t _ms1_ = ((s1->nums[(s1->nlen-1U)]&BIGNUM_MSB_MASK)?BIGNUM_MAX:0U);  // _msN_: magnitude sN
        for(size_t i=0ul; i<d->nlen; i++) {
            bignum_t _ts0_, _ss0_;   // _tsN_: temp sN, _ssN_: selecte sN
            bignum_t _ts1_, _ss1_;

            if(i < s0->nlen)    _ss0_ = s0->nums[i];
            else                _ss0_ = _ms0_;
            _ts0_ = _ss0_ + _c;
            _c = (_ts0_ < _ss0_);

            if(i < s1->nlen)    _ss1_ = s1->nums[i];
            else                _ss1_ = _ms1_;
            _ts1_ = _ts0_ + _ss1_;
            _c |= (_ts1_ < _ts0_);
            d->nums[i] = _ts1_;
        }

        if(co != NULL)  (*co) = _c;

    }
    return E_OK;
}

/* Return carry out, it can be only FALSE / TRUE, the others are error */
ReturnType sub_bignum(bignum_t* co, bignum_s* d, const bignum_s* s0, const bignum_s* s1, const bignum_t c) {
    if(!((d != NULL) && (s0 != NULL) && (s1 != NULL)))
        return E_ERROR_NULL;

    if(!((d->nlen >= s0->nlen) && (d->nlen >= s1->nlen)))
        return E_ERROR_ARGS;

    {
        bignum_t _c = c;

        const bignum_t _ms0_ = ((s0->nums[(s0->nlen-1U)]&BIGNUM_MSB_MASK)?BIGNUM_MAX:0U);  // _msN_: magnitude sN
        const bignum_t _ms1_ = ((s1->nums[(s1->nlen-1U)]&BIGNUM_MSB_MASK)?BIGNUM_MAX:0U);  // _msN_: magnitude sN
        for(size_t i=0UL; i<d->nlen; i++) {
            bignum_t _ts0_, _ss0_;
            bignum_t _ts1_, _ss1_;

            if(i < s0->nlen)    _ss0_ = s0->nums[i];
            else                _ss0_ = _ms0_;
            _ts0_ = _ss0_ - _c;
            _c = (_ts0_ > _ss0_);

            if(i < s1->nlen)    _ss1_ = s1->nums[i];
            else                _ss1_ = _ms1_;
            _ts1_ = _ts0_ - _ss1_;
            _c |= (_ts1_ > _ts0_);
            d->nums[i] = _ts1_;
        }

        if(co != NULL)  (*co) = _c;
    }
    return E_OK;
}

#define MACRO_MULTIPLIER_COMMON_OPEN(D, S1, S0, T) { \
    /* clear destination */ \
    (void)memset((D)->nums, 0x0U, (D)->size); \
    (T) = mkBigNum((D)->bits); \
    /* clear temp '(T)' */ \
    (void)memset(((T)->nums + (S0)->nlen), 0x0U, ((T)->size - (S0)->size)); \
    (void)memcpy((T)->nums, (S0)->nums, s0->size); \
}

#define MACRO_MULTIPLIER_COMMON_CLOSE(D, S1, S0, T) { \
    rmBitNum(&(T)); \
}
// idea notes.
// s0 accumulates then shift left
// s1 checks inclease nums index and shift likes bit witth
ReturnType mul_bignum_bs_ext(bignum_s* d, const bignum_s* s1, const bignum_s* s0, const bool guard) {
    if((d != NULL) && (s1 != NULL) && (s0 != NULL)) {
        if((d->nlen) >= (s1->nlen + s0->nlen) || (!guard)) {
            bignum_s* tmp;
            MACRO_MULTIPLIER_COMMON_OPEN(d, s1, s0, tmp);

#if 1   /* IMPL_BIT_SHIFT_MULTIPLIER */
            size_t nSftBit = s0->bits;
            for(size_t i = 0U; i < s1->nlen; i++) {
                size_t sftBit = (nSftBit >= BIGNUM_BITS)?(BIGNUM_BITS):(nSftBit);
                for(size_t sft = 0U; sft < sftBit; sft++) {
                    if(((s1->nums[i] >> sft) & 0x1U) != 0x0u) {
                        bignum_t co = BIGNUM_MAX;
                        if(add_bignum(&co, d, d, tmp, 0U) != E_OK)
                        {
                            return E_ERROR_RUNTIME;
                        }
                    } else { /* Do nothing */}
                    lsl1b_bignum(tmp, NULL, 0U);
                }
                nSftBit-=sftBit;
            }
#endif  /* IMPL_BIT_SHIFT_MULTIPLIER */
            MACRO_MULTIPLIER_COMMON_CLOSE(d, s1, s0, tmp);

#if 1   /* IMPL_BIT_SHIFT_MULTIPLIER */
            if(nSftBit != 0U) {
                return E_ERROR_RUNTIME;
            } else { /* Do nothing */ }
#endif  /* IMPL_BIT_SHIFT_MULTIPLIER */
        } else {
            return E_ERROR_ARGS;
        }
    } else {
        return E_ERROR_NULL;
    }
    return E_OK;
}

/* Divide with Modulo: 'n'umerator = 'q'uotient * 'd'enominator + 'r'emainder */
/* Divide with Modulo: ('n'umerator - 'r'emainder) / 'd'enominator = 'q'uotient  */
ReturnType div_bignum_with_mod_ext(bignum_t* q, bignum_t* r, const bignum_s* n, const bignum_s* d, const bool guard) {
    if((q != NULL) && (r != NULL) && (n != NULL) && (d != NULL)) {
        if(((n->nlen) >= (d->nlen)) || (!guard)) {
#if 0 /* NOW_WORKING... */
            bignum_s* _n, _d;

            size_t n_msbl = find_bignum_MSBL(n);
            size_t d_msbl = find_bignum_MSBL(d);

            if(d_msbl != SIZE_MAX)
            {

            }
            else
            {
                /* NOT_FOUND_MSB: denominator is 0 */
                return E_ERROR_DIVIDE_ZERO;
            };
#else
            return E_NOT_IMPL;
#endif/* NOW_WORKING... */
        } else {
            return E_ERROR_ARGS;
        }
    } else {
        return E_ERROR_NULL;
    }
    return E_OK;
}

bignum_t add_bignum_loc(bignum_s* d, const bignum_t v, const size_t idx) {
    bignum_t s;
    bignum_t c = v;
    for(size_t i = idx; i < d->nlen; i++) {
        s = d->nums[i] + c;
        c = (s < d->nums[i]);
        d->nums[i] = s;
        if(c != 0UL) {
            continue;
        }
        else {
            break;
        }
    }
    return c;
}
