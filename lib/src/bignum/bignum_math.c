#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "bignum/bignum_math.h"
#include "bignum/bignum_logic.h"

#ifdef ENABLE_BIGNUM_LOG
#include <stdio.h>
#define _DPRINTF_   printf

#define _PRINT_BITNUM_(p, title) _internal_print_bignum(p, title, __func__, __LINE__, 0UL, false)
void _internal_print_bignum(bignum_s* p, const char* title, const char* funcName, const int lineNum, const size_t lfn, const bool details)
{
    _DPRINTF_("[%s]\r\n", title);
    if(funcName != NULL)
    {
        _DPRINTF_("@%s():%d\r\n", funcName, lineNum);
    }
    if(details)
    {
        _DPRINTF_("addr:0x%p, bignum_t size:%lu\r\n", p, sizeof(bignum_t));
        _DPRINTF_("p->nums:0x%p, p->lmsk:0x%x\r\np->bits=%ld, p->nlen=%ld, p->size=%ld\r\n", \
                p->nums, p->lmsk, p->bits, p->nlen, p->size);
        _DPRINTF_("[HEX]\r\n");
    }
    for(size_t i = p->nlen- 1u; i != ((size_t)-1); i--) {
        _DPRINTF_("%08x", p->nums[i]);
        if(i != 0u)                 _DPRINTF_(" ");
        else if((i & (lfn-1U) == lfn) & (lfn != 0U))
                                    _DPRINTF_("\r\n");
        else                        _DPRINTF_("\r\n");
    }
}
#else
#define _DPRINTF_
#define _PRINT_BITNUM_(p, title)
#define _DEBUG_SELECTIVES_
#ifdef _DEBUG_SELECTIVES_
#include <stdio.h>
void _print_bignum_ext_(bignum_s* p, const char* title, const char* funcName, const int lineNum, const size_t lfn, const bool details)
{
    printf("[%s]\r\n", title);
    if(funcName != NULL)
    {
        printf("@%s():%d\r\n", funcName, lineNum);
    }
    if(details)
    {
        printf("addr:0x%p, bignum_t size:%lu\r\n", p, sizeof(bignum_t));
        printf("p->nums:0x%p, p->lmsk:0x%x\r\np->bits=%ld, p->nlen=%ld, p->size=%ld\r\n", \
                p->nums, p->lmsk, p->bits, p->nlen, p->size);
        printf("[HEX]\r\n");
    }
    for(size_t i = p->nlen- 1u; i != ((size_t)-1); i--) {
        printf("%08x", p->nums[i]);
        if(i != 0u)                 printf(" ");
        else if((i & (lfn-1U) == lfn) & (lfn != 0U))
                                    printf("\r\n");
        else                        printf("\r\n");
    }
}
#define _print_bignum_(p, title) _print_bignum_ext_(p, title, __func__, __LINE__, 0UL, false)
#else
#define _print_bignum_(p, title, funcName, lineNum)
#define _print_bignum_ext_(p, title, funcName, lineNum, lfn, details)
#endif /* _DEBUG_SELECTIVES_ */
#endif /* ENABLE_BIGNUM_LOG */

ReturnType cpy_bignum_math_ext(bignum_s* d, const bignum_s* s, const bool ignore_type) {
    if((d != NULL) && (s != NULL)) {
        if((d->nums != NULL) && (s->nums != NULL)) {
            bignum_t signBit;
            if(d->type == BIGNUM_TYPE_SIGNED) {
                if((d->type == s->type) || (ignore_type)) {
                    if(s->nums[s->nlen-1U]&BIGNUM_MSB_MASK) signBit = BIGNUM_MAX;
                    else                                    signBit = 0U;
                } else {
                    /* is not BIGNUM_TYPE_SIGNED */
                    return E_ERROR_BIGNUM_SIGN;
                }
            }
            else if(d->type == BIGNUM_TYPE_UNSIGNED) {
                if((d->type == s->type) || (ignore_type)) {
                    signBit = 0U;
                } else {
                    /*  is not BIGNUM_TYPE_UNSIGNED */
                    return E_ERROR_BIGNUM_SIGN;
                }
            }
            else {
                    return E_ERROR_BIGNUM_SIGN;
            }

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
                    if(s->nums[i] != signBit)   return E_ERROR_BIGNUM_LOSS;
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

    (void)add_bignum_carry_loc(d, 1UL, 0UL);

    ret = E_OK;

    return ret;
}

ReturnType abs_bignum(bignum_s* d, const bignum_s* s)
{
    if((d == NULL) || (s == NULL))  return E_ERROR_NULL;
    if((d->type != BIGNUM_TYPE_SIGNED) || (s->type != BIGNUM_TYPE_SIGNED))
                                    return E_ERROR_BIGNUM_SIGN;

    if(s->nums[s->nlen-1Ul]&BIGNUM_MSB_MASK) // negative
    {
        return twos_bignum(d, s);
    }
    else
    {
        return cpy_bignum_math(d, s);
    }
}

bignum_sign_e sign_bignum_ext(const bignum_s* s, const bool ignoreType)
{
    if(!(s != NULL))                            return BIGNUM_SIGN_ERR;
    if(!(s->nlen != 0UL))                       return BIGNUM_SIGN_ERR;
    if(!(s->nums != NULL))                      return BIGNUM_SIGN_ERR;

    if((!(s->type != BIGNUM_TYPE_UNSIGNED)) && (!ignoreType))
                                                return BIGNUM_SIGN_POS;
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

bignum_cmp_e cmp1_bignum(const bignum_s* s) {
    if(s != NULL)
    {
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
    return BIGNUM_CMP_ER;
}
/* +1: s0  > s1
 *  0: s0 == s1
 * -1: s0  < s1
 */
bignum_cmp_e cmp_bignum_with_sub_add_twos(const bignum_s* s0, const bignum_s* s1) {
    bignum_cmp_e cmp = BIGNUM_CMP_ER;
    bignum_s* tmp;    // 2's compliment...?...
                        //
    if(s0->bits > s1->bits) tmp = mkBigNum_ext(s0->bits, s0->type);
    else                    tmp = mkBigNum_ext(s1->bits, s1->type);

    if(sub_bignum_with_add_twos(NULL, tmp, s0, s1, 0U) == E_OK)
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

bignum_cmp_e cmp_bignum_logical_ext(const bignum_s* s0, const bignum_s* s1, const bool ignore_type) {
    bignum_sign_e sig_s0 = sign_bignum(s0);
    bignum_sign_e sig_s1 = sign_bignum(s1);

    /* sign_bignum() is checking invalid case of input arguments 's0' and 's1' */
    if(((sig_s0 == BIGNUM_SIGN_ERR) || (sig_s0 == BIGNUM_SIGN_ERR)) && (!ignore_type))
        return BIGNUM_CMP_ER;
    if((s0->nlen != s1->nlen) || (s0->bits != s1->bits))
        return BIGNUM_CMP_ER;

    // 1's compiment comparing
    //  b0000_0000_0001 (positive b0000_0000_0001)b1111_1111_1110+b1 -> (2's) b1111_1111_1111 => (1's) b0000_0000_0000
    //  b0000_0000_0010 (positive b0000_0000_0010)b1111_1111_1101+b1 -> (2's) b1111_1111_1110 => (1's) b0000_0000_0001
    //  b0111_1111_1110 (positive b0111_1111_1110)b1000_0000_0001+b1 -> (2's) b1000_0000_0010 => (1's) b0111_1111_1101
    //  b0111_1111_1111 (positive b0111_1111_1111)b1000_0000_0000+b1 -> (2's) b1000_0000_0001 => (1's) b0111_1111_1110
    if((sig_s0 == sig_s1) || (ignore_type)) /* s0 and s1 has same significant bit */
    {
        for(size_t i = (s0->nlen) - 1UL; i < SIZE_MAX; i--)
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

static inline bignum_t getMSB_fill(const bignum_s* s, const bool sub_signed_twos) {
    if(s->type == BIGNUM_TYPE_SIGNED) {
            if( ((s->nums[(s->nlen-1U)]))&BIGNUM_MSB_MASK) {
                if(!sub_signed_twos)    return BIGNUM_MAX;
                else                    return 0U;
            } else {
                if(!sub_signed_twos)    return 0U;
                else                    return BIGNUM_MAX;
            }
    } else {
                                        return 0U;
    }
}

/* Return carry out, it can be only FALSE / TRUE, the others are error */
ReturnType add_bignum(bignum_t* co, bignum_s* d, const bignum_s* s0, const bignum_s* s1, const bignum_t ci) {
    if(!((d != NULL) && (s0 != NULL) && (s1 != NULL)))
        return E_ERROR_NULL;

    if(!((d->nlen >= s0->nlen) && (d->nlen >= s1->nlen)))
        return E_ERROR_BIGNUM_LENGTH;

    {
        bignum_t _c = ci;

        /* just Consider Condition(d->nlen == s1->nlen == s0->nlen) */
        const bignum_t _bf0_ = getMSB_fill(s0, false);  // _bfN_: bit fill sN
        const bignum_t _bf1_ = getMSB_fill(s1, false);  // _bfN_: bit fill sN

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
    }
    return E_OK;
}

bignum_t add_bignum_carry_loc(bignum_s* d, const bignum_t v, const size_t idx) {
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

/* Return carry out, it can be only FALSE / TRUE, the others are error */
ReturnType sub_bignum(bignum_t* co, bignum_s* d, const bignum_s* s0, const bignum_s* s1, const bignum_t ci) {
    if(!((d != NULL) && (s0 != NULL) && (s1 != NULL)))
        return E_ERROR_NULL;

    if(!((d->nlen >= s0->nlen) && (d->nlen >= s1->nlen)))
        return E_ERROR_BIGNUM_LENGTH;

    {
        bignum_t _c = ci;

        const bignum_t _bf0_ = getMSB_fill(s0, false);  // _bfN_: bit fill sN
        const bignum_t _bf1_ = getMSB_fill(s1, false);  // _bfN_: bit fill sN

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

ReturnType sub_bignum_with_add_twos(bignum_t* co, bignum_s* d, const bignum_s* s0, const bignum_s* s1, const bignum_t ci) {
    if(!((d != NULL) && (s0 != NULL) && (s1 != NULL)))
        return E_ERROR_NULL;

    if(!((d->nlen >= s0->nlen) && (d->nlen >= s1->nlen)))
        return E_ERROR_BIGNUM_LENGTH;

    {
        bignum_t _c = ci + 1U;  // 2's compliment

        /* just Consider Condition(d->nlen == s1->nlen == s0->nlen) */
        const bignum_t _bf0_ = getMSB_fill(s0, false);  // _bfN_: bit fill sN
        const bignum_t _bf1_ = getMSB_fill(s1, true);   // _bfN_: bit fill sN

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
ReturnType mul_bignum_1bs_ext(bignum_s* d, const bignum_s* s1, const bignum_s* s0, const bool guard) {
    if((d != NULL) && (s1 != NULL) && (s0 != NULL)) {
        if((d->nlen) >= (s1->nlen + s0->nlen) || (!guard)) {
#if 0 /* NOT_CONSIDER_SIGNED_CASES */
            if((s1->type == BIGNUM_TYPE_SIGNED) && (s0->type == BIGNUM_TYPE_SIGNED))
#endif/* NOT_CONSIDER_SIGNED_CASES */
            if((s1->type != BIGNUM_TYPE_UNSIGNED) || (s0->type != BIGNUM_TYPE_UNSIGNED))
            {
                return E_ERROR_BIGNUM_SIGN;
            }

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
                    asl1b_bignum_self(tmp, NULL, 0U);
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
            return E_ERROR_BIGNUM_LENGTH;
        }
    } else {
        return E_ERROR_NULL;
    }
    return E_OK;
}

ReturnType mul_bignum_nbs_up2dn_ext(bignum_s* d, const bignum_s* s1, const bignum_s* s0, const bool guard) {
    if((d != NULL) && (s1 != NULL) && (s0 != NULL)) {
        _DPRINTF_("find_bignum_MSBL(s1) = %lu\n", find_bignum_MSBL(s1));
        _DPRINTF_("find_bignum_MSBL(s0) = %lu\n", find_bignum_MSBL(s0));

        if((d->bits) >= (find_bignum_MSBL(s1) + find_bignum_MSBL(s0) + 1UL) || (!guard)) {
#if 0 /* NOT_CONSIDER_SIGNED_CASES */
            if((s1->type == BIGNUM_TYPE_SIGNED) && (s0->type == BIGNUM_TYPE_SIGNED))
#endif/* NOT_CONSIDER_SIGNED_CASES */
            if(!guard)
            {
                return E_NOT_IMPL;
            }
            if((s1->type != BIGNUM_TYPE_UNSIGNED) || (s0->type != BIGNUM_TYPE_UNSIGNED))
            {
                return E_ERROR_BIGNUM_SIGN;
            }

            if(cmp0_bignum(s0) != BIGNUM_CMP_ZO)
            {
                ReturnType _fr_ = E_OK;

                bignum_s* _s0m2_;
                bignum_s* _prod_;

                size_t _s1_msbl_ = find_bignum_MSBL(s1);

                _s0m2_ = mkBigNum(d->bits);
                _prod_ = mkBigNum(d->bits);
                _fr_ = cpy_bignum_math(_s0m2_, s0);
                if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                _fr_ = clr_bignum(_prod_);
                if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };

                _PRINT_BITNUM_(_s0m2_, "[init] _s0m2_");
                _DPRINTF_("[init] _s1_msbl_ = %ld\r\n", _s1_msbl_);
                if(aslb_bignum_self(_s0m2_, _s1_msbl_) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                _PRINT_BITNUM_(_s0m2_, "[init] _s0m2_<<_s1_msbl_");

                _DPRINTF_("line before while(_s1_msbl_ != SIZE_MAX)\n");
                while(_s1_msbl_ != SIZE_MAX)
                {
                    _DPRINTF_("_s1_msbl_ = %lu\n", _s1_msbl_);
                    _PRINT_BITNUM_(_s0m2_, "_s0m2_");
                    bignum_t _bits_ = chk1b_bignum(s1, _s1_msbl_);
                    if(_bits_ != SIZE_MAX)
                    {
                        size_t _msbl_, _asrl_;

                        if(_bits_ != 0U)
                        {
                            _fr_ = add_bignum(NULL, _prod_, _prod_, _s0m2_, 0U);
                            _PRINT_BITNUM_(_prod_, "_prod_ += _s0m2_");
                            if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); break; };
                        }

                        _msbl_ = find_bignum_MSBL_bitLoc(s1, _s1_msbl_-1UL);
                        _asrl_ = (_s1_msbl_ - _msbl_);
                        _DPRINTF_("_msbl_ = %lu\n", _msbl_);
                        _DPRINTF_("_asrl_ = %lu\n", _asrl_);

                        if(_msbl_ != SIZE_MAX)
                        {
                            if(_s1_msbl_ >= _msbl_)
                            {
                                _fr_ = asrb_bignum_self(_s0m2_ , _asrl_);
                                if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); break; };
                                _s1_msbl_ = _msbl_;
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
                        _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_);
                        break;
                    }
                }

                if(_fr_ == E_OK)
                {
                    /* _quot_ is quotient */
                    _fr_ = cpy_bignum_math(d, _prod_);
                    if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                }

                if(rmBitNum(&_s0m2_) != 0)  { /* Memory leakage? */ };
                if(rmBitNum(&_prod_) != 0)  { /* Memory leakage? */ };
            }
            else
            {
                /* s0 is zero */
                return clr_bignum(d);
            }
        } else {
            return E_ERROR_BIGNUM_LENGTH;
        }
    } else {
        return E_ERROR_NULL;
    }
    return E_OK;
}

ReturnType mul_bignum_nbs_dn2up_ext(bignum_s* d, const bignum_s* s1, const bignum_s* s0, const bool guard) {
    if((d != NULL) && (s1 != NULL) && (s0 != NULL)) {
        _DPRINTF_("find_bignum_MSBL(s1) = %lu\n", find_bignum_MSBL(s1));
        _DPRINTF_("find_bignum_MSBL(s0) = %lu\n", find_bignum_MSBL(s0));

        if((d->bits) >= (find_bignum_MSBL(s1) + find_bignum_MSBL(s0) + 1UL) || (!guard)) {
#if 0 /* NOT_CONSIDER_SIGNED_CASES */
            if((s1->type == BIGNUM_TYPE_SIGNED) && (s0->type == BIGNUM_TYPE_SIGNED))
#endif/* NOT_CONSIDER_SIGNED_CASES */
            if((s1->type != BIGNUM_TYPE_UNSIGNED) || (s0->type != BIGNUM_TYPE_UNSIGNED))
            {
                return E_ERROR_BIGNUM_SIGN;
            }

            if(cmp0_bignum(s0) != BIGNUM_CMP_ZO)
            {
                ReturnType _fr_ = E_OK;

                bignum_s* _s0m2_;
                bignum_s* _prod_;

                size_t _s1_lsbl_ = find_bignum_LSBL(s1);

                _s0m2_ = mkBigNum(d->bits);
                _prod_ = mkBigNum(d->bits);
                _fr_ = cpy_bignum_math(_s0m2_, s0);
                if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                _fr_ = clr_bignum(_prod_);
                if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };

                _PRINT_BITNUM_(_s0m2_, "[init] _s0m2_");
                _DPRINTF_("[init] _s1_lsbl_ = %ld\r\n", _s1_lsbl_);
                if(aslb_bignum_self_unsafe(_s0m2_, _s1_lsbl_) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                _PRINT_BITNUM_(_s0m2_, "[init] _s0m2_<<_s1_lsbl_");

                while(s1->bits > _s1_lsbl_)
                {
                    _DPRINTF_("_s1_lsbl_ = %lu\n", _s1_lsbl_);
                    _PRINT_BITNUM_(_s0m2_, "_s0m2_");
                    bignum_t _bits_ = chk1b_bignum(s1, _s1_lsbl_);
                    if(_bits_ != SIZE_MAX)
                    {
                        size_t _lsbl_, _asll_;

                        if(_bits_ != 0U)
                        {
                            _fr_ = add_bignum(NULL, _prod_, _prod_, _s0m2_, 0U);
                            _PRINT_BITNUM_(_prod_, "_prod_ += _s0m2_");
                            if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); break; };
                        }

                        _lsbl_ = find_bignum_LSBL_bitLoc(s1, _s1_lsbl_+1UL);
                        _asll_ = (_lsbl_ - _s1_lsbl_ );
                        _DPRINTF_("_lsbl_ = %lu\n", _lsbl_);
                        _DPRINTF_("_asll_ = %lu\n", _asll_);

                        if(_lsbl_ != SIZE_MAX)
                        {
                            if(_lsbl_ >= _s1_lsbl_)
                            {
                                _fr_ = aslb_bignum_self_unsafe(_s0m2_ , _asll_);
                                if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); break; };
                                _s1_lsbl_ = _lsbl_;
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
                        _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_);
                        break;
                    }
                }

                if(_fr_ == E_OK)
                {
                    /* _quot_ is quotient */
                    _fr_ = cpy_bignum_math(d, _prod_);
                    if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                }

                if(rmBitNum(&_s0m2_) != 0)  { /* Memory leakage? */ };
                if(rmBitNum(&_prod_) != 0)  { /* Memory leakage? */ };
            }
            else
            {
                /* s0 is zero */
                return clr_bignum(d);
            }
        } else {
            return E_ERROR_BIGNUM_LENGTH;
        }
    } else {
        return E_ERROR_NULL;
    }
    return E_OK;
}
/* Divide with Modulo: 'n'umerator = 'q'uotient * 'd'enominator + 'r'emainder */
/* Divide with Modulo: ('n'umerator - 'r'emainder) / 'd'enominator = 'q'uotient  */
ReturnType div_bignum_with_mod_nbs_ext(bignum_s* q, bignum_s* r, const bignum_s* n, const bignum_s* d, const bool guard) {
    if(((q != NULL) || (r != NULL)) && (n != NULL) && (d != NULL)) {
        if(((n->bits) >= (d->bits)) || (!guard)) {
#if 0 /* NOT_CONSIDER_SIGNED_CASES */
            if((n->type == BIGNUM_TYPE_SIGNED) && (d->type == BIGNUM_TYPE_SIGNED))
#endif/* NOT_CONSIDER_SIGNED_CASES */
            if((n->type != BIGNUM_TYPE_UNSIGNED) || (d->type != BIGNUM_TYPE_UNSIGNED))
            {
                return E_ERROR_BIGNUM_SIGN;
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

                _temp_ = mkBigNum((n->bits)+(d->bits));  // _temp_ is init to n
                _d_m2_ = mkBigNum((n->bits)+(d->bits));  // _d_m2_ is multiple of d
                _quot_ = mkBigNum(d->bits);
                _fr_ = cpy_bignum_math(_temp_, n);
                if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                _fr_ = cpy_bignum_math(_d_m2_, d);
                if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                _fr_ = clr_bignum(_quot_);
                if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };

                _PRINT_BITNUM_(_temp_, "[init] _temp_");
                _PRINT_BITNUM_(_d_m2_, "[init] _d_m2_");

#if 0
                /*
                 * [init] _n_msbl_ = 1020
                 * [init] _d_msbl_ = 1020
                 * [init] _d_lsbl_ = 18446744073709551613
                 */
                /* not understandable test logs, why?.... */
                _d_lsbl_ = (_n_msbl_ - _d_msbl_);
#else
                _cmp_ = cmp_bignum_logical_unsafe(n, d);
                if((_cmp_ == BIGNUM_SIGN_NU) || (_cmp_ == BIGNUM_SIGN_ERR))
                {
                    /* has error */
                    _DPRINTF_("%s, line:%d, E_ERROR_BIGNUM_SIGN\r\n", __func__, __LINE__);
                    _fr_ = E_ERROR_BIGNUM_SIGN;
                }
                /* 'n'umerator is could be greater(larger) than or equal with 'd'enominator */
                else if((_cmp_ == BIGNUM_CMP_GT) || (_cmp_ == BIGNUM_CMP_EQ))
                {
                    _DPRINTF_("%s, line:%d, _cmp_:%d\r\n", __func__, __LINE__, _cmp_);
                    _d_lsbl_ = (_n_msbl_ - _d_msbl_);
                    _d_msbl_ = _n_msbl_;
                    if(aslb_bignum_self(_d_m2_, _d_lsbl_) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                }
                /* 'n'umerator is could be smaller than 'd'enominator, ex) 10 / 100 */
                else
                {
                    _DPRINTF_("%s, line:%d\r\n", __func__, __LINE__);
                    /* DO_NOTHING */
                };
#endif
                _DPRINTF_("[init] _n_msbl_ = %lu\n", _n_msbl_);
                _DPRINTF_("[init] _d_msbl_ = %lu\n", _d_msbl_);
                _DPRINTF_("[init] _d_lsbl_ = %lu\n", _d_lsbl_);

#if 0
                _DPRINTF_("line before while(_d_lsbl_ < SIZE_MAX)\n");
                while(_d_lsbl_ < SIZE_MAX)
#else
                _DPRINTF_("line before while(_d_lsbl_ < ((d->bits)-1UL))\n");
                while(_d_lsbl_ < ((d->bits)-1UL))
#endif
                {
                    _DPRINTF_("_n_msbl_ = %lu\n", _n_msbl_);
                    _DPRINTF_("_d_msbl_ = %lu\n", _d_msbl_);
                    _DPRINTF_("_d_lsbl_ = %lu\n", _d_lsbl_);
                    _PRINT_BITNUM_(_temp_, "_temp_");
                    _PRINT_BITNUM_(_d_m2_, "_d_m2_");
                    _cmp_ = cmp_bignum_logical_unsafe(_temp_, _d_m2_);
                    _DPRINTF_("%s, line:%d, _cmp_: %d\n", __func__, __LINE__, _cmp_);
                    if((_cmp_ == BIGNUM_CMP_GT) || (_cmp_ == BIGNUM_CMP_EQ))
                    {
                        size_t _msbl_, _lsrl_;
                        /* set bit q at lsb of d(N'th bit) */
                        _fr_ = set1b_bignum(_quot_, _d_lsbl_);
                        _PRINT_BITNUM_(_quot_, "_quot_");
                        if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); break; };
                        /* n = n - (d<<N) */
                        _fr_ = sub_bignum(NULL, _temp_, _temp_, _d_m2_, 0U);
                        _PRINT_BITNUM_(_temp_, "_temp_ -= _d_m2_");
                        if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); break; };

                        _msbl_ = find_bignum_MSBL(_temp_);
                        _lsrl_ = (_d_msbl_ - _msbl_);
                        _DPRINTF_("_msbl_ = %lu\n", _msbl_);
                        _DPRINTF_("_lsrl_ = %lu\n", _lsrl_);

                        if(_msbl_ != SIZE_MAX)
                        {
                            /* found next bit loction */
                            if(_d_lsbl_ >= _lsrl_)
                            {
                                _fr_ = asrb_bignum_self(_d_m2_, _lsrl_);
                                if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); break; };
                                _n_msbl_ = _msbl_;
                                _d_msbl_ -= _lsrl_;
                                _d_lsbl_ -= _lsrl_;
                            }
                            else
                            {
                                /* logical shift right(lsr) of d is end, has remainder */
                                _DPRINTF_("logical shift right(lsr) of d is end, has remainder, %s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_);
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
                        _fr_ = asr1b_bignum_self(_d_m2_, NULL, 0UL);
                        if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); break; };
                        _d_msbl_--;
                        _d_lsbl_--;
                    }
                    else
                    {
                        /* unreachable */
                        _fr_ = E_ERROR_RUNTIME;
                        _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_);
                        break;
                    }
                }

                if(_fr_ == E_OK)
                {
                    /* _temp_ has remainder */
                    if(r != NULL)   _fr_ = cpy_bignum_math(r, _temp_);
                    /* _quot_ is quotient */
                    if(q != NULL)   _fr_ = cpy_bignum_math(q, _quot_);
                }

                if(rmBitNum(&_temp_) != 0)  { /* Memory leakage? */ };
                if(rmBitNum(&_d_m2_) != 0)  { /* Memory leakage? */ };
                if(rmBitNum(&_quot_) != 0)  { /* Memory leakage? */ };

                return _fr_;
            }
            else
            {
                /* NOT_FOUND_MSB: denominator is 0 */
                return E_ERROR_DIVIDE_ZERO;
            };
        } else {
            return E_ERROR_BIGNUM_LENGTH;
        }
    } else {
        return E_ERROR_NULL;
    }
    return E_OK;
}

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
ReturnType gcd_bignum_ext(bignum_s* r, bignum_s* s, bignum_s* t, const bignum_s* a, const bignum_s* b, const bool guard) {
    if((r != NULL) && (a != NULL) && (b != NULL)) {
        if((((a->bits) == (b->bits)) && ((a->bits) == (r->bits)))|| (!guard)) {
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
            if(cpy_bignum_math(_o_r_, a) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
            if(cpy_bignum_math(___r_, b) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
            // (old_s, s) := (1, 0)
            if(clr_bignum(_o_s_) != E_OK)         { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
            if(set1b_bignum(_o_s_, 0UL) != E_OK)  { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
            if(clr_bignum(___s_) != E_OK)         { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
            // (old_t, t) := (0, 1)
            if(clr_bignum(_o_t_) != E_OK)         { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
            if(clr_bignum(___t_) != E_OK)         { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
            if(set1b_bignum(___t_, 0UL) != E_OK)  { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };

            _PRINT_BITNUM_(_o_r_, "[init] _o_r_");
            _PRINT_BITNUM_(___r_, "[init] ___r_");
            _PRINT_BITNUM_(_o_s_, "[init] _o_s_");
            _PRINT_BITNUM_(___s_, "[init] ___s_");
            _PRINT_BITNUM_(_o_t_, "[init] _o_t_");
            _PRINT_BITNUM_(___t_, "[init] ___t_");
            while(cmp0_bignum(___r_) != BIGNUM_CMP_ZO)
            {
                if((_fr_ = cpy_bignum_math(_tmp_, ___r_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };

                // quotient := old_r div r
                if((_fr_ = div_bignum_with_mod(_quo_, ___r_, _o_r_, ___r_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); }
                if((_fr_ = cpy_bignum_math(_o_r_, _tmp_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                // (old_r, r) := (r, old_r − quotient × r)
                // note: 'old_r − quotient × r' is maen that remainder
                _PRINT_BITNUM_(_quo_, "_quo_");
                _PRINT_BITNUM_(_o_r_, "_o_r_");
                _PRINT_BITNUM_(___r_, "___r_");

                // (old_s, s) := (s, old_s − quotient × s)
                if((_fr_ = cpy_bignum_math(_tmp_, ___s_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                if((_fr_ = mul_bignum_unsafe(_tmp_, _quo_, _tmp_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                if((_fr_ = sub_bignum(NULL, _tmp_, _o_s_, _tmp_, 0U)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                if((_fr_ = cpy_bignum_math(_o_s_, ___s_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                if((_fr_ = cpy_bignum_math(___s_, _tmp_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                _PRINT_BITNUM_(_o_s_, "_o_s_");
                _PRINT_BITNUM_(___s_, "___s_");

                // (old_t, t) := (t, old_t − quotient × t)
                if((_fr_ = cpy_bignum_math(_tmp_, ___t_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                if((_fr_ = mul_bignum_unsafe(_tmp_, _quo_, _tmp_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                if((_fr_ = sub_bignum(NULL, _tmp_, _o_t_, _tmp_, 0U)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                if((_fr_ = cpy_bignum_math(_o_t_, ___t_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                if((_fr_ = cpy_bignum_math(___t_, _tmp_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                _PRINT_BITNUM_(_o_t_, "_o_t_");
                _PRINT_BITNUM_(___t_, "___t_");
            }

            if(s != NULL) {
                if(cpy_bignum_math(s, _o_s_) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
            }
            if(t != NULL) {
                if(cpy_bignum_math(t, _o_t_) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
            }
            _PRINT_BITNUM_(_o_s_, "Bézout coefficients: s");
            _PRINT_BITNUM_(_o_t_, "Bézout coefficients: t");

            if(cpy_bignum_math(r, _o_r_) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
            _PRINT_BITNUM_(_o_r_, "greatest common divisor");

            if(rmBitNum(&_tmp_) != 0)  { /* Memory leakage? */ };
            if(rmBitNum(&_quo_) != 0)  { /* Memory leakage? */ };
            if(rmBitNum(&_o_r_) != 0)  { /* Memory leakage? */ };
            if(rmBitNum(&___r_) != 0)  { /* Memory leakage? */ };
            if(rmBitNum(&_o_s_) != 0)  { /* Memory leakage? */ };
            if(rmBitNum(&___s_) != 0)  { /* Memory leakage? */ };
            if(rmBitNum(&_o_t_) != 0)  { /* Memory leakage? */ };
            if(rmBitNum(&___t_) != 0)  { /* Memory leakage? */ };
        } else {
            return E_ERROR_BIGNUM_LENGTH;
        }
    } else {
        return E_ERROR_NULL;
    }
    return E_OK;
}

ReturnType mim_bignum_ext(bignum_s* t, bignum_s* r, const bignum_s* a, const bignum_s* n, const bool guard) {
    if((t != NULL) && (a != NULL) && (n != NULL)) {
        if((((a->bits) == (n->bits)) && ((a->bits) == (t->bits)))|| (!guard)) {
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
            if((_fr_ = cpy_bignum_math(_o_r_, n)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
            if((_fr_ = cpy_bignum_math(_n_r_, a)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
            // t := 0;     newt := 1
            if(clr_bignum(_o_t_) != E_OK)         { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
            if(clr_bignum(_n_t_) != E_OK)         { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
            if(set1b_bignum(_n_t_, 0UL) != E_OK)  { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };

            _PRINT_BITNUM_(_o_r_, "[init] _o_r_");
            _PRINT_BITNUM_(_n_r_, "[init] _n_r_");
            _PRINT_BITNUM_(_o_t_, "[init] _o_t_");
            _PRINT_BITNUM_(_n_t_, "[init] _n_t_");
            while(cmp0_bignum(_n_r_) != BIGNUM_CMP_ZO)
            {
                if((_fr_ = cpy_bignum_math(_tmp_, _n_r_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };

                // quotient := r div newr
                if((_fr_ = div_bignum_with_mod(_quo_, _n_r_, _o_r_, _n_r_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); }
                if((_fr_ = cpy_bignum_math(_o_r_, _tmp_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                // (r, newr) := (newr, r − quotient × newr)
                // note: 'old_r − quotient × r' is maen that remainder
                _PRINT_BITNUM_(_quo_, "_quo_");
                _PRINT_BITNUM_(_o_r_, "_o_r_");
                _PRINT_BITNUM_(_n_r_, "_n_r_");

                // (t, newt) := (newt, t − quotient × newt)
                if((_fr_ = cpy_bignum_math(_tmp_, _n_t_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                if((_fr_ = mul_bignum_unsafe(_tmp_, _quo_, _tmp_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                if((_fr_ = sub_bignum(NULL, _tmp_, _o_t_, _tmp_, 0U)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                if((_fr_ = cpy_bignum_math(_o_t_, _n_t_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                if((_fr_ = cpy_bignum_math(_n_t_, _tmp_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                _PRINT_BITNUM_(_o_t_, "_o_t_");
                _PRINT_BITNUM_(_n_t_, "_n_t_");
            }

            _o_r_is_0_ = cmp0_bignum(_o_r_);
            _o_r_is_1_ = cmp1_bignum(_o_r_);
            _sign_of_o_t_ = sign_bignum_unsafe(_o_r_);
#if 0 /* OLD_R_IS_UNSIGNED_NUMBER_BECAUSE_REMAINDER_CAN_NOT_BE_NEGATIVE_VALUES */
            if(((_o_r_is_0_ == BIGNUM_CMP_ZO) || (_o_r_is_1_ == BIGNUM_CMP_ON)) || (_sign_of_o_t_ == BIGNUM_SIGN_NEG))
#else
            if((_o_r_is_0_ == BIGNUM_CMP_ZO) || (_o_r_is_1_ == BIGNUM_CMP_ON))
#endif/* OLD_R_IS_UNSIGNED_NUMBER_BECAUSE_REMAINDER_CAN_NOT_BE_NEGATIVE_VALUES */
            {
                // if t < 0 then
                //     t := t + n
                _PRINT_BITNUM_(_o_t_, "Bézout coefficients: t");
                _sign_of_o_t_ = sign_bignum_unsafe(_o_t_);
                if(_sign_of_o_t_ == BIGNUM_SIGN_NEG)
                {
                    /*  added with n */
                    _DPRINTF_("add_bignum(NULL, t, _o_t_, n, 0U)\r\n");
                    if((_fr_ = add_bignum(NULL, t, _o_t_, n, 0U)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                }
                else if(_sign_of_o_t_ == BIGNUM_SIGN_POS)
                {
                    _DPRINTF_("cpy_bignum_math(t, _o_t_)\r\n");
                    if((_fr_ = cpy_bignum_math(t, _o_t_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                }
                else
                {
                    /* has error */ _DPRINTF_("%s, line:%d, _sign_of_o_t_: %d\n", __func__, __LINE__, _sign_of_o_t_);
                }
            }

            if(r != NULL)   if((_fr_ = cpy_bignum_math(r, _o_r_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };

            if(rmBitNum(&_tmp_) != 0)  { /* Memory leakage? */ };
            if(rmBitNum(&_quo_) != 0)  { /* Memory leakage? */ };
            if(rmBitNum(&_o_r_) != 0)  { /* Memory leakage? */ };
            if(rmBitNum(&_n_r_) != 0)  { /* Memory leakage? */ };
            if(rmBitNum(&_o_t_) != 0)  { /* Memory leakage? */ };
            if(rmBitNum(&_n_t_) != 0)  { /* Memory leakage? */ };
        } else {
            return E_ERROR_BIGNUM_LENGTH;
        }
    } else {
        return E_ERROR_NULL;
    }
    return E_OK;
}
#undef _DPRINTF_

