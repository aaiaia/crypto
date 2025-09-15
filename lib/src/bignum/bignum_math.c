#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "bignum/bignum_math.h"
#include "bignum/bignum_logic.h"

#ifdef ENABLE_BIGNUM_LOG
#include <stdio.h>
#define _DPRINTF_   printf

#define _PRINT_BITNUM_(p, title) _internal_print_bignum(p, title, 0UL, false)
void _internal_print_bignum(bignum_s* p, const char* title, const size_t lfn, const bool details)
{
    _DPRINTF_("[%s]\r\n", title);
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

    (void)add_bignum_loc(d, 1UL, 0UL);

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
        return E_ERROR_ARGS;

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

/* Return carry out, it can be only FALSE / TRUE, the others are error */
ReturnType sub_bignum(bignum_t* co, bignum_s* d, const bignum_s* s0, const bignum_s* s1, const bignum_t ci) {
    if(!((d != NULL) && (s0 != NULL) && (s1 != NULL)))
        return E_ERROR_NULL;

    if(!((d->nlen >= s0->nlen) && (d->nlen >= s1->nlen)))
        return E_ERROR_ARGS;

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
        return E_ERROR_ARGS;

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
                    lsl1b_bignum_self(tmp, NULL, 0U);
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

ReturnType mul_bignum_nbs_ext(bignum_s* d, const bignum_s* s1, const bignum_s* s0, const bool guard) {
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

                size_t _s1_msbl_ = find_bignum_MSBL(s1);

                _s0m2_ = mkBigNum(d->bits);
                _prod_ = mkBigNum(d->bits);
                _fr_ = cpy_bignum_math(_s0m2_, s0);
                if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                _fr_ = clr_bignum(_prod_);
                if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };

                _PRINT_BITNUM_(_s0m2_, "[init] _s0m2_");

                if(lslb_bignum_self(_s0m2_, _s1_msbl_) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };

                _DPRINTF_("line before while(_s1_msbl_ != SIZE_MAX)\n");
                while(_s1_msbl_ != SIZE_MAX)
                {
                    _DPRINTF_("_s1_msbl_ = %lu\n", _s1_msbl_);
                    _PRINT_BITNUM_(_s0m2_, "_s0m2_");
                    bignum_t _bits_ = chk1b_bignum(s1, _s1_msbl_);
                    if(_bits_ != SIZE_MAX)
                    {
                        size_t _msbl_, _lsrl_;

                        if(_bits_ != 0U)
                        {
                            _fr_ = add_bignum(NULL, _prod_, _prod_, _s0m2_, 0U);
                            _PRINT_BITNUM_(_prod_, "_prod_ += _s0m2_");
                            if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); break; };
                        }

                        _msbl_ = find_bignum_MSBL_bitLoc(s1, _s1_msbl_-1UL);
                        _lsrl_ = (_s1_msbl_ - _msbl_);
                        _DPRINTF_("_msbl_ = %lu\n", _msbl_);
                        _DPRINTF_("_lsrl_ = %lu\n", _lsrl_);

                        if(_msbl_ != SIZE_MAX)
                        {
                            if(_s1_msbl_ >= _msbl_)
                            {
                                _fr_ = lsrb_bignum_self(_s0m2_ , _lsrl_);
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
            return E_ERROR_ARGS;
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

                size_t _n_msbl_ = find_bignum_MSBL(n);
                size_t _d_msbl_ = find_bignum_MSBL(d);
                size_t _d_lsbl_ = 0UL;

                _temp_ = mkBigNum(n->bits);  // _temp_ is init to n
                _d_m2_ = mkBigNum(n->bits);  // _d_m2_ is multiple of d
                _quot_ = mkBigNum(d->bits);
                _fr_ = cpy_bignum_math(_temp_, n);
                if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                _fr_ = cpy_bignum_math(_d_m2_, d);
                if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                _fr_ = clr_bignum(_quot_);
                if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };

                _PRINT_BITNUM_(_temp_, "[init] _temp_");
                _PRINT_BITNUM_(_d_m2_, "[init] _d_m2_");

                _d_lsbl_ = (_n_msbl_ - _d_msbl_);
                _d_msbl_ = _n_msbl_;
                if(lslb_bignum_self(_d_m2_, _d_lsbl_) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
                _DPRINTF_("[init] _n_msbl_ = %lu\n", _n_msbl_);
                _DPRINTF_("[init] _d_msbl_ = %lu\n", _d_msbl_);
                _DPRINTF_("[init] _d_lsbl_ = %lu\n", _d_lsbl_);

                _DPRINTF_("line before while(_d_lsbl_ < SIZE_MAX)\n");
                while(_d_lsbl_ < SIZE_MAX)
                {
                    _DPRINTF_("_n_msbl_ = %lu\n", _n_msbl_);
                    _DPRINTF_("_d_msbl_ = %lu\n", _d_msbl_);
                    _DPRINTF_("_d_lsbl_ = %lu\n", _d_lsbl_);
                    _PRINT_BITNUM_(_temp_, "_temp_");
                    _PRINT_BITNUM_(_d_m2_, "_d_m2_");
                    bignum_cmp_e _cmp_ = cmp_bignum_logical(_temp_, _d_m2_);
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
                                _fr_ = lsrb_bignum_self(_d_m2_, _lsrl_);
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
                        _fr_ = lsr1b_bignum_self(_d_m2_, NULL, 0UL);
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
            return E_ERROR_ARGS;
        }
    } else {
        return E_ERROR_NULL;
    }
    return E_OK;
}
#undef _DPRINTF_

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
