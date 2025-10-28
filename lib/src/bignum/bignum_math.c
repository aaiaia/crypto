#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "bignum/bignum_math.h"
#include "bignum/bignum_logic.h"

#define BIGNUM_SIGN_MASK(N, IGN)    ((((N)->nums[(N)->nlen-1U]&BIGNUM_MSB_MASK)&&(!(IGN)))?(BIGNUM_MAX):(0U))
#define BIGNUM_PRC_LEN(D, S)        (((D)->nlen > (S)->nlen)?((S)->nlen):((D)->nlen))
#define BIGNUM_EXT_LEN(D, S)        ((D)->nlen)
#define BIGNUM_SAME_LEN(D, S)       ((D)->nlen == (S)->nlen)
#define BIGNUM_SAME_BIT(D, S)       ((D)->bits == (S)->bits)

#if 0 /* ENABLE_BIGNUM_LOG */
#ifndef ENABLE_BIGNUM_LOG
#define ENABLE_BIGNUM_LOG
#endif/* ENABLE_BIGNUM_LOG */
#endif/* ENABLE_BIGNUM_LOG */
#ifdef ENABLE_BIGNUM_LOG
#include <stdio.h>
#define _DPRINTF_   printf

#define _PRINT_BIGNUM_(p, title) _internal_print_bignum(p, title, __func__, __LINE__, 0UL, false)
void _internal_print_bignum(const bignum_s* p, const char* title, const char* funcName, const int lineNum, const size_t lfn, const bool details)
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
#define _PRINT_BIGNUM_(p, title)
#undef _DEBUG_SELECTIVES_
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

ReturnType cpy_bignum_ext(bignum_s* d, const bignum_s* s, const bool ign_sign, const bool ign_len) {
    if(!((d != NULL) && (s != NULL))) {
        _DPRINTF_("[ERROR]@%s, line:%d, d:0x%p, s:0x%p\n", __func__, __LINE__, d, s);
        return E_ERROR_NULL;
    }
    if(!((d->nums != NULL) && (s->nums != NULL))) {
        _DPRINTF_("[ERROR]@%s, line:%d, d->nums:0x%p, s->nums:0x%p\n", __func__, __LINE__, d->nums, s->nums);
        return E_ERROR_NULL;
    }

    const bignum_t signBit = BIGNUM_SIGN_MASK(s, ign_sign);
    const size_t cpyLen = BIGNUM_PRC_LEN(d, s);
    const size_t extLen = BIGNUM_EXT_LEN(d, s);

    _DPRINTF_("%s, line:%d, signBit=0x%x, cpyLen=%ld, extLen=%ld\n", __func__, __LINE__, signBit, cpyLen, extLen);
    _DPRINTF_("%s, line:%d, signBit=0x%x, d->nlen=%ld, s->nlen=%ld\n", __func__, __LINE__, signBit, d->nlen, s->nlen);
    if((d->nlen < s->nlen) && (!ign_len)) {
        _DPRINTF_("[ERROR]@%s, line:%d, d->nlen=%ld, s->nlen=%ld\n", __func__, __LINE__, d->nlen, s->nlen);
        // Accept only same length
        return E_ERROR_BIGNUM_LENGTH;
    }

    for(size_t i = cpyLen; i < extLen; i++) {
        d->nums[i] = signBit;
    }
    for(size_t i = 0; i < cpyLen; i++) {
        d->nums[i] = s->nums[i];
    }

    return E_OK;
}

ReturnType twos_bignum(bignum_s* d, const bignum_s* s)
{
    ReturnType ret = E_NOT_OK;
    ret = cpy_bignum_signed_safe(d, s);
    if(ret != E_OK) return ret;

    ret = inv_bignum(d);
    if(ret != E_OK) return ret;

    (void)add_bignum_carry_loc_unsigned(d, 1UL, 0UL);

    ret = E_OK;

    return ret;
}

ReturnType abs_bignum_ext(bignum_s* d, const bignum_s* s, const bool ign_sign)
{
    if((d == NULL) || (s == NULL))  return E_ERROR_NULL;

    if(BIGNUM_SIGN_MASK(s, ign_sign)) // negative
    {
        return twos_bignum(d, s);
    }
    else
    {
        return cpy_bignum_signed_safe(d, s);
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

bignum_cmp_e cmp_bignum_logical_ext(const bignum_s* s0, const bignum_s* s1, const bool ign_sign, const bool ign_len) {
    bignum_sign_e sig_s0 = sign_bignum_ext(s0, ign_sign);
    bignum_sign_e sig_s1 = sign_bignum_ext(s1, ign_sign);

    /* sign_bignum_signed() is checking invalid case of input arguments 's0' and 's1' */
    if((sig_s0 == BIGNUM_SIGN_ERR) || (sig_s1 == BIGNUM_SIGN_ERR))
	{
		_DPRINTF_("@%s, line:%d, BIGNUM_CMP_ERR, sig_s0: %d\r\n", __func__, __LINE__, sig_s0);
		_DPRINTF_("@%s, line:%d, BIGNUM_CMP_ERR, sig_s1: %d\r\n", __func__, __LINE__, sig_s1);
        return BIGNUM_CMP_ER;
	}
    if((!BIGNUM_SAME_LEN(s0, s1) || !BIGNUM_SAME_BIT(s0, s1)) && (!ign_len))
	{
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

        for(size_t i = cmp_nlen - 1UL; i < SIZE_MAX; i--)
        {
            if(s0->nums[i] > s1->nums[i])		return BIGNUM_CMP_GT;
            if(s0->nums[i] < s1->nums[i])   	return BIGNUM_CMP_LT;
        }

        _DPRINTF_("@%s, line:%d, cmp_nlen: %lu, cmp_elen: %lu\r\n", __func__, __LINE__, cmp_nlen, cmp_elen);
        if(s0->nlen > s1->nlen)
        {
            _DPRINTF_("@%s, line:%d, s0->nlen:%lu > s1->nlen:%lu\r\n", __func__, __LINE__, s0->nlen, s1->nlen);
            for(size_t i = cmp_elen; i < cmp_elen; i++)
            {
                if(s0->nums[i] > s1_signBit)	return BIGNUM_CMP_GT;
                if(s0->nums[i] < s1_signBit)   	return BIGNUM_CMP_LT;
            }
        }
        else if((s0->nlen < s1->nlen))
        {
            _DPRINTF_("@%s, line:%d, s0->nlen:%lu < s1->nlen:%lu\r\n", __func__, __LINE__, s0->nlen, s1->nlen);
            for(size_t i = cmp_elen; i < cmp_elen; i++)
            {
                if(s0_signBit > s1->nums[i])	return BIGNUM_CMP_GT;
                if(s0_signBit < s1->nums[i])   	return BIGNUM_CMP_LT;
            }
        }
        else
        {
            _DPRINTF_("@%s, line:%d, s0->nlen:%lu == s1->nlen:%lu\r\n", __func__, __LINE__, s0->nlen, s1->nlen);
            /* s0->nlen == s1->nlen Case */
            /* Already done */
        }
												return BIGNUM_CMP_EQ;
    }
    else if(sig_s0 == BIGNUM_SIGN_POS)			return BIGNUM_CMP_GT;
    else if(sig_s1 == BIGNUM_SIGN_POS)      	return BIGNUM_CMP_LT;
    else                                    	return BIGNUM_CMP_ER; /* Unreachable */
}

/* Return carry out, it can be only FALSE / TRUE, the others are error */
ReturnType add_bignum_ext(bignum_t* co, bignum_s* d, const bignum_s* s0, const bignum_s* s1, const bignum_t ci) {
    if(!((d != NULL) && (s0 != NULL) && (s1 != NULL)))
        return E_ERROR_NULL;

    if(!((d->nlen >= s0->nlen) && (d->nlen >= s1->nlen)))
        return E_ERROR_BIGNUM_LENGTH;

    bignum_t _c = ci;

    /* just Consider Condition(d->nlen == s1->nlen == s0->nlen) */
    const bignum_t _bf0_ = BIGNUM_SIGN_MASK(s0, true);  // _bfN_: bit fill sN
    const bignum_t _bf1_ = BIGNUM_SIGN_MASK(s1, true);  // _bfN_: bit fill sN

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

bignum_t sub_bignum_carry_loc_ext(bignum_s* d, const bignum_t v, const size_t idx, const bool ign_sign) {
    bignum_t _s;
    bignum_t _c = v;
    const bignum_t SIGN_EXT = ((BIGNUM_SIGN_BIT(v) != 0U) && (!ign_sign))?(BIGNUM_MAX):(0U);;

    for(size_t i = idx; i < d->nlen; i++) {
        _s = d->nums[i] - _c;
        _c = (_s > d->nums[i]);
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

/* Return carry out, it can be only FALSE / TRUE, the others are error */
ReturnType sub_bignum_ext(bignum_t* co, bignum_s* d, const bignum_s* s0, const bignum_s* s1, const bignum_t ci) {
    if(!((d != NULL) && (s0 != NULL) && (s1 != NULL)))
        return E_ERROR_NULL;

    if(!((d->nlen >= s0->nlen) && (d->nlen >= s1->nlen)))
        return E_ERROR_BIGNUM_LENGTH;

    {
        bignum_t _c = ci;

        const bignum_t _bf0_ = BIGNUM_SIGN_MASK(s0, true);  // _bfN_: bit fill sN
        const bignum_t _bf1_ = BIGNUM_SIGN_MASK(s1, true);  // _bfN_: bit fill sN

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
    for(size_t i = 0U; i < es1->nlen; i++) {
        size_t sftBit = (nSftBit >= BIGNUM_BITS)?(BIGNUM_BITS):(nSftBit);
        for(size_t sft = 0U; sft < sftBit; sft++) {
            if(((es1->nums[i] >> sft) & 0x1U) != 0x0u) {
                bignum_t co = BIGNUM_MAX;
                if(add_bignum_ext(&co, acc, acc, es0, 0U) != E_OK)
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

ReturnType mul_bignum_nbs_dn2up_ext(bignum_s* d, const bignum_s* s1, const bignum_s* s0, const bool ign_len) {
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
        _fr_ = cpy_bignum_signed_safe(_es0_, s0);
        if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
        _fr_ = cpy_bignum_signed_safe(_es1_, s1);
        if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
        _fr_ = clr_bignum(_acc_);
        if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };

        _es1_lsbl_ = find_bignum_LSBL(s1);

        _PRINT_BIGNUM_(_es0_, "[init] _es0_");
        _DPRINTF_("[init] _es1_lsbl_ = %ld\r\n", _es1_lsbl_);
        if(aslb_bignum_self_unsafe(_es0_, _es1_lsbl_) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
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
                    _fr_ = add_bignum(_acc_, _acc_, _es0_);
                    _PRINT_BIGNUM_(_acc_, "_acc_ += _es0_");
                    if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); break; };
                }

                _lsbl_ = find_bignum_LSBL_bitLoc(_es1_, _es1_lsbl_+1UL);
                _asll_ = (_lsbl_ - _es1_lsbl_ );
                _DPRINTF_("_lsbl_ = %lu\n", _lsbl_);
                _DPRINTF_("_asll_ = %lu\n", _asll_);

                if(_lsbl_ != SIZE_MAX)
                {
                    if(_lsbl_ >= _es1_lsbl_)
                    {
                        _fr_ = aslb_bignum_self_unsafe(_es0_ , _asll_);
                        if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); break; };
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
                _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_);
                break;
            }
        }

        if(_fr_ == E_OK)
        {
            /* _quot_ is quotient */
            _fr_ = cpy_bignum_signed_safe(d, _acc_);
            if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
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
ReturnType div_bignum_with_mod_nbs_ext(bignum_s* q, bignum_s* r, const bignum_s* n, const bignum_s* d, const bool ign_len) {
    if(!((n != NULL) && (d != NULL))) {
        _DPRINTF_("[ERROR]@%s, line:%d, n: 0x%p, d: 0x%p\n", __func__, __LINE__, n, d);
        return E_ERROR_NULL;
    }
    /* output was selecable, all output are NULL check */
    if(!((q != NULL) || (r != NULL))) {
        _DPRINTF_("[ERROR]@%s, line:%d, q: 0x%p, r: 0x%p\n", __func__, __LINE__, q, r);
        return E_ERROR_NULL;
    }
    if(!(n->bits) >= (d->bits)) {
        _DPRINTF_("[ERROR]@%s, line:%d, n->bits: 0x%lu, d->bits: 0x%lu\n", __func__, __LINE__, n->bits, d->bits);
        return E_ERROR_BIGNUM_LENGTH;
    }
    if(q != NULL) {
        /* worst case: if 'd' is d1, 'q'uotient has same length with 'n'umerator */
        if(!((q->bits) >= (n->bits)) && (!ign_len)) {
            _DPRINTF_("[ERROR]@%s, line:%d, q->bits: 0x%lu, n->bits: 0x%lu\n", __func__, __LINE__, q->bits, n->bits);
            return E_ERROR_BIGNUM_LENGTH;
        }
    }
    if(r != NULL) {
        /* worst case: if 'q'uotient become 0d0, 'r'emainder has same length with 'n'umerator */
        if(!((r->bits) >= (n->bits)) && (!ign_len)) {
            _DPRINTF_("[ERROR]@%s, line:%d, r->bits: 0x%lu, n->bits: 0x%lu\n", __func__, __LINE__, r->bits, n->bits);
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
        if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
        _fr_ = cpy_bignum_unsigned_safe(_d_m2_, d);
        if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
        _fr_ = clr_bignum(_quot_);
        if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };

        _PRINT_BIGNUM_(_temp_, "[init] _temp_");
        _PRINT_BIGNUM_(_d_m2_, "[init] _d_m2_");

#if 0
        /*
         * [init] _n_msbl_ = 1020
         * [init] _d_msbl_ = 1020
         * [init] _d_lsbl_ = 18446744073709551613
         */
        /* not understandable test logs, why?.... */
        _d_lsbl_ = (_n_msbl_ - _d_msbl_);
#else

#if 0
        _cmp_ = cmp_bignum_logical_unsigned(n, d);
#else
        _cmp_ = cmp_bignum_logical_unsigned_unsafe(n, d);

#endif
        if((_cmp_ == BIGNUM_CMP_NU) || (_cmp_ == BIGNUM_CMP_ER))
        {
            /* has error */
            _DPRINTF_("%s, line:%d, _cmp_:%d\r\n", __func__, __LINE__, _cmp_);
            _fr_ = E_ERROR_BIGNUM_COMPARE;
        }
        /* 'n'umerator is could be greater(larger) than or equal with 'd'enominator */
        else if((_cmp_ == BIGNUM_CMP_GT) || (_cmp_ == BIGNUM_CMP_EQ))
        {
            _DPRINTF_("%s, line:%d, _cmp_:%d\r\n", __func__, __LINE__, _cmp_);
            _d_lsbl_ = (_n_msbl_ - _d_msbl_);
            _d_msbl_ = _n_msbl_;
            if(lslb_bignum_self(_d_m2_, _d_lsbl_) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
        }
        /* 'n'umerator is could be smaller than 'd'enominator, ex) 10 / 100 */
        else if(_cmp_ == BIGNUM_CMP_LT)
        {
            _DPRINTF_("'n'umerator is could be smaller than 'd'enominator, ex) 10 / 100\r\n");
            _PRINT_BIGNUM_(n, "n");
            _PRINT_BIGNUM_(d, "d");
            _DPRINTF_("%s, line:%d\r\n", __func__, __LINE__);
            /* DO_NOTHING */
        }
        else
        {
            _DPRINTF_("%s, line:%d, _cmp_:%d, UNREACHABLE\r\n", __func__, __LINE__, _cmp_);
        }
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
            _PRINT_BIGNUM_(_temp_, "_temp_");
            _PRINT_BIGNUM_(_d_m2_, "_d_m2_");
            _cmp_ = cmp_bignum_logical_unsigned(_temp_, _d_m2_);
            _DPRINTF_("%s, line:%d, _cmp_: %d\n", __func__, __LINE__, _cmp_);
            if((_cmp_ == BIGNUM_CMP_GT) || (_cmp_ == BIGNUM_CMP_EQ))
            {
                size_t _msbl_, _lsrl_;
                /* set bit q at lsb of d(N'th bit) */
                _fr_ = set1b_bignum(_quot_, _d_lsbl_);
                _PRINT_BIGNUM_(_quot_, "_quot_");
                if(_fr_ != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); break; };
                /* n = n - (d<<N) */
                _fr_ = sub_bignum(_temp_, _temp_, _d_m2_);
                _PRINT_BIGNUM_(_temp_, "_temp_ -= _d_m2_");
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
            if(r != NULL)   _fr_ = cpy_bignum_unsigned_unsafe(r, _temp_);
            /* _quot_ is quotient */
            if(q != NULL)   _fr_ = cpy_bignum_unsigned_unsafe(q, _quot_);
        }

        if(rmBigNum(&_temp_) != 0)  { /* Memory leakage? */ };
        if(rmBigNum(&_d_m2_) != 0)  { /* Memory leakage? */ };
        if(rmBigNum(&_quot_) != 0)  { /* Memory leakage? */ };

        return _fr_;
    }
    else
    {
        /* NOT_FOUND_MSB: denominator is 0 */
        return E_ERROR_DIVIDE_ZERO;
    };

    return E_OK;
}

ReturnType aim_bignum_ext(bignum_s* x, const bignum_s* n, const bignum_s* p, const bool ign_len)
{
    if(!((x != NULL) && (n != NULL) && (p != NULL)))                            return E_ERROR_NULL;
    if(!(((n->bits) == (p->bits)) && ((x->bits) == (p->bits))) && (!ign_len))   return E_ERROR_BIGNUM_LENGTH;

    bool errFlags;
    bignum_sign_e signOf_n = BIGNUM_SIGN_NU;
    bignum_cmp_e cmp_n_with_p = BIGNUM_CMP_NU;
    bignum_s* abs_n = mkBigNum(n->bits);

    abs_bignum_signed(abs_n, n);
    cmp_n_with_p = cmp_bignum_logical(abs_n, p);
    signOf_n = sign_bignum_signed(n);

    _DPRINTF_("%s, line:%d, signOf_n:%d\n", __func__, __LINE__, signOf_n);
    if(signOf_n  == BIGNUM_SIGN_POS) {
        if((cmp_n_with_p == BIGNUM_CMP_GT) || (cmp_n_with_p == BIGNUM_CMP_EQ)) {
            sub_bignum(x, abs_n, p);
        } else {
            cpy_bignum_signed_safe(x, abs_n);
        }
    } else if(signOf_n  == BIGNUM_SIGN_NEG) {
        if((cmp_n_with_p == BIGNUM_CMP_GT) || (cmp_n_with_p == BIGNUM_CMP_EQ)) {
            rmBigNum(&abs_n);
            return E_NOT_IMPL;
        } else {
            sub_bignum(x, p, abs_n);
        }
    } else {
        rmBigNum(&abs_n);
        return E_ERROR_RUNTIME;
    }

    rmBigNum(&abs_n);

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
    if(cpy_bignum_signed_safe(_o_r_, a) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
    if(cpy_bignum_signed_safe(___r_, b) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
    // (old_s, s) := (1, 0)
    if(clr_bignum(_o_s_) != E_OK)         { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
    if(set1b_bignum(_o_s_, 0UL) != E_OK)  { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
    if(clr_bignum(___s_) != E_OK)         { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
    // (old_t, t) := (0, 1)
    if(clr_bignum(_o_t_) != E_OK)         { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
    if(clr_bignum(___t_) != E_OK)         { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
    if(set1b_bignum(___t_, 0UL) != E_OK)  { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };

    _PRINT_BIGNUM_(_o_r_, "[init] _o_r_");
    _PRINT_BIGNUM_(___r_, "[init] ___r_");
    _PRINT_BIGNUM_(_o_s_, "[init] _o_s_");
    _PRINT_BIGNUM_(___s_, "[init] ___s_");
    _PRINT_BIGNUM_(_o_t_, "[init] _o_t_");
    _PRINT_BIGNUM_(___t_, "[init] ___t_");
    while(cmp0_bignum(___r_) != BIGNUM_CMP_ZO)
    {
        if((_fr_ = cpy_bignum_signed_safe(_tmp_, ___r_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };

        // quotient := old_r div r
        if((_fr_ = div_bignum_with_mod(_quo_, ___r_, _o_r_, ___r_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); }
        if((_fr_ = cpy_bignum_signed_safe(_o_r_, _tmp_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
        // (old_r, r) := (r, old_r − quotient × r)
        // note: 'old_r − quotient × r' is maen that remainder
        _PRINT_BIGNUM_(_quo_, "_quo_");
        _PRINT_BIGNUM_(_o_r_, "_o_r_");
        _PRINT_BIGNUM_(___r_, "___r_");

        // (old_s, s) := (s, old_s − quotient × s)
        if((_fr_ = cpy_bignum_signed_safe(_tmp_, ___s_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
        if((_fr_ = mul_bignum_unsafe(_tmp_, _quo_, _tmp_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
        if((_fr_ = sub_bignum(_tmp_, _o_s_, _tmp_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
        if((_fr_ = cpy_bignum_signed_safe(_o_s_, ___s_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
        if((_fr_ = cpy_bignum_signed_safe(___s_, _tmp_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
        _PRINT_BIGNUM_(_o_s_, "_o_s_");
        _PRINT_BIGNUM_(___s_, "___s_");

        // (old_t, t) := (t, old_t − quotient × t)
        if((_fr_ = cpy_bignum_signed_safe(_tmp_, ___t_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
        if((_fr_ = mul_bignum_unsafe(_tmp_, _quo_, _tmp_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
        if((_fr_ = sub_bignum(_tmp_, _o_t_, _tmp_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
        if((_fr_ = cpy_bignum_signed_safe(_o_t_, ___t_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
        if((_fr_ = cpy_bignum_signed_safe(___t_, _tmp_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
        _PRINT_BIGNUM_(_o_t_, "_o_t_");
        _PRINT_BIGNUM_(___t_, "___t_");
    }

    if(s != NULL) {
        if(cpy_bignum_signed_safe(s, _o_s_) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
    }
    if(t != NULL) {
        if(cpy_bignum_signed_safe(t, _o_t_) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
    }
    _PRINT_BIGNUM_(_o_s_, "Bézout coefficients: s");
    _PRINT_BIGNUM_(_o_t_, "Bézout coefficients: t");

    if(cpy_bignum_signed_safe(r, _o_r_) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
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
    if((_fr_ = cpy_bignum_signed_safe(_o_r_, n)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
    if((_fr_ = cpy_bignum_signed_safe(_n_r_, a)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
    // t := 0;     newt := 1
    if(clr_bignum(_o_t_) != E_OK)         { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
    if(clr_bignum(_n_t_) != E_OK)         { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
    if(set1b_bignum(_n_t_, 0UL) != E_OK)  { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };

    _PRINT_BIGNUM_(_o_r_, "[init] _o_r_");
    _PRINT_BIGNUM_(_n_r_, "[init] _n_r_");
    _PRINT_BIGNUM_(_o_t_, "[init] _o_t_");
    _PRINT_BIGNUM_(_n_t_, "[init] _n_t_");
    while(cmp0_bignum(_n_r_) != BIGNUM_CMP_ZO)
    {
        if((_fr_ = cpy_bignum_signed_safe(_tmp_, _n_r_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };

        // quotient := r div newr
        if((_fr_ = div_bignum_with_mod(_quo_, _n_r_, _o_r_, _n_r_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); }
        if((_fr_ = cpy_bignum_signed_safe(_o_r_, _tmp_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
        // (r, newr) := (newr, r − quotient × newr)
        // note: 'old_r − quotient × r' is maen that remainder
        _PRINT_BIGNUM_(_quo_, "_quo_");
        _PRINT_BIGNUM_(_o_r_, "_o_r_");
        _PRINT_BIGNUM_(_n_r_, "_n_r_");

        // (t, newt) := (newt, t − quotient × newt)
        if((_fr_ = cpy_bignum_signed_safe(_tmp_, _n_t_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
        if((_fr_ = mul_bignum_unsafe(_tmp_, _quo_, _tmp_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
        if((_fr_ = sub_bignum(_tmp_, _o_t_, _tmp_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
        if((_fr_ = cpy_bignum_signed_safe(_o_t_, _n_t_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
        if((_fr_ = cpy_bignum_signed_safe(_n_t_, _tmp_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
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
            _DPRINTF_("add_bignum(t, _o_t_, n)\r\n");
            if((_fr_ = add_bignum(t, _o_t_, n)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
        }
        else if(_sign_of_o_t_ == BIGNUM_SIGN_POS)
        {
            _DPRINTF_("cpy_bignum_signed_safe(t, _o_t_)\r\n");
            if((_fr_ = cpy_bignum_signed_safe(t, _o_t_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
        }
        else
        {
            /* has error */ _DPRINTF_("%s, line:%d, _sign_of_o_t_: %d\n", __func__, __LINE__, _sign_of_o_t_);
        }
        has_value = true;
    }
    else
    {
        _DPRINTF_("clr_bignum(t)\r\n");
        if((_fr_ = clr_bignum(t)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };
        has_value = false;
    }

    if(r != NULL)   if((_fr_ = cpy_bignum_signed_safe(r, _o_r_)) != E_OK) { /* has error */ _DPRINTF_("%s, line:%d, _fr_: %d\n", __func__, __LINE__, _fr_); };

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

