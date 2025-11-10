#ifndef BIGNUM_WNAF_H
#define BIGNUM_WNAF_H
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "common/returnType.h"
#include "bignum/bignum.h"

#define WNAF_MAX            UINT8_MAX
#define WNAF_BITS           8U
#define signMsk_WNAF(WLEN)  ((1U)<<((WLEN)-1U))
#define signExt_WNAF(WLEN)  ((WNAF_MAX)<<(WLEN))
#define bitMask_WNAF(WLEN)  ((WNAF_MAX)>>(WNAF_BITS-(WLEN)))
typedef uint8_t uwnaf;
typedef int8_t  swnaf;

typedef struct {
    size_t          bits;   // bit width length
    size_t          size;   // valid bit length
    size_t          vLen;   // valid bit length
    uwnaf           window;
    uwnaf           signMsk;
    uwnaf           signExt;
    uwnaf           wNafMsk;
    union {
        uwnaf*      ui;
        swnaf*      si;
        void*       vp;
    }wnaf;
}wnaf_s;

static inline bool chkWNAF_window_lenth(const uwnaf w)
{
    if((8U > w) && (w > 1U))// 8 > w > 1, 7~2
    {
        return true;
    }
    else
    {
        return false;
    }
}

wnaf_s* mkWNAF(const uwnaf w, const size_t bits);
int rmWNAF(wnaf_s** p);

static inline bool isNegWNAF(const uwnaf wnaf)
{
    if((wnaf>>(WNAF_BITS-1U)) == 0U)    return false;
    else                                return true;
}
static inline uwnaf absWNAF(const uwnaf wnaf)
{
    if((wnaf>>(WNAF_BITS-1U)) == 0U)    return wnaf;
    else                                return ((~wnaf)+1U);
}

/* getWNAF_preCompupte_lengh: Pre-Compute Length by Window Size(length) */
static inline uwnaf getWNAF_preCompupte_lengh(const uwnaf window)
{
    // valid w range (1 < w < 8) for uint8_t
    return (1U<<(window-2U));
}
static inline uwnaf getWNAF_index(const uwnaf v)
{
    return (absWNAF(v)>>1U);
}

void convBigNum_wNAF(wnaf_s* dst, const bignum_s* src);

#endif /* BIGNUM_WNAF_H */
