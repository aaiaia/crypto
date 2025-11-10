#ifndef TEST_TOOL_H
#define TEST_TOOL_H
#include <stdio.h>

#include "common/returnType.h"
#define __RETURN_TYPE_WRAPPING__(FR_VAR, FUNC) { \
    (FR_VAR) = (FUNC); \
    if((FR_VAR) == E_HAS_NO_VALUE) \
    { \
        /* has error */ \
        printf("[\x1b[33mWARNING\x1b[0m] has no value, %s, line:%d, _fr_: %d\n", __func__, __LINE__, (FR_VAR)); \
    } \
    else if((FR_VAR) != E_OK) \
    { \
        /* has error */ \
        printf("[\x1b[31mERROR\x1b[0m] %s, line:%d, _fr_: %d\n", __func__, __LINE__, (FR_VAR)); \
    } \
}

#include "bignum/bignum.h"
#include "bignum/bignum_alu.h"
void test_print_bignum_ext(const bignum_s* p, const char* title, \
        const char* funcName, const int lineNum, \
        const bool linefeed, const size_t lfn, const bool details, const bool prefix, const bool space);
#define test_print_bignum_value_only(p) test_print_bignum_ext(p, NULL, __func__, __LINE__, false, 0UL, false, true, false)
#define test_print_bignum(p, title) test_print_bignum_ext(p, title, __func__, __LINE__, true, 0UL, false, false, true)
#define test_print_bignum_info(p, title) test_print_bignum_ext(p, title, __func__, __LINE__, true, 0UL, true, false, true)
static inline void test_print_bignum_array_ext(const bignum_t* nums, const size_t nlen, const bool linefeed, const size_t lfn, const bool prefix, const bool space)
{
    if(prefix)                      printf("0x");
    if(prefix&&space)               printf(" ");
    for(size_t i = nlen- 1u; i != ((size_t)-1); i--) {
        printf("%08x", nums[i]);
        if((i != 0u) && space)      printf(" ");
        if((((i & (lfn-1U)) == lfn) && (lfn != 0U)) && linefeed)
                                    printf("\r\n");
    }
    if(linefeed)                    printf("\r\n");
}
#define test_print_bignum_array(nums, nlen) test_print_bignum_array_ext(nums, nlen, true, 0UL, false, true)

void test_print_bignum_sign_ext(const bignum_sign_e sign, const bool lf);
#define test_print_bignum_sign(sign)  test_print_bignum_sign_ext(sign, true)

void test_print_bignum_cmp_ext(const bignum_cmp_e cmp, const bool lf);
#define test_print_bignum_cmp(cmp)  test_print_bignum_cmp_ext(cmp, true)
#endif /* TEST_TOOL_H */
