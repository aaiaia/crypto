#include <time.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <unistd.h>

#include <sys/sysinfo.h>

#include <time.h>

#include "common/util.h"
#include "bignum/bignum.h"
#include "common/returnType.h"

#include "bignum/bignum_math.h"
#include "bignum/bignum_logic.h"

#include "test/vector.h"

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

const uint8_t MES_PASS[] = "\x1b[32mPASS\x1b[0m";
const uint8_t MES_FAIL[] = "\x1b[31mFAIL\x1b[0m";
const uint8_t MES_SKIP[] = "\x1b[35mSKIP\x1b[0m";

#define TEST_ASSERT(CONDITION) {        \
    if(!(CONDITION)) {                  \
        printf("Assert: Fail\r\n");     \
        while(!(CONDITION)) sleep(1);   \
    }                                   \
}

void _memChk(void) {
    struct sysinfo info;

    sysinfo(&info);

    printf("load: %ld %ld %ld\n", info.loads[0], info.loads[1], info.loads[2]);
    printf("mem : %ld %ld %ld\n", info.totalram, info.totalram-info.freeram, info.freeram);
}

static const char* g_tTimeTitle;
static clock_t g_tic, g_toc;
static double g_pTime;
static bool g_clkOvf;
#define TICK_TIME_START(TITLE) {    \
    g_tTimeTitle = (TITLE);         \
    g_tic = clock();                \
}
#define TICK_TIME_END   {                                                                   \
    g_toc = clock();                                                                        \
    if(g_toc > g_tic) {                                                                     \
        g_clkOvf = false;                                                                   \
        g_pTime = ((double)(g_toc - g_tic)) / CLOCKS_PER_SEC;                               \
    } else {                                                                                \
        g_clkOvf = true;                                                                    \
    }                                                                                       \
    if(!g_clkOvf)   printf("Process Time(%s): %lf\r\n", g_tTimeTitle ,g_pTime);             \
    else            printf("Process Time(%s): clock tick overflow!!!\r\n", g_tTimeTitle);   \
}

#define test_print_bignum_value_only(p) test_print_bignum_ext(p, NULL, false, 0UL, false, true, false)
#define test_print_bignum(p, title) test_print_bignum_ext(p, title, true, 0UL, false, false, true)
#define test_print_bignum_array(nums, nlen) test_print_bignum_array_ext(nums, nlen, true, 0UL, false, true)
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
void test_print_bignum_ext(const bignum_s* p, const char* title, const bool linefeed, const size_t lfn, const bool details, const bool prefix, const bool space)
{
    if(title != NULL)   printf("[%s]\r\n", title);
    if(details)
    {
        printf("addr:0x%p, bignum_t size:%lu\r\n", p, sizeof(bignum_t));
        printf("p->nums:0x%p, p->lmsk:0x%x\r\np->bits=%ld, p->nlen=%ld, p->size=%ld\r\n", \
                p->nums, p->lmsk, p->bits, p->nlen, p->size);
        printf("[HEX]\r\n");
    }
    test_print_bignum_array_ext(p->nums, p->nlen, linefeed, lfn, prefix, space);
}

#define test_print_bignum_sign(sign)  test_print_bignum_sign_ext(sign, true)
void test_print_bignum_sign_ext(const bignum_sign_e sign, const bool lf)
{
    printf("bignum sign: ");
    switch(sign)
    {
        case BIGNUM_SIGN_NU:    // Not Used(Reserved)
            printf("BIGNUM_SIGN_NU");
            break;
        case BIGNUM_SIGN_POS:   // POSitive
            printf("BIGNUM_SIGN_POS");
            break;
        case BIGNUM_SIGN_NEG:   // NEGative
            printf("BIGNUM_SIGN_NEG");
            break;
        case BIGNUM_SIGN_ERR:   // ERRor
            printf("BIGNUM_SIGN_ERR");
            break;

        default:
            printf("enum case is wrong!!!");
            break;
    }
    if(lf)  printf("\n");
}

#define test_print_bignum_cmp(cmp)  test_print_bignum_cmp_ext(cmp, true)
void test_print_bignum_cmp_ext(const bignum_cmp_e cmp, const bool lf)
{
    printf("bignum cmp: ");
    switch(cmp)
    {
        case BIGNUM_CMP_NU: // Not Used(Reserved)
            printf("BIGNUM_CMP_NU");
            break;
        case BIGNUM_CMP_NZ: // Not Zero
            printf("BIGNUM_CMP_NZ");
            break;
        case BIGNUM_CMP_ZO: // ZerO
            printf("BIGNUM_CMP_ZO");
            break;
        case BIGNUM_CMP_EQ: // EQual
            printf("BIGNUM_CMP_EQ");
            break;
        case BIGNUM_CMP_GT: // Greater Than
            printf("BIGNUM_CMP_GT");
            break;
        case BIGNUM_CMP_LT: // Less Than
            printf("BIGNUM_CMP_LT");
            break;
        case BIGNUM_CMP_ER: // ERror
            printf("BIGNUM_CMP_ER");
            break;

        default:
            printf("enum case is wrong!!!");
            break;
    }
    if(lf)  printf("\n");
}

bool chkVector(uint8_t* va, uint8_t* vb, size_t size)
{
    bool chkResult = (memcmp(va, vb, size) == 0);

    printf("Test is \"%s\"\r\n", (chkResult?MES_PASS:MES_FAIL));

    return chkResult;
}

void printHex(void* data, size_t size, const char* title, size_t lf)
{
    if(data != NULL)
    {
        size_t lfe;
        if(lf == 0)
        {
            lf = 32UL;
            lfe = 31UL;
        }
        else
        {
            lfe = lf - 1UL;
        }
        printf("[%s]\r\n", (title!=NULL)?title:"unknown");
        uint8_t* p = (uint8_t*)data;
        for(size_t i = 0UL; i < size; i++)
        {
            if((i % lf) == 0UL) printf("0x%016lx: ", i);
            printf("%02x ", p[i]);
            if((i % lf) == lfe) printf("\r\n");
        }
        if((size-1UL) != lfe)   printf("\r\n");
    }
    else { /* Do Nothing */ }
}

void test_macro(void)
{
    bool cmp_result;
    bool invalid_case;
    // test: UIN_CEIL(n, x)
    {
        typedef struct {
            const uint32_t  u32_n;
            const uint32_t  u32_m;
            const uint32_t  u32_ref;
            const char*     title;
            const bool      invalid_case;
        } test_bignum_UIN_CEIL_set_t;
        const test_bignum_UIN_CEIL_set_t TEST_UINT_CEIL_set_LIST[] = {
            { 6u,         14u,        1u,         NULL,       false, }, 
            { 14u,        14u,        1u,         NULL,       false, }, 
            { 1024u,      1023u,      2u,         NULL,       false, }, 
            { 34u + 7u,   17u,        3u,         NULL,       false, }, 
            { 60u + 14u,  37u,        2u,         NULL,       false, }, 
            { 35u + 6u,   7u,         6u,         NULL,       false, }, 
        };

        uint32_t n, m;
        uint32_t ref, r;

        printf("[TEST] UIN_CEIL\r\n");
        for(size_t i = 0UL; i < sizeof(TEST_UINT_CEIL_set_LIST)/sizeof(test_bignum_UIN_CEIL_set_t); i++)
        {
            n = TEST_UINT_CEIL_set_LIST[i].u32_n;
            m = TEST_UINT_CEIL_set_LIST[i].u32_m;
            ref = TEST_UINT_CEIL_set_LIST[i].u32_ref;
            invalid_case = TEST_UINT_CEIL_set_LIST[i].invalid_case;

            r = UIN_CEIL(n, m);
            cmp_result = (ref==r);
            printf("[%lu] UIN_CEIL(): %s\r\n", i, cmp_result?(MES_PASS):(invalid_case?MES_SKIP:MES_FAIL));
            if(!cmp_result || invalid_case)
            {
                printf("[%lu] n=%u, m=%u, r=%u\r\n", i, n, m, r);
            }
            TEST_ASSERT(cmp_result || invalid_case);
        }
    }

    // test: INT_CEIL(n, x)
    {
        typedef struct {
            const int32_t   i32_n;
            const int32_t   i32_m;
            const int32_t   i32_ref;
            const char*     title;
            const bool      invalid_case;
        } test_bignum_INT_CEIL_set_t;
        const test_bignum_INT_CEIL_set_t TEST_INT_CEIL_set_LIST[] = {
            { 6,          14,         1,      NULL,       false, }, 
            { 14,         14,         1,      NULL,       false, }, 
            { 1024,       1023,       2,      NULL,       false, }, 
            { 34u + 7,    17,         3,      NULL,       false, }, 
            { 60u + 14,   37,         2,      NULL,       false, }, 
            { 35u + 6,    7,          6,      NULL,       false, }, 

        };

        int32_t n, m;
        int32_t ref, r;

        printf("[TEST] INT_CEIL\r\n");
        for(size_t i = 0UL; i < sizeof(TEST_INT_CEIL_set_LIST)/sizeof(test_bignum_INT_CEIL_set_t); i++)
        {
            n = TEST_INT_CEIL_set_LIST[i].i32_n;
            m = TEST_INT_CEIL_set_LIST[i].i32_m;
            ref = TEST_INT_CEIL_set_LIST[i].i32_ref;
            invalid_case = TEST_INT_CEIL_set_LIST[i].invalid_case;

            r = INT_CEIL(n, m);
            cmp_result = (ref==r);
            printf("[%lu] INT_CEIL(): %s\r\n", i, cmp_result?(MES_PASS):(invalid_case?MES_SKIP:MES_FAIL));
            if(!cmp_result || invalid_case)
            {
                printf("[%lu] n=%u, m=%u, r=%u\r\n", i, n, m, r);
            }
            TEST_ASSERT(cmp_result || invalid_case);
        }

    }

    // test: BITS2SIZE(bits)
    {
        typedef struct {
            const uint32_t  u32_n;
            const uint32_t  u32_ref;
            const char*     title;
            const bool      invalid_case;
        } test_bignum_BIT2SIZE_set_t;
        const test_bignum_BIT2SIZE_set_t TEST_BIT2SIZE_set_LIST[] = {
            { 6u,     1u,     NULL,   false, }, 
            { 14u,    2u,     NULL,   false, }, 
            { 1024u,  128u,   NULL,   false, }, 
            { 10240u, 1280u,  NULL,   false, }, 
            { 10241u, 1281u,  NULL,   false, }, 
            { 727u,   91u,    NULL,   false, }, 
        };

        uint32_t r, n;
        uint32_t ref;

        printf("[TEST] BITS2SIZE\r\n");
        for(size_t i = 0UL; i < sizeof(TEST_BIT2SIZE_set_LIST)/sizeof(test_bignum_BIT2SIZE_set_t); i++)
        {
            n = TEST_BIT2SIZE_set_LIST[i].u32_n;
            ref = TEST_BIT2SIZE_set_LIST[i].u32_ref;
            invalid_case = TEST_BIT2SIZE_set_LIST[i].invalid_case;

            r = BITS2SIZE(n);
            cmp_result = (ref==r);
            printf("[%lu] BITS2SIZE(): %s\r\n", i, cmp_result?(MES_PASS):(invalid_case?MES_SKIP:MES_FAIL));
            if(!cmp_result || invalid_case)
            {
                printf("[%lu] n=%u, r=%u\r\n", i, n, r);
            }
            TEST_ASSERT(cmp_result || invalid_case);
        }
    }

    // test: BIT2U16L(bits)
    {
        typedef struct {
            const uint32_t  u32_n;
            const uint32_t  u32_ref;
            const char*     title;
            const bool      invalid_case;
        } test_bignum_BIT2U16L_set_t;
        const test_bignum_BIT2U16L_set_t TEST_BIT2U16L_set_LIST[] = {
            { 6u,     1u,     NULL,   false, }, 
            { 14u,    1u,     NULL,   false, }, 
            { 1024u,  64u,    NULL,   false, }, 
            { 10240u, 640u,   NULL,   false, }, 
            { 10241u, 641u,   NULL,   false, }, 
            { 727u,   46u,    NULL,   false, }, 
        };

        uint32_t n;
        uint32_t ref, r;

        printf("[TEST] BIT2U16L\r\n");
        for(size_t i = 0UL; i < sizeof(TEST_BIT2U16L_set_LIST)/sizeof(test_bignum_BIT2U16L_set_t); i++)
        {
            n = TEST_BIT2U16L_set_LIST[i].u32_n;
            ref = TEST_BIT2U16L_set_LIST[i].u32_ref;
            invalid_case = TEST_BIT2U16L_set_LIST[i].invalid_case;

            r = BIT2U16L(n);
            cmp_result = (ref==r);
            printf("[%lu] BIT2U16L(): %s\r\n", i, cmp_result?(MES_PASS):(invalid_case?MES_SKIP:MES_FAIL));
            if(!cmp_result || invalid_case)
            {
                printf("[%lu] n=%u, r=%u\r\n", i, n, r);
            }
            TEST_ASSERT(cmp_result || invalid_case);
        }
    }

    // test: BIT2U32L(bits)
    {
        typedef struct {
            const uint32_t  u32_n;
            const uint32_t  u32_ref;
            const char*     title;
            const bool      invalid_case;
        } test_bignum_BIT2U32L_set_t;
        const test_bignum_BIT2U32L_set_t TEST_BIT2U32L_set_LIST[] = {
            { 6u,     1u,     NULL,   false, }, 
            { 14u,    1u,     NULL,   false, }, 
            { 1024u,  32u,    NULL,   false, }, 
            { 10240u, 320u,   NULL,   false, }, 
            { 10241u, 321u,   NULL,   false, }, 
            { 727u,   23u,    NULL,   false, }, 
        };

        uint32_t n;
        uint32_t ref, r;

        printf("[TEST] BIT2U32L\r\n");
        for(size_t i = 0UL; i < sizeof(TEST_BIT2U32L_set_LIST)/sizeof(test_bignum_BIT2U32L_set_t); i++)
        {
            n = TEST_BIT2U32L_set_LIST[i].u32_n;
            ref = TEST_BIT2U32L_set_LIST[i].u32_ref;
            invalid_case = TEST_BIT2U32L_set_LIST[i].invalid_case;

            r = BIT2U32L(n);
            cmp_result = (ref==r);
            printf("[%lu] BIT2U32L(): %s\r\n", i, cmp_result?(MES_PASS):(invalid_case?MES_SKIP:MES_FAIL));
            if(!cmp_result || invalid_case)
            {
                printf("[%lu] n=%u, r=%u\r\n", i, n, r);
            }
            TEST_ASSERT(cmp_result || invalid_case);
        }
    }

    // test: BIT2U64L(bits)
    {
        typedef struct {
            const uint32_t  u32_n;
            const uint32_t  u32_ref;
            const char*     title;
            const bool      invalid_case;
        } test_bignum_BIT2U64L_set_t;
        const test_bignum_BIT2U64L_set_t TEST_BIT2U64L_set_LIST[] = {
            { 6u,     1u,     NULL,   false, }, 
            { 14u,    1u,     NULL,   false, }, 
            { 1024u,  16u,    NULL,   false, }, 
            { 10240u, 160u,   NULL,   false, }, 
            { 10241u, 161u,   NULL,   false, }, 
            { 727u,   12u,    NULL,   false, }, 
        };

        uint32_t n;
        uint32_t ref, r;

        printf("[TEST] BIT2U64L\r\n");
        for(size_t i = 0UL; i < sizeof(TEST_BIT2U64L_set_LIST)/sizeof(test_bignum_BIT2U64L_set_t); i++)
        {
            n = TEST_BIT2U64L_set_LIST[i].u32_n;
            ref = TEST_BIT2U64L_set_LIST[i].u32_ref;
            invalid_case = TEST_BIT2U64L_set_LIST[i].invalid_case;

            r = BIT2U64L(n);
            cmp_result = (ref==r);
            printf("[%lu] BIT2U64L(): %s\r\n", i, cmp_result?(MES_PASS):(invalid_case?MES_SKIP:MES_FAIL));
            if(!cmp_result || invalid_case)
            {
                printf("[%lu] n=%u, r=%u\r\n", i, n, r);
            }
            TEST_ASSERT(cmp_result || invalid_case);
        }
    }

    // test: LASTBITMASK(bits, TYPE)
    {
        typedef struct {
            const uint32_t  u32_bits;
            const uint32_t  u32_ref;
            const char*     title;
            const bool      invalid_case;
        } test_bignum_LASTBITMASK_set_t;
        const test_bignum_LASTBITMASK_set_t TEST_LASTBITMASK_set_LIST[] = {
            { 127UL,      0x7FFFFFFFUL,   NULL,       false, }, 
            { 126UL,      0x3FFFFFFFUL,   NULL,       false, }, 
            { 125UL,      0x1FFFFFFFUL,   NULL,       false, }, 
            { 124UL,      0x0FFFFFFFUL,   NULL,       false, }, 
            { 105UL,      0x000001FFUL,   NULL,       false, }, 
            { 104UL,      0x000000FFUL,   NULL,       false, }, 
            { 103UL,      0x0000007FUL,   NULL,       false, }, 
            { 102UL,      0x0000003FUL,   NULL,       false, }, 
            { 101UL,      0x0000001FUL,   NULL,       false, }, 
            { 100UL,      0x0000000FUL,   NULL,       false, }, 
            { 99UL,       0x00000007UL,   NULL,       false, }, 
            { 98UL,       0x00000003UL,   NULL,       false, }, 
            { 97UL,       0x00000001UL,   NULL,       false, }, 
        };

        // uint32_t
        uint32_t u32_bits;
        uint32_t u32_ref, u32_mask;

        printf("[TEST] LASTBITMASK\r\n");
        for(size_t i = 0UL; i < sizeof(TEST_LASTBITMASK_set_LIST)/sizeof(test_bignum_LASTBITMASK_set_t); i++)
        {
            u32_bits= TEST_LASTBITMASK_set_LIST[i].u32_bits;
            u32_ref = TEST_LASTBITMASK_set_LIST[i].u32_ref;
            invalid_case = TEST_LASTBITMASK_set_LIST[i].invalid_case;

            u32_mask = LASTBITMASK(u32_bits, uint32_t);
            cmp_result = (u32_ref==u32_mask);
            printf("[%lu] LASTBITMASK(): %s\r\n", i, cmp_result?(MES_PASS):(invalid_case?MES_SKIP:MES_FAIL));
            if(!cmp_result || invalid_case)
            {
                printf("[%lu] LASTBITMASK(%u, uint32_t)=0x%08x, result: %s\r\n", i, u32_bits, u32_mask, (cmp_result)?(MES_PASS):(MES_FAIL));
            }
            TEST_ASSERT(cmp_result || invalid_case);
        }
    }
    {
        typedef struct {
            const uint64_t  u64_bits;
            const uint64_t  u64_ref;
            const char*     title;
            const bool      invalid_case;
        } test_bignum_LASTBITMASK_set_t;
        const test_bignum_LASTBITMASK_set_t TEST_LASTBITMASK_set_LIST[] = {
            { 127UL,  0x7FFFFFFFFFFFFFFFUL,   NULL,       false, }, 
            { 126UL,  0x3FFFFFFFFFFFFFFFUL,   NULL,       false, }, 
            { 125UL,  0x1FFFFFFFFFFFFFFFUL,   NULL,       false, }, 
            { 124UL,  0x0FFFFFFFFFFFFFFFUL,   NULL,       false, }, 
            { 105UL,  0x000001FFFFFFFFFFUL,   NULL,       false, }, 
            { 104UL,  0x000000FFFFFFFFFFUL,   NULL,       false, }, 
            { 103UL,  0x0000007FFFFFFFFFUL,   NULL,       false, }, 
            { 102UL,  0x0000003FFFFFFFFFUL,   NULL,       false, }, 
            { 101UL,  0x0000001FFFFFFFFFUL,   NULL,       false, }, 
            { 100UL,  0x0000000FFFFFFFFFUL,   NULL,       false, }, 
            { 99UL,   0x00000007FFFFFFFFUL,   NULL,       false, }, 
            { 98UL,   0x00000003FFFFFFFFUL,   NULL,       false, }, 
            { 97UL,   0x00000001FFFFFFFFUL,   NULL,       false, }, 
            { 69UL,   0x000000000000001FUL,   NULL,       false, }, 
            { 68UL,   0x000000000000000FUL,   NULL,       false, }, 
            { 67UL,   0x0000000000000007UL,   NULL,       false, }, 
            { 66UL,   0x0000000000000003UL,   NULL,       false, }, 
            { 65UL,   0x0000000000000001UL,   NULL,       false, }, 
        };

        // uint64_t
        uint64_t u64_bits;
        uint64_t u64_ref;
        uint64_t u64_mask;

        printf("[TEST] LASTBITMASK\r\n");
        for(size_t i = 0UL; i < sizeof(TEST_LASTBITMASK_set_LIST)/sizeof(test_bignum_LASTBITMASK_set_t); i++)
        {
            u64_bits= TEST_LASTBITMASK_set_LIST[i].u64_bits;
            u64_ref = TEST_LASTBITMASK_set_LIST[i].u64_ref;
            invalid_case = TEST_LASTBITMASK_set_LIST[i].invalid_case;

            u64_mask = LASTBITMASK(u64_bits, uint64_t);
            cmp_result = (u64_ref==u64_mask);
            printf("[%lu] LASTBITMASK(): %s\r\n", i, cmp_result?(MES_PASS):(invalid_case?MES_SKIP:MES_FAIL));
            if(!cmp_result || invalid_case)
            {
                printf("[%lu] LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", i, u64_bits, u64_mask, (cmp_result)?(MES_PASS):(MES_FAIL));
            }
            TEST_ASSERT(cmp_result || invalid_case);
        }
    }
}

void test_bignum(void)
{
#define _CMP_TRUE_  1
    bignum_s* p = (bignum_s*)NULL;

    size_t test_bits, test_size, test_nlen;
    int test_cmp_bits, test_cmp_size, test_cmp_nlen;

    {
        test_bits = 1ul;
        test_size = UIN_CEIL(test_bits, 8u);
        test_nlen = BYTE2U32L(test_size);
        p = mkBigNum(test_bits);
        test_cmp_bits = (test_bits == p->bits);
        test_cmp_size = (test_size == p->size);
        test_cmp_nlen = (test_nlen == p->nlen);
        printf("(bignum_s*):0x%p, bits:%8lu[bit]:%s, size:%6lu[Bytes]:%s, nlen:%4lu[length]:%s\r\n", p,
            p->bits, (test_cmp_bits == _CMP_TRUE_)?MES_PASS:MES_FAIL, \
            p->size, (test_cmp_size == _CMP_TRUE_)?MES_PASS:MES_FAIL, \
            p->nlen, (test_cmp_nlen == _CMP_TRUE_)?MES_PASS:MES_FAIL);
        rmBitNum(&p);

        test_bits = 8ul - 1ul;
        test_size = UIN_CEIL(test_bits, 8u);
        test_nlen = BYTE2U32L(test_size);
        p = mkBigNum(test_bits);
        test_cmp_bits = (test_bits == p->bits);
        test_cmp_size = (test_size == p->size);
        test_cmp_nlen = (test_nlen == p->nlen);
        printf("(bignum_s*):0x%p, bits:%8lu[bit]:%s, size:%6lu[Bytes]:%s, nlen:%4lu[length]:%s\r\n", p,
            p->bits, (test_cmp_bits == _CMP_TRUE_)?MES_PASS:MES_FAIL, \
            p->size, (test_cmp_size == _CMP_TRUE_)?MES_PASS:MES_FAIL, \
            p->nlen, (test_cmp_nlen == _CMP_TRUE_)?MES_PASS:MES_FAIL);
        rmBitNum(&p);

        test_bits = 8ul;
        test_size = UIN_CEIL(test_bits, 8u);
        test_nlen = BYTE2U32L(test_size);
        p = mkBigNum(test_bits);
        test_cmp_bits = (test_bits == p->bits);
        test_cmp_size = (test_size == p->size);
        test_cmp_nlen = (test_nlen == p->nlen);
        printf("(bignum_s*):0x%p, bits:%8lu[bit]:%s, size:%6lu[Bytes]:%s, nlen:%4lu[length]:%s\r\n", p,
            p->bits, (test_cmp_bits == _CMP_TRUE_)?MES_PASS:MES_FAIL, \
            p->size, (test_cmp_size == _CMP_TRUE_)?MES_PASS:MES_FAIL, \
            p->nlen, (test_cmp_nlen == _CMP_TRUE_)?MES_PASS:MES_FAIL);
        rmBitNum(&p);

        test_bits = 8ul + 1ul;
        test_size = UIN_CEIL(test_bits, 8u);
        test_nlen = BYTE2U32L(test_size);
        p = mkBigNum(test_bits);
        test_cmp_bits = (test_bits == p->bits);
        test_cmp_size = (test_size == p->size);
        test_cmp_nlen = (test_nlen == p->nlen);
        printf("(bignum_s*):0x%p, bits:%8lu[bit]:%s, size:%6lu[Bytes]:%s, nlen:%4lu[length]:%s\r\n", p,
            p->bits, (test_cmp_bits == _CMP_TRUE_)?MES_PASS:MES_FAIL, \
            p->size, (test_cmp_size == _CMP_TRUE_)?MES_PASS:MES_FAIL, \
            p->nlen, (test_cmp_nlen == _CMP_TRUE_)?MES_PASS:MES_FAIL);
        rmBitNum(&p);

        test_bits = 16ul - 1ul;
        test_size = UIN_CEIL(test_bits, 8u);
        test_nlen = BYTE2U32L(test_size);
        p = mkBigNum(test_bits);
        test_cmp_bits = (test_bits == p->bits);
        test_cmp_size = (test_size == p->size);
        test_cmp_nlen = (test_nlen == p->nlen);
        printf("(bignum_s*):0x%p, bits:%8lu[bit]:%s, size:%6lu[Bytes]:%s, nlen:%4lu[length]:%s\r\n", p,
            p->bits, (test_cmp_bits == _CMP_TRUE_)?MES_PASS:MES_FAIL, \
            p->size, (test_cmp_size == _CMP_TRUE_)?MES_PASS:MES_FAIL, \
            p->nlen, (test_cmp_nlen == _CMP_TRUE_)?MES_PASS:MES_FAIL);
        rmBitNum(&p);

        test_bits = 16ul;
        test_size = UIN_CEIL(test_bits, 8u);
        test_nlen = BYTE2U32L(test_size);
        p = mkBigNum(test_bits);
        test_cmp_bits = (test_bits == p->bits);
        test_cmp_size = (test_size == p->size);
        test_cmp_nlen = (test_nlen == p->nlen);
        printf("(bignum_s*):0x%p, bits:%8lu[bit]:%s, size:%6lu[Bytes]:%s, nlen:%4lu[length]:%s\r\n", p,
            p->bits, (test_cmp_bits == _CMP_TRUE_)?MES_PASS:MES_FAIL, \
            p->size, (test_cmp_size == _CMP_TRUE_)?MES_PASS:MES_FAIL, \
            p->nlen, (test_cmp_nlen == _CMP_TRUE_)?MES_PASS:MES_FAIL);
        rmBitNum(&p);

        test_bits = 16ul + 1ul;
        test_size = UIN_CEIL(test_bits, 8u);
        test_nlen = BYTE2U32L(test_size);
        p = mkBigNum(test_bits);
        test_cmp_bits = (test_bits == p->bits);
        test_cmp_size = (test_size == p->size);
        test_cmp_nlen = (test_nlen == p->nlen);
        printf("(bignum_s*):0x%p, bits:%8lu[bit]:%s, size:%6lu[Bytes]:%s, nlen:%4lu[length]:%s\r\n", p,
            p->bits, (test_cmp_bits == _CMP_TRUE_)?MES_PASS:MES_FAIL, \
            p->size, (test_cmp_size == _CMP_TRUE_)?MES_PASS:MES_FAIL, \
            p->nlen, (test_cmp_nlen == _CMP_TRUE_)?MES_PASS:MES_FAIL);
        rmBitNum(&p);

        test_bits = 512ul - 1ul;
        test_size = UIN_CEIL(test_bits, 8u);
        test_nlen = BYTE2U32L(test_size);
        p = mkBigNum(test_bits);
        test_cmp_bits = (test_bits == p->bits);
        test_cmp_size = (test_size == p->size);
        test_cmp_nlen = (test_nlen == p->nlen);
        printf("(bignum_s*):0x%p, bits:%8lu[bit]:%s, size:%6lu[Bytes]:%s, nlen:%4lu[length]:%s\r\n", p,
            p->bits, (test_cmp_bits == _CMP_TRUE_)?MES_PASS:MES_FAIL, \
            p->size, (test_cmp_size == _CMP_TRUE_)?MES_PASS:MES_FAIL, \
            p->nlen, (test_cmp_nlen == _CMP_TRUE_)?MES_PASS:MES_FAIL);
        rmBitNum(&p);

        test_bits = 512ul;
        test_size = UIN_CEIL(test_bits, 8u);
        test_nlen = BYTE2U32L(test_size);
        p = mkBigNum(test_bits);
        test_cmp_bits = (test_bits == p->bits);
        test_cmp_size = (test_size == p->size);
        test_cmp_nlen = (test_nlen == p->nlen);
        printf("(bignum_s*):0x%p, bits:%8lu[bit]:%s, size:%6lu[Bytes]:%s, nlen:%4lu[length]:%s\r\n", p,
            p->bits, (test_cmp_bits == _CMP_TRUE_)?MES_PASS:MES_FAIL, \
            p->size, (test_cmp_size == _CMP_TRUE_)?MES_PASS:MES_FAIL, \
            p->nlen, (test_cmp_nlen == _CMP_TRUE_)?MES_PASS:MES_FAIL);
        rmBitNum(&p);

        test_bits = 512ul + 1ul;
        test_size = UIN_CEIL(test_bits, 8u);
        test_nlen = BYTE2U32L(test_size);
        p = mkBigNum(test_bits);
        test_cmp_bits = (test_bits == p->bits);
        test_cmp_size = (test_size == p->size);
        test_cmp_nlen = (test_nlen == p->nlen);
        printf("(bignum_s*):0x%p, bits:%8lu[bit]:%s, size:%6lu[Bytes]:%s, nlen:%4lu[length]:%s\r\n", p,
            p->bits, (test_cmp_bits == _CMP_TRUE_)?MES_PASS:MES_FAIL, \
            p->size, (test_cmp_size == _CMP_TRUE_)?MES_PASS:MES_FAIL, \
            p->nlen, (test_cmp_nlen == _CMP_TRUE_)?MES_PASS:MES_FAIL);
        rmBitNum(&p);

        test_bits = 1023ul;
        test_size = UIN_CEIL(test_bits, 8u);
        test_nlen = BYTE2U32L(test_size);
        p = mkBigNum(test_bits);
        test_cmp_bits = (test_bits == p->bits);
        test_cmp_size = (test_size == p->size);
        test_cmp_nlen = (test_nlen == p->nlen);
        printf("(bignum_s*):0x%p, bits:%8lu[bit]:%s, size:%6lu[Bytes]:%s, nlen:%4lu[length]:%s\r\n", p,
            p->bits, (test_cmp_bits == _CMP_TRUE_)?MES_PASS:MES_FAIL, \
            p->size, (test_cmp_size == _CMP_TRUE_)?MES_PASS:MES_FAIL, \
            p->nlen, (test_cmp_nlen == _CMP_TRUE_)?MES_PASS:MES_FAIL);
        rmBitNum(&p);
    }

    for(uint32_t tmp_bits = 1ul; tmp_bits < 20480ul; tmp_bits++)
    {
        test_bits = tmp_bits;
        test_size = UIN_CEIL(test_bits, 8u);
        test_nlen = BYTE2U32L(test_size);
        p = mkBigNum(test_bits);
        test_cmp_bits = (test_bits == p->bits);
        test_cmp_size = (test_size == p->size);
        test_cmp_nlen = (test_nlen == p->nlen);
        printf("(bignum_s*):0x%p, bits:%8lu[bit]:%s, size:%6lu[Bytes]:%s, nlen:%4lu[length]:%s\r\n", p,
            p->bits, (test_cmp_bits == _CMP_TRUE_)?MES_PASS:MES_FAIL, \
            p->size, (test_cmp_size == _CMP_TRUE_)?MES_PASS:MES_FAIL, \
            p->nlen, (test_cmp_nlen == _CMP_TRUE_)?MES_PASS:MES_FAIL);
        rmBitNum(&p);

        if((test_cmp_bits != 0) || (test_cmp_size != 0))
        {
            printf("config:, bits:%8lu[bit], size:%6lu[Bytes], nlen:%4lu[length]\r\n", test_bits, test_size, test_nlen);
            break;
        }
        else
        {
        }
    }
#undef _CMP_TRUE_
}

void test_cpy_bignum_math_signed(void)
{
#define TEST_BIGNUM_L_BIT   128U
#define TEST_BIGNUM_S_BIT   64U
    int test_cmp;
    int test_cmp_fail;

    ReturnType fr;
    bignum_s* test_bignum_r;    // reference
    bignum_s* test_bignum_l;    // long
    bignum_s* test_bignum_s;    // short

    test_bignum_r = mkBigNum_signed(TEST_BIGNUM_L_BIT);
    test_bignum_l = mkBigNum_signed(TEST_BIGNUM_L_BIT);
    test_bignum_s = mkBigNum_signed(TEST_BIGNUM_S_BIT);

    /* Copy bignum Short to Long, Positive */
    {
        test_bignum_r->nums[0] = 0xA8ABCDEF;
        test_bignum_r->nums[1] = 0x70275bCE;
        test_bignum_r->nums[2] = 0x00000000;
        test_bignum_r->nums[3] = 0x00000000;
        memcpy(test_bignum_s->nums, test_bignum_r->nums, test_bignum_s->size);
        memset(test_bignum_l->nums, 0x0u, (test_bignum_l->size));

        TICK_TIME_START("cpy_bignum_math(long, short)");
        if(fr = cpy_bignum_math(test_bignum_l, test_bignum_s)) {
            printReturnType(fr);
        } else { /* Do nothing */ }
        TICK_TIME_END;

        test_print_bignum(test_bignum_s, "short");
        test_print_bignum(test_bignum_l, "long");

        test_cmp = memcmp(test_bignum_r->nums, test_bignum_l->nums, (test_bignum_l->size));
        printf("cpy_bignum_math() is %s\r\n", ((test_cmp == 0)?MES_PASS:MES_FAIL));
        TEST_ASSERT(test_cmp == 0);
    }
    /* Copy bignum Short to Long, Negative */
    {
        test_bignum_r->nums[0] = 0x9B25814B;
        test_bignum_r->nums[1] = 0xA8CFD59C;
        test_bignum_r->nums[2] = 0xFFFFFFFF;
        test_bignum_r->nums[3] = 0xFFFFFFFF;
        memcpy(test_bignum_s->nums, test_bignum_r->nums, test_bignum_s->size);
        memset(test_bignum_l->nums, 0x0u, (test_bignum_l->size));

        TICK_TIME_START("cpy_bignum_math(long, short)");
        if(fr = cpy_bignum_math(test_bignum_l, test_bignum_s)) {
            printReturnType(fr);
        } else { /* Do nothing */ }
        TICK_TIME_END;

        test_print_bignum(test_bignum_s, "short");
        test_print_bignum(test_bignum_l, "long");

        test_cmp = memcmp(test_bignum_r->nums, test_bignum_l->nums, (test_bignum_l->size));
        printf("cpy_bignum_math() is %s\r\n", ((test_cmp == 0)?MES_PASS:MES_FAIL));
        TEST_ASSERT(test_cmp == 0);
    }

    /* Copy bignum Long to Short, Positive */
    {
        test_bignum_r->nums[0] = 0xA8ABCDEF;
        test_bignum_r->nums[1] = 0x70275bCE;
        test_bignum_r->nums[2] = 0x00000000;
        test_bignum_r->nums[3] = 0x00000000;
        memcpy(test_bignum_l->nums, test_bignum_r->nums, test_bignum_l->size);
        memset(test_bignum_s->nums, 0x0u, (test_bignum_s->size));

        TICK_TIME_START("cpy_bignum_math(short, long)");
        if(fr = cpy_bignum_math(test_bignum_s, test_bignum_l)) {
            printReturnType(fr);
        } else { /* Do nothing */ }
        TICK_TIME_END;

        test_print_bignum(test_bignum_l, "long");
        test_print_bignum(test_bignum_s, "short");

        test_cmp = memcmp(test_bignum_r->nums, test_bignum_l->nums, (test_bignum_l->size));
        printf("cpy_bignum_math() is %s\r\n", ((test_cmp == 0)?MES_PASS:MES_FAIL));
        TEST_ASSERT(test_cmp == 0);
    }
    /* Copy bignum Long to Short, Negative */
    {
        test_bignum_r->nums[0] = 0x9B25814B;
        test_bignum_r->nums[1] = 0xA8CFD59C;
        test_bignum_r->nums[2] = 0xFFFFFFFF;
        test_bignum_r->nums[3] = 0xFFFFFFFF;
        memcpy(test_bignum_l->nums, test_bignum_r->nums, test_bignum_l->size);
        memset(test_bignum_s->nums, 0x0u, (test_bignum_s->size));

        TICK_TIME_START("cpy_bignum_math(short, long)");
        if(fr = cpy_bignum_math(test_bignum_s, test_bignum_l)) {
            printReturnType(fr);
        } else { /* Do nothing */ }
        TICK_TIME_END;

        test_print_bignum(test_bignum_l, "long");
        test_print_bignum(test_bignum_s, "short");

        test_cmp = memcmp(test_bignum_r->nums, test_bignum_l->nums, (test_bignum_l->size));
        printf("cpy_bignum_math() is %s\r\n", ((test_cmp == 0)?MES_PASS:MES_FAIL));
        TEST_ASSERT(test_cmp == 0);
    }

    /* FAIL CASE */
    /* Copy bignum Long to Short, Positive */
    {
        test_bignum_r->nums[0] = 0xA8ABCDEF;
        test_bignum_r->nums[1] = 0x70275bCE;
        test_bignum_r->nums[2] = 0x783BC0A0;
        test_bignum_r->nums[3] = 0x00000000;
        memcpy(test_bignum_l->nums, test_bignum_r->nums, test_bignum_l->size);
        memset(test_bignum_s->nums, 0x0u, (test_bignum_s->size));

        TICK_TIME_START("cpy_bignum_math(short, long)");
        if(fr = cpy_bignum_math(test_bignum_s, test_bignum_l)) {
            printReturnType(fr);
        } else { /* Do nothing */ }
        TICK_TIME_END;

        test_print_bignum(test_bignum_l, "long");
        test_print_bignum(test_bignum_s, "short");

        test_cmp_fail = memcmp(test_bignum_r->nums, test_bignum_s->nums, (test_bignum_s->size));
        printf("%sFAIL CASE%s: ", ANSI_COLOR_MAGENTA, ANSI_COLOR_RESET);
        printf("cpy_bignum_math() is %s\r\n", ((test_cmp_fail != 0)?MES_PASS:MES_FAIL));
        TEST_ASSERT(test_cmp_fail != 0);
    }
    /* FAIL CASE */
    /* Copy bignum Long to Short, Positive */
    {
        test_bignum_r->nums[0] = 0xA8ABCDEF;
        test_bignum_r->nums[1] = 0x70275bCE;
        test_bignum_r->nums[2] = 0x00000000;
        test_bignum_r->nums[3] = 0x783BC0A0;
        memcpy(test_bignum_l->nums, test_bignum_r->nums, test_bignum_l->size);
        memset(test_bignum_s->nums, 0x0u, (test_bignum_s->size));

        TICK_TIME_START("cpy_bignum_math(short, long)");
        if(fr = cpy_bignum_math(test_bignum_s, test_bignum_l)) {
            printReturnType(fr);
        } else { /* Do nothing */ }
        TICK_TIME_END;

        test_print_bignum(test_bignum_l, "long");
        test_print_bignum(test_bignum_s, "short");

        test_cmp_fail = memcmp(test_bignum_r->nums, test_bignum_s->nums, (test_bignum_s->size));
        printf("%sFAIL CASE%s: ", ANSI_COLOR_MAGENTA, ANSI_COLOR_RESET);
        printf("cpy_bignum_math() is %s\r\n", ((test_cmp_fail != 0)?MES_PASS:MES_FAIL));
        TEST_ASSERT(test_cmp_fail != 0);
    }
    /* FAIL CASE */
    /* Copy bignum Long to Short, Negative */
    {
        test_bignum_r->nums[0] = 0x9B25814B;
        test_bignum_r->nums[1] = 0xA8CFD59C;
        test_bignum_r->nums[2] = 0x7FFFFFFF;
        test_bignum_r->nums[3] = 0xFFFFFFFF;
        memcpy(test_bignum_l->nums, test_bignum_r->nums, test_bignum_l->size);
        memset(test_bignum_s->nums, 0x0u, (test_bignum_s->size));

        TICK_TIME_START("cpy_bignum_math(short, long)");
        if(fr = cpy_bignum_math(test_bignum_s, test_bignum_l)) {
            printReturnType(fr);
        } else { /* Do nothing */ }
        TICK_TIME_END;

        test_print_bignum(test_bignum_l, "long");
        test_print_bignum(test_bignum_s, "short");

        test_cmp_fail = memcmp(test_bignum_r->nums, test_bignum_s->nums, (test_bignum_s->size));
        printf("%sFAIL CASE%s: ", ANSI_COLOR_MAGENTA, ANSI_COLOR_RESET);
        printf("cpy_bignum_math() is %s\r\n", ((test_cmp_fail != 0)?MES_PASS:MES_FAIL));
        TEST_ASSERT(test_cmp_fail != 0);
    }
    /* FAIL CASE */
    /* Copy bignum Long to Short, Negative */
    {
        test_bignum_r->nums[0] = 0x9B25814B;
        test_bignum_r->nums[1] = 0xA8CFD59C;
        test_bignum_r->nums[2] = 0xFFFFFFFF;
        test_bignum_r->nums[3] = 0x7FFFFFFF;
        memcpy(test_bignum_l->nums, test_bignum_r->nums, test_bignum_l->size);
        memset(test_bignum_s->nums, 0x0u, (test_bignum_s->size));

        TICK_TIME_START("cpy_bignum_math(short, long)");
        if(fr = cpy_bignum_math(test_bignum_s, test_bignum_l)) {
            printReturnType(fr);
        } else { /* Do nothing */ }
        TICK_TIME_END;

        test_print_bignum(test_bignum_l, "long");
        test_print_bignum(test_bignum_s, "short");

        test_cmp_fail = memcmp(test_bignum_r->nums, test_bignum_s->nums, (test_bignum_s->size));
        printf("%sFAIL CASE%s: ", ANSI_COLOR_MAGENTA, ANSI_COLOR_RESET);
        printf("cpy_bignum_math() is %s\r\n", ((test_cmp_fail != 0)?MES_PASS:MES_FAIL));
        TEST_ASSERT(test_cmp_fail != 0);
    }

    rmBitNum(&test_bignum_r);
    rmBitNum(&test_bignum_l);
    rmBitNum(&test_bignum_s);
#undef TEST_BIGNUM_L_BIT
#undef TEST_BIGNUM_S_BIT
}

void test_cpy_bignum_math_unsigned(void)
{
#define TEST_BIGNUM_L_BIT   128U
#define TEST_BIGNUM_S_BIT   64U
    int test_cmp;
    int test_cmp_fail;

    ReturnType fr;
    bignum_s* test_bignum_r;    // reference
    bignum_s* test_bignum_l;    // long
    bignum_s* test_bignum_s;    // short

    test_bignum_r = mkBigNum_unsigned(TEST_BIGNUM_L_BIT);
    test_bignum_l = mkBigNum_unsigned(TEST_BIGNUM_L_BIT);
    test_bignum_s = mkBigNum_unsigned(TEST_BIGNUM_S_BIT);

    /* Copy bignum Short to Long */
    {
        test_bignum_r->nums[0] = 0xA8ABCDEF;
        test_bignum_r->nums[1] = 0x70275bCE;
        test_bignum_r->nums[2] = 0x00000000;
        test_bignum_r->nums[3] = 0x00000000;
        memcpy(test_bignum_s->nums, test_bignum_r->nums, test_bignum_s->size);
        memset(test_bignum_l->nums, 0x0u, (test_bignum_l->size));

        TICK_TIME_START("cpy_bignum_math(long, short)");
        if(fr = cpy_bignum_math(test_bignum_l, test_bignum_s)) {
            printReturnType(fr);
        } else { /* Do nothing */ }
        TICK_TIME_END;

        test_print_bignum(test_bignum_s, "short");
        test_print_bignum(test_bignum_l, "long");

        test_cmp = memcmp(test_bignum_r->nums, test_bignum_l->nums, (test_bignum_l->size));
        printf("cpy_bignum_math() is %s\r\n", ((test_cmp == 0)?MES_PASS:MES_FAIL));
        TEST_ASSERT(test_cmp == 0);
    }
    /* Copy bignum Short to Long */
    {
        test_bignum_r->nums[0] = 0x9B25814B;
        test_bignum_r->nums[1] = 0xA8CFD59C;
        test_bignum_r->nums[2] = 0x00000000;
        test_bignum_r->nums[3] = 0x00000000;
        memcpy(test_bignum_s->nums, test_bignum_r->nums, test_bignum_s->size);
        memset(test_bignum_l->nums, 0x0u, (test_bignum_l->size));

        TICK_TIME_START("cpy_bignum_math(long, short)");
        if(fr = cpy_bignum_math(test_bignum_l, test_bignum_s)) {
            printReturnType(fr);
        } else { /* Do nothing */ }
        TICK_TIME_END;

        test_print_bignum(test_bignum_s, "short");
        test_print_bignum(test_bignum_l, "long");

        test_cmp = memcmp(test_bignum_r->nums, test_bignum_l->nums, (test_bignum_l->size));
        printf("cpy_bignum_math() is %s\r\n", ((test_cmp == 0)?MES_PASS:MES_FAIL));
        TEST_ASSERT(test_cmp == 0);
    }

    /* Copy bignum Long to Short */
    {
        test_bignum_r->nums[0] = 0xA8ABCDEF;
        test_bignum_r->nums[1] = 0x70275bCE;
        test_bignum_r->nums[2] = 0x00000000;
        test_bignum_r->nums[3] = 0x00000000;
        memcpy(test_bignum_l->nums, test_bignum_r->nums, test_bignum_l->size);
        memset(test_bignum_s->nums, 0x0u, (test_bignum_s->size));

        TICK_TIME_START("cpy_bignum_math(short, long)");
        if(fr = cpy_bignum_math(test_bignum_s, test_bignum_l)) {
            printReturnType(fr);
        } else { /* Do nothing */ }
        TICK_TIME_END;

        test_print_bignum(test_bignum_l, "long");
        test_print_bignum(test_bignum_s, "short");

        test_cmp = memcmp(test_bignum_r->nums, test_bignum_l->nums, (test_bignum_l->size));
        printf("cpy_bignum_math() is %s\r\n", ((test_cmp == 0)?MES_PASS:MES_FAIL));
        TEST_ASSERT(test_cmp == 0);
    }
    /* FAIL CASE */
    /* Copy bignum Long to Short */
    {
        test_bignum_r->nums[0] = 0x9B25814B;
        test_bignum_r->nums[1] = 0xA8CFD59C;
        test_bignum_r->nums[2] = 0xFFFFFFFF;
        test_bignum_r->nums[3] = 0xFFFFFFFF;
        memcpy(test_bignum_l->nums, test_bignum_r->nums, test_bignum_l->size);
        memset(test_bignum_s->nums, 0x0u, (test_bignum_s->size));

        TICK_TIME_START("cpy_bignum_math(short, long)");
        if(fr = cpy_bignum_math(test_bignum_s, test_bignum_l)) {
            printReturnType(fr);
        } else { /* Do nothing */ }
        TICK_TIME_END;

        test_print_bignum(test_bignum_l, "long");
        test_print_bignum(test_bignum_s, "short");

        test_cmp_fail = memcmp(test_bignum_r->nums, test_bignum_s->nums, (test_bignum_s->size));
        printf("%sFAIL CASE%s: ", ANSI_COLOR_MAGENTA, ANSI_COLOR_RESET);
        printf("cpy_bignum_math() is %s\r\n", ((test_cmp_fail != 0)?MES_PASS:MES_FAIL));
        TEST_ASSERT(test_cmp_fail != 0);
    }

    /* FAIL CASE */
    /* Copy bignum Long to Short */
    {
        test_bignum_r->nums[0] = 0xA8ABCDEF;
        test_bignum_r->nums[1] = 0x70275bCE;
        test_bignum_r->nums[2] = 0x783BC0A0;
        test_bignum_r->nums[3] = 0x00000000;
        memcpy(test_bignum_l->nums, test_bignum_r->nums, test_bignum_l->size);
        memset(test_bignum_s->nums, 0x0u, (test_bignum_s->size));

        TICK_TIME_START("cpy_bignum_math(short, long)");
        if(fr = cpy_bignum_math(test_bignum_s, test_bignum_l)) {
            printReturnType(fr);
        } else { /* Do nothing */ }
        TICK_TIME_END;

        test_print_bignum(test_bignum_l, "long");
        test_print_bignum(test_bignum_s, "short");

        test_cmp_fail = memcmp(test_bignum_r->nums, test_bignum_s->nums, (test_bignum_s->size));
        printf("%sFAIL CASE%s: ", ANSI_COLOR_MAGENTA, ANSI_COLOR_RESET);
        printf("cpy_bignum_math() is %s\r\n", ((test_cmp_fail != 0)?MES_PASS:MES_FAIL));
        TEST_ASSERT(test_cmp_fail != 0);
    }
    /* FAIL CASE */
    /* Copy bignum Long to Short */
    {
        test_bignum_r->nums[0] = 0xA8ABCDEF;
        test_bignum_r->nums[1] = 0x70275bCE;
        test_bignum_r->nums[2] = 0x00000000;
        test_bignum_r->nums[3] = 0x783BC0A0;
        memcpy(test_bignum_l->nums, test_bignum_r->nums, test_bignum_l->size);
        memset(test_bignum_s->nums, 0x0u, (test_bignum_s->size));

        TICK_TIME_START("cpy_bignum_math(short, long)");
        if(fr = cpy_bignum_math(test_bignum_s, test_bignum_l)) {
            printReturnType(fr);
        } else { /* Do nothing */ }
        TICK_TIME_END;

        test_print_bignum(test_bignum_l, "long");
        test_print_bignum(test_bignum_s, "short");

        test_cmp_fail = memcmp(test_bignum_r->nums, test_bignum_s->nums, (test_bignum_s->size));
        printf("%sFAIL CASE%s: ", ANSI_COLOR_MAGENTA, ANSI_COLOR_RESET);
        printf("cpy_bignum_math() is %s\r\n", ((test_cmp_fail != 0)?MES_PASS:MES_FAIL));
        TEST_ASSERT(test_cmp_fail != 0);
    }
    /* FAIL CASE */
    /* Copy bignum Long to Short */
    {
        test_bignum_r->nums[0] = 0x9B25814B;
        test_bignum_r->nums[1] = 0xA8CFD59C;
        test_bignum_r->nums[2] = 0x7FFFFFFF;
        test_bignum_r->nums[3] = 0xFFFFFFFF;
        memcpy(test_bignum_l->nums, test_bignum_r->nums, test_bignum_l->size);
        memset(test_bignum_s->nums, 0x0u, (test_bignum_s->size));

        TICK_TIME_START("cpy_bignum_math(short, long)");
        if(fr = cpy_bignum_math(test_bignum_s, test_bignum_l)) {
            printReturnType(fr);
        } else { /* Do nothing */ }
        TICK_TIME_END;

        test_print_bignum(test_bignum_l, "long");
        test_print_bignum(test_bignum_s, "short");

        test_cmp_fail = memcmp(test_bignum_r->nums, test_bignum_s->nums, (test_bignum_s->size));
        printf("%sFAIL CASE%s: ", ANSI_COLOR_MAGENTA, ANSI_COLOR_RESET);
        printf("cpy_bignum_math() is %s\r\n", ((test_cmp_fail != 0)?MES_PASS:MES_FAIL));
        TEST_ASSERT(test_cmp_fail != 0);
    }
    /* FAIL CASE */
    /* Copy bignum Long to Short */
    {
        test_bignum_r->nums[0] = 0x9B25814B;
        test_bignum_r->nums[1] = 0xA8CFD59C;
        test_bignum_r->nums[2] = 0xFFFFFFFF;
        test_bignum_r->nums[3] = 0x7FFFFFFF;
        memcpy(test_bignum_l->nums, test_bignum_r->nums, test_bignum_l->size);
        memset(test_bignum_s->nums, 0x0u, (test_bignum_s->size));

        TICK_TIME_START("cpy_bignum_math(short, long)");
        if(fr = cpy_bignum_math(test_bignum_s, test_bignum_l)) {
            printReturnType(fr);
        } else { /* Do nothing */ }
        TICK_TIME_END;

        test_print_bignum(test_bignum_l, "long");
        test_print_bignum(test_bignum_s, "short");

        test_cmp_fail = memcmp(test_bignum_r->nums, test_bignum_s->nums, (test_bignum_s->size));
        printf("%sFAIL CASE%s: ", ANSI_COLOR_MAGENTA, ANSI_COLOR_RESET);
        printf("cpy_bignum_math() is %s\r\n", ((test_cmp_fail != 0)?MES_PASS:MES_FAIL));
        TEST_ASSERT(test_cmp_fail != 0);
    }

    rmBitNum(&test_bignum_r);
    rmBitNum(&test_bignum_l);
    rmBitNum(&test_bignum_s);
#undef TEST_BIGNUM_L_BIT
#undef TEST_BIGNUM_S_BIT
}

const bignum_t TEST_BIGNUM_256b_signed__zero[] = { 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, };
const bignum_t TEST_BIGNUM_256b_signed____p1[] = { 
    0x00000001U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, };
const bignum_t TEST_BIGNUM_256b_signed____m1[] = { 
    0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, };
const bignum_t TEST_BIGNUM_256b_signed____m2[] = { 
    0xFFFFFFFEU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, };
const bignum_t TEST_BIGNUM_256b_signed____m3[] = { 
    0xFFFFFFFDU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, };
const bignum_t TEST_BIGNUM_256b_signed_max__[] = { 
    0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x7FFFFFFFU, };
const bignum_t TEST_BIGNUM_256b_signed_minp1[] = { 
    0x00000001U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x80000000U, };
const bignum_t TEST_BIGNUM_256b_signed_min__[] = { 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x80000000U, };

const bignum_t TEST_BIGNUM_256b_RandomNum_______A_0[] = { 0x90ABCDEFU, 0x12345678U, 0x90ABCDEFU, 0x12345678U, 0x90ABCDEFU, 0x12345678U, 0x90ABCDEFU, 0x12345678U, };
const bignum_t TEST_BIGNUM_256b_RandomNum_______B_0[] = { 0x76543210U, 0xFEDCBA98U, 0x76543210U, 0xFEDCBA98U, 0x76543210U, 0xFEDCBA98U, 0x76543210U, 0xFEDCBA98U, };
const bignum_t TEST_BIGNUM_256b_RandomNum_Add_A_B_0[] = { 0x06ffffffU, 0x11111111U, 0x07000000U, 0x11111111U, 0x07000000U, 0x11111111U, 0x07000000U, 0x11111111U, };

void test_twos_bignum_256b(void)
{
#define TEST_BIGNUM_TWOS_BIT  256U // 32Bytes, 32bits 8ea
    typedef struct {
        const bignum_t* nums___a;
        const bignum_t* nums_ref;
        const char*     title;
        const bool      invalid_case;
    } test_bignum_twos_bignum_set_t;
    const test_bignum_twos_bignum_set_t TEST_BIGNUM_twos_bignum_set_LIST[] = {
        {
            TEST_BIGNUM_256b_signed____p1, TEST_BIGNUM_256b_signed____m1, 
            "2's compliment test, 1 -> -1", false, 
        },
        {
            TEST_BIGNUM_256b_signed____m1, TEST_BIGNUM_256b_signed____p1, 
            "2's compliment test, -1 -> 1", false, 
        },
        {
            TEST_BIGNUM_256b_signed_max__, TEST_BIGNUM_256b_signed_minp1, 
            "2's compliment test, signed 256bit MAX -> MIN+1", false, 
        },
        {
            TEST_BIGNUM_256b_signed_minp1, TEST_BIGNUM_256b_signed_max__, 
            "2's compliment test, signed 256bit MIN+1 -> MAX", false, 
        },
        {
            TEST_BIGNUM_256b_signed_min__, TEST_BIGNUM_256b_signed_min__,
            "2's compliment test, signed 256bit MIN -> MIN", true, 
        },
    };

    bool cmp_result;
    bool intentional_invalid;

    ReturnType fr;
    bignum_s* test___a;
    bignum_s* test_ref;
    bignum_s* test_tmp;

    test___a = mkBigNum(TEST_BIGNUM_TWOS_BIT);
    test_ref = mkBigNum(TEST_BIGNUM_TWOS_BIT);
    test_tmp = mkBigNum(TEST_BIGNUM_TWOS_BIT);

    for(size_t i = 0UL; i < sizeof(TEST_BIGNUM_twos_bignum_set_LIST)/sizeof(test_bignum_twos_bignum_set_t); i++)
    {
        (void)memcpy(test___a->nums, TEST_BIGNUM_twos_bignum_set_LIST[i].nums___a, test___a->size);
        (void)memcpy(test_ref->nums, TEST_BIGNUM_twos_bignum_set_LIST[i].nums_ref, test_ref->size);
        for(size_t x = 0UL; x < test_tmp->nlen; x++)    test_tmp->nums[x] = ~test_ref->nums[x];
        intentional_invalid = TEST_BIGNUM_twos_bignum_set_LIST[i].invalid_case;

        TICK_TIME_START("twos_bignum");
        if(fr = twos_bignum(test_tmp, test___a)) {
            printReturnType(fr);
        } else { /* Do nothing */ }
        TICK_TIME_END;

        cmp_result = (memcmp(test_ref->nums, test_tmp->nums, (test_ref->size)) == 0);
        if((!cmp_result))
        {
            test_print_bignum(test___a, "test___a");
            test_print_bignum(test_tmp, "test_tmp");
            test_print_bignum(test_ref, "test_ref");
        }
        printf("[%lu] twos_bignum() is %s\r\n", i, ((cmp_result)?(MES_PASS):(intentional_invalid?MES_SKIP:MES_FAIL)));
        TEST_ASSERT(cmp_result || (intentional_invalid));
    }

    rmBitNum(&test___a);
    rmBitNum(&test_ref);
    rmBitNum(&test_tmp);
#undef TEST_BIGNUM_TWOS_BIT
}

void test_abs_bignum_signed_256b(void)
{
#define TEST_BIGNUM_ABS_BIT  256U // 32Bytes, 32bits 8ea
    typedef struct {
        const bignum_t* nums___a;
        const bignum_t* nums_ref;
        const char*     title;
        const bool      invalid_case;
    } test_bignum_abs_bignum_set_t;
    const test_bignum_abs_bignum_set_t TEST_BIGNUM_abs_bignum_set_LIST[] = {
        {
            TEST_BIGNUM_256b_signed____p1, TEST_BIGNUM_256b_signed____p1, 
            "absolute test, 1 -> 1", 
            false, 
        },
        {
            TEST_BIGNUM_256b_signed____m1, TEST_BIGNUM_256b_signed____p1, 
            "absolute test, -1 -> 1", 
            false, 
        },
        {
            TEST_BIGNUM_256b_signed_max__, TEST_BIGNUM_256b_signed_max__, 
            "absolute test, signed 256bit MAX -> MAX", 
            false, 
        },
        {
            TEST_BIGNUM_256b_signed_minp1, TEST_BIGNUM_256b_signed_max__, 
            "absolute test, signed 256bit MIN+1 -> MAX", 
            false, 
        },
        {
            TEST_BIGNUM_256b_signed_min__, TEST_BIGNUM_256b_signed_min__,
            "absolute test, signed 256bit MIN -> MIN", 
            true, 
        },
    };

    bool cmp_result;
    bool intentional_invalid;

    ReturnType fr;
    bignum_s* test___a;
    bignum_s* test_ref;
    bignum_s* test_tmp;

    test___a = mkBigNum_signed(TEST_BIGNUM_ABS_BIT);
    test_ref = mkBigNum_signed(TEST_BIGNUM_ABS_BIT);
    test_tmp = mkBigNum_signed(TEST_BIGNUM_ABS_BIT);

    for(size_t i = 0UL; i < sizeof(TEST_BIGNUM_abs_bignum_set_LIST)/sizeof(test_bignum_abs_bignum_set_t); i++)
    {
        (void)memcpy(test___a->nums, TEST_BIGNUM_abs_bignum_set_LIST[i].nums___a, test___a->size);
        (void)memcpy(test_ref->nums, TEST_BIGNUM_abs_bignum_set_LIST[i].nums_ref, test_ref->size);
        for(size_t x = 0UL; x < test_ref->nlen; x++)    test_tmp->nums[x] = ~test_ref->nums[x];
        intentional_invalid = TEST_BIGNUM_abs_bignum_set_LIST[i].invalid_case;

        TICK_TIME_START("abs_bignum");
        if(fr = abs_bignum(test_tmp, test___a)) {
            printReturnType(fr);
        } else { /* Do nothing */ }
        TICK_TIME_END;

        cmp_result = (memcmp(test_ref->nums, test_tmp->nums, (test_ref->size)) == 0);
        if((!cmp_result))
        {
            test_print_bignum(test___a, "test___a");
            test_print_bignum(test_tmp, "test_tmp");
            test_print_bignum(test_ref, "test_ref");
        }

        printf("abs_bignum() is %s\r\n", (cmp_result?MES_PASS:(MES_FAIL)));
        TEST_ASSERT((cmp_result) || (intentional_invalid));
    }

    rmBitNum(&test___a);
    rmBitNum(&test_ref);
    rmBitNum(&test_tmp);
#undef TEST_BIGNUM_ABS_BIT
}

void test_sign_bignum_256b(void)
{
#define TEST_BIGNUM_SIGN_BIT  256U // 32Bytes, 32bits 8ea
    int cmp_result;

    ReturnType fr;
    bignum_s* test_bignum;
    bignum_sign_e test_sign_ref;
    bignum_sign_e test_sign;

    /* type: unsigned int, significant bit is 1'b0 */
    {
        test_bignum = mkBigNum_unsigned(TEST_BIGNUM_SIGN_BIT);
        test_bignum->nums[test_bignum->nlen-1U] = 0U;
        test_sign_ref = BIGNUM_SIGN_POS;

        TICK_TIME_START("sign_bignum, unsigned int, significant bit is 1'b0");
        test_sign = sign_bignum(test_bignum);
        TICK_TIME_END;

        cmp_result = (test_sign == test_sign_ref);
        if(!cmp_result)
        {
            test_print_bignum(test_bignum, "bignum");
            test_print_bignum_sign(test_sign);
        }
        printf("sign_bignum(): %s\r\n", ((cmp_result)?(MES_PASS):(MES_FAIL)));
        TEST_ASSERT(cmp_result);

        rmBitNum(&test_bignum);
    }

    /* type: unsigned int, significant bit is 1'b1 */
    {
        test_bignum = mkBigNum_unsigned(TEST_BIGNUM_SIGN_BIT);
        test_bignum->nums[test_bignum->nlen-1U] = BIGNUM_MAX;
        test_sign_ref = BIGNUM_SIGN_POS;

        TICK_TIME_START("sign_bignum, unsigned int, significant bit is 1'b1");
        test_sign = sign_bignum(test_bignum);
        TICK_TIME_END;

        cmp_result = (test_sign == test_sign_ref);
        if(!cmp_result)
        {
            test_print_bignum(test_bignum, "bignum");
            test_print_bignum_sign(test_sign);
        }
        printf("sign_bignum(): %s\r\n", ((cmp_result)?(MES_PASS):(MES_FAIL)));
        TEST_ASSERT(cmp_result);

        rmBitNum(&test_bignum);
    }

    /* type: signed int, significant bit is 1'b0 */
    {
        test_bignum = mkBigNum_signed(TEST_BIGNUM_SIGN_BIT);
        test_bignum->nums[test_bignum->nlen-1U] = 0U;
        test_sign_ref = BIGNUM_SIGN_POS;

        TICK_TIME_START("sign_bignum, signed int, significant bit is 1'b0");
        test_sign = sign_bignum(test_bignum);
        TICK_TIME_END;

        cmp_result = (test_sign == test_sign_ref);
        if(!cmp_result)
        {
            test_print_bignum(test_bignum, "bignum");
            test_print_bignum_sign(test_sign);
        }
        printf("sign_bignum(): %s\r\n", ((cmp_result)?(MES_PASS):(MES_FAIL)));
        TEST_ASSERT(cmp_result);

        rmBitNum(&test_bignum);
    }

    /* type: unsigned int, significant bit is 1'b1 */
    {
        test_bignum = mkBigNum_signed(TEST_BIGNUM_SIGN_BIT);
        test_bignum->nums[test_bignum->nlen-1U] = BIGNUM_MAX;
        test_sign_ref = BIGNUM_SIGN_NEG;

        TICK_TIME_START("sign_bignum, signed int, significant bit is 1'b1");
        test_sign = sign_bignum(test_bignum);
        TICK_TIME_END;

        cmp_result = (test_sign == test_sign_ref);
        if(!cmp_result)
        {
            test_print_bignum(test_bignum, "bignum");
            test_print_bignum_sign(test_sign);
        }
        printf("sign_bignum(): %s\r\n", ((cmp_result)?(MES_PASS):(MES_FAIL)));
        TEST_ASSERT(cmp_result);

        rmBitNum(&test_bignum);
    }

#undef TEST_BIGNUM_SIGN_BIT
}

void test_cmp0_bignum_256b(void)
{
#define TEST_BIGNUM_CMP0_BIT  256U // 32Bytes, 32bits 8ea
    typedef struct {
        const bignum_t*     test___a;
        const bignum_cmp_e  cmp__ref;
        const char*     title;
        const bool      invalid_case;
    } test_bignum_cmp0_bignum_set_t;
    const test_bignum_cmp0_bignum_set_t TEST_BIGNUM_cmp0_bignum_set_LIST[] = {
        {
            TEST_BIGNUM_256b_signed__zero, BIGNUM_CMP_ZO,
            "compare with zero test, 0", false, 
        },
        {
            TEST_BIGNUM_256b_signed____p1, BIGNUM_CMP_NZ,
            "compare with zero test, 1", false, 
        },
        {
            TEST_BIGNUM_256b_signed_max__, BIGNUM_CMP_NZ,
            "compare with zero test, MAX", false, 
        },
        {
            TEST_BIGNUM_256b_signed_minp1, BIGNUM_CMP_NZ,
            "compare with zero test, MIN+1", false, 
        },
        {
            TEST_BIGNUM_256b_signed_min__, BIGNUM_CMP_NZ,
            "compare with zero test, MIN", false, 
        },
    };

    bool cmp_result;
    bool intentional_invalid;

    ReturnType fr;
    bignum_s* test___a;
    bignum_cmp_e test_bignum_cmp        = BIGNUM_CMP_NU;
    bignum_cmp_e test_bignum_cmp_ref;

    test___a = mkBigNum(TEST_BIGNUM_CMP0_BIT);

    for(size_t i = 0UL; i < sizeof(TEST_BIGNUM_cmp0_bignum_set_LIST)/sizeof(test_bignum_cmp0_bignum_set_t); i++)
    {
        memcpy(test___a->nums, TEST_BIGNUM_cmp0_bignum_set_LIST[i].test___a, test___a->size);
        test_bignum_cmp_ref = TEST_BIGNUM_cmp0_bignum_set_LIST[i].cmp__ref;
        test_bignum_cmp = BIGNUM_CMP_NU;
        intentional_invalid = TEST_BIGNUM_cmp0_bignum_set_LIST[i].invalid_case;

        TICK_TIME_START("cmp0_bignum");
        test_bignum_cmp = cmp0_bignum(test___a);
        TICK_TIME_END;

        cmp_result = (test_bignum_cmp == test_bignum_cmp_ref);
        if((!cmp_result))
        {
            test_print_bignum(test___a, "test___a");
            test_print_bignum_cmp(test_bignum_cmp);
        }
        printf("cmp0_bignum() is NON ZERO(NZ): %s\r\n", ((cmp_result)?(MES_PASS):(intentional_invalid?MES_SKIP:MES_FAIL)));
        TEST_ASSERT((cmp_result) || (intentional_invalid));
    }

    rmBitNum(&test___a);
#undef TEST_BIGNUM_CMP0_BIT
}

/*
 * int32_t, INT32_MAX, INT32_MIN
 * (INT32_MAX/2)-2 - (INT32_MIN/2)+3 : 0x7ffffffa
 * (INT32_MIN/2)+3 - (INT32_MAX/2)-2 : 0x80000006
 * (INT32_MAX/2)-1 - (INT32_MIN/2)+2 : 0x7ffffffc
 * (INT32_MIN/2)+2 - (INT32_MAX/2)-1 : 0x80000004
 * (INT32_MAX/2)-0 - (INT32_MIN/2)+1 : 0x7ffffffe
 * (INT32_MIN/2)+1 - (INT32_MAX/2)-0 : 0x80000002
 *
 * (INT64_MAX/2)-3 = 0x3FFF_FFFF_FFFF_FFFC
 * (INT64_MAX/2)-2 = 0x3FFF_FFFF_FFFF_FFFD
 * (INT64_MAX/2)-1 = 0x3FFF_FFFF_FFFF_FFFE
 * (INT64_MAX/2)-0 = 0x3FFF_FFFF_FFFF_FFFF
 *
 * (INT64_MIN/2)+4 = 0xC000_0000_0000_0003
 * (INT64_MIN/2)+3 = 0xC000_0000_0000_0003
 * (INT64_MIN/2)+2 = 0xC000_0000_0000_0002
 * (INT64_MIN/2)+1 = 0xC000_0000_0000_0001
 */
const bignum_t TEST_SIGNED_NUM_256b_______0[] = {
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
};
const bignum_t TEST_SIGNED_NUM_256b______p1[] = {
    0x00000001U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
};
const bignum_t TEST_SIGNED_NUM_256b______p2[] = {
    0x00000002U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
};
const bignum_t TEST_SIGNED_NUM_256b_maxd2m3[] = {
    0xFFFFFFFDU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x3FFFFFFFU, 
};
const bignum_t TEST_SIGNED_NUM_256b_maxd2m2[] = {
    0xFFFFFFFDU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x3FFFFFFFU, 
};
const bignum_t TEST_SIGNED_NUM_256b_maxd2m1[] = {
    0xFFFFFFFEU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x3FFFFFFFU, 
};
const bignum_t TEST_SIGNED_NUM_256b___maxd2[] = {
    0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x3FFFFFFFU, 
};
const bignum_t TEST_SIGNED_NUM_256b___maxm2[] = {
    0xFFFFFFFDU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x7FFFFFFFU, 
};
const bignum_t TEST_SIGNED_NUM_256b___maxm1[] = {
    0xFFFFFFFEU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x7FFFFFFFU, 
};
const bignum_t TEST_SIGNED_NUM_256b_____max[] = {
    0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x7FFFFFFFU, 
};
const bignum_t TEST_SIGNED_NUM_256b______m1[] = {
    0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 
};
const bignum_t TEST_SIGNED_NUM_256b______m2[] = {
    0xFFFFFFFEU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 
};
const bignum_t TEST_SIGNED_NUM_256b_mind2p4[] = {
    0x00000004U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0xC0000000U, 
};
const bignum_t TEST_SIGNED_NUM_256b_mind2p3[] = {
    0x00000003U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0xC0000000U, 
};
const bignum_t TEST_SIGNED_NUM_256b_mind2p2[] = {
    0x00000002U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0xC0000000U, 
};
const bignum_t TEST_SIGNED_NUM_256b_mind2p1[] = {
    0x00000001U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0xC0000000U, 
};
const bignum_t TEST_SIGNED_NUM_256b___minp2[] = {
    0x00000002U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x80000000U, 
};
const bignum_t TEST_SIGNED_NUM_256b___minp1[] = {
    0x00000001U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x80000000U, 
};
const bignum_t TEST_SIGNED_NUM_256b_____min[] = {
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x80000000U, 
};
typedef struct {
    const bignum_t*       bignumA;
    const bignum_t*       bignumB;
    const bignum_cmp_e    cmp_ref;
    const char*           title;
    const bool            invalid_case;
} test_bignum_cmp_set_t;
const test_bignum_cmp_set_t cmpTestSet[] = {
    {TEST_SIGNED_NUM_256b_______0,   TEST_SIGNED_NUM_256b_______0,    BIGNUM_CMP_EQ,  "cmp_bignum, 0 == 0",           false },
    {TEST_SIGNED_NUM_256b______p1,   TEST_SIGNED_NUM_256b_______0,    BIGNUM_CMP_GT,  "cmp_bignum, 1 > 0",            false },
    {TEST_SIGNED_NUM_256b_______0,   TEST_SIGNED_NUM_256b______p1,    BIGNUM_CMP_LT,  "cmp_bignum, 0 < 1",            false },
    {TEST_SIGNED_NUM_256b______p1,   TEST_SIGNED_NUM_256b______p1,    BIGNUM_CMP_EQ,  "cmp_bignum, 1 == 1",           false },
    {TEST_SIGNED_NUM_256b______p2,   TEST_SIGNED_NUM_256b______p1,    BIGNUM_CMP_GT,  "cmp_bignum, 2 > 1",            false },
    {TEST_SIGNED_NUM_256b______p1,   TEST_SIGNED_NUM_256b______p2,    BIGNUM_CMP_LT,  "cmp_bignum, 1 < 2",            false },
    {TEST_SIGNED_NUM_256b______p2,   TEST_SIGNED_NUM_256b______p2,    BIGNUM_CMP_EQ,  "cmp_bignum, 2 == 2",           false },
    {TEST_SIGNED_NUM_256b___maxm2,   TEST_SIGNED_NUM_256b___maxm2,    BIGNUM_CMP_EQ,  "cmp_bignum, MAX-2 == MAX-2",   false },
    {TEST_SIGNED_NUM_256b___maxm2,   TEST_SIGNED_NUM_256b______p2,    BIGNUM_CMP_GT,  "cmp_bignum, MAX-2 > 2",        false },
    {TEST_SIGNED_NUM_256b______p2,   TEST_SIGNED_NUM_256b___maxm2,    BIGNUM_CMP_LT,  "cmp_bignum, 2 < MAX-2",        false },
    {TEST_SIGNED_NUM_256b___maxm1,   TEST_SIGNED_NUM_256b___maxm1,    BIGNUM_CMP_EQ,  "cmp_bignum, MAX-1 == MAX-1",   false },
    {TEST_SIGNED_NUM_256b___maxm1,   TEST_SIGNED_NUM_256b___maxm2,    BIGNUM_CMP_GT,  "cmp_bignum, MAX-1 > MAX-2",    false },
    {TEST_SIGNED_NUM_256b___maxm2,   TEST_SIGNED_NUM_256b___maxm1,    BIGNUM_CMP_LT,  "cmp_bignum, MAX-1 < MAX-2",    false },
    {TEST_SIGNED_NUM_256b_____max,   TEST_SIGNED_NUM_256b_____max,    BIGNUM_CMP_EQ,  "cmp_bignum, MAX == MAX",       false },
    {TEST_SIGNED_NUM_256b_____max,   TEST_SIGNED_NUM_256b___maxm1,    BIGNUM_CMP_GT,  "cmp_bignum, MAX > MAX-1",      false },
    {TEST_SIGNED_NUM_256b___maxm1,   TEST_SIGNED_NUM_256b_____max,    BIGNUM_CMP_LT,  "cmp_bignum, MAX-1 < MAX",      false },
    {TEST_SIGNED_NUM_256b_______0,   TEST_SIGNED_NUM_256b_______0,    BIGNUM_CMP_EQ,  "cmp_bignum, 0 == 0",           false },
    {TEST_SIGNED_NUM_256b_______0,   TEST_SIGNED_NUM_256b______m1,    BIGNUM_CMP_GT,  "cmp_bignum, 0 > -1",           false },
    {TEST_SIGNED_NUM_256b______m1,   TEST_SIGNED_NUM_256b_______0,    BIGNUM_CMP_LT,  "cmp_bignum, -1 < 0",           false },
    {TEST_SIGNED_NUM_256b______m1,   TEST_SIGNED_NUM_256b______m1,    BIGNUM_CMP_EQ,  "cmp_bignum, -1 == -1",         false },
    {TEST_SIGNED_NUM_256b______m1,   TEST_SIGNED_NUM_256b______m2,    BIGNUM_CMP_GT,  "cmp_bignum, -1 > -2",          false },
    {TEST_SIGNED_NUM_256b______m2,   TEST_SIGNED_NUM_256b______m2,    BIGNUM_CMP_EQ,  "cmp_bignum, -2 == -2",         false },
    {TEST_SIGNED_NUM_256b______m2,   TEST_SIGNED_NUM_256b___minp2,    BIGNUM_CMP_GT,  "cmp_bignum, -2 > MIN+2",       false },
    {TEST_SIGNED_NUM_256b___minp2,   TEST_SIGNED_NUM_256b______m2,    BIGNUM_CMP_LT,  "cmp_bignum, MIN+2 < -2",       false },
    {TEST_SIGNED_NUM_256b___minp2,   TEST_SIGNED_NUM_256b___minp2,    BIGNUM_CMP_EQ,  "cmp_bignum, MIN+2 == MIN+2",   false },
    {TEST_SIGNED_NUM_256b___minp2,   TEST_SIGNED_NUM_256b___minp1,    BIGNUM_CMP_GT,  "cmp_bignum, MIN+2 > MIN+1",    false },
    {TEST_SIGNED_NUM_256b___minp1,   TEST_SIGNED_NUM_256b___minp2,    BIGNUM_CMP_LT,  "cmp_bignum, MIN+1 < MIN+2",    false },
    {TEST_SIGNED_NUM_256b___minp1,   TEST_SIGNED_NUM_256b___minp1,    BIGNUM_CMP_EQ,  "cmp_bignum, MIN+1 == MIN+1",   false },
    {TEST_SIGNED_NUM_256b___minp1,   TEST_SIGNED_NUM_256b_____min,    BIGNUM_CMP_GT,  "cmp_bignum, MIN+1 > MIN",      false },
    {TEST_SIGNED_NUM_256b_____min,   TEST_SIGNED_NUM_256b___minp1,    BIGNUM_CMP_LT,  "cmp_bignum, MIN < MIN+1",      false },
    {TEST_SIGNED_NUM_256b_____min,   TEST_SIGNED_NUM_256b_____min,    BIGNUM_CMP_EQ,  "cmp_bignum, MIN == MIN",       false },
    {TEST_SIGNED_NUM_256b______p1,   TEST_SIGNED_NUM_256b______m1,    BIGNUM_CMP_GT,  "cmp_bignum, +1 > -1",          false },
    {TEST_SIGNED_NUM_256b______m1,   TEST_SIGNED_NUM_256b______p1,    BIGNUM_CMP_LT,  "cmp_bignum, -1 < +1",          false },
    {TEST_SIGNED_NUM_256b______p2,   TEST_SIGNED_NUM_256b______m2,    BIGNUM_CMP_GT,  "cmp_bignum, +2 > -2",          false },
    {TEST_SIGNED_NUM_256b______m2,   TEST_SIGNED_NUM_256b______p2,    BIGNUM_CMP_LT,  "cmp_bignum, -2 < +2",          false },

    {TEST_SIGNED_NUM_256b_maxd2m3,   TEST_SIGNED_NUM_256b_mind2p4,    BIGNUM_CMP_GT,  "cmp_bignum, MAX/2-3 > MIN/2+4",false },  // invalid
    {TEST_SIGNED_NUM_256b_mind2p4,   TEST_SIGNED_NUM_256b_maxd2m3,    BIGNUM_CMP_LT,  "cmp_bignum, MIN/2+4 < MAX/2-3",false },  // invalid
    {TEST_SIGNED_NUM_256b_maxd2m2,   TEST_SIGNED_NUM_256b_mind2p3,    BIGNUM_CMP_GT,  "cmp_bignum, MAX/2-2 > MIN/2+3",false },  // invalid
    {TEST_SIGNED_NUM_256b_mind2p3,   TEST_SIGNED_NUM_256b_maxd2m2,    BIGNUM_CMP_LT,  "cmp_bignum, MIN/2+3 < MAX/2-2",false },  // invalid
    {TEST_SIGNED_NUM_256b_maxd2m1,   TEST_SIGNED_NUM_256b_mind2p2,    BIGNUM_CMP_GT,  "cmp_bignum, MAX/2-1 > MIN/2+2",false },  // invalid
    {TEST_SIGNED_NUM_256b_mind2p2,   TEST_SIGNED_NUM_256b_maxd2m1,    BIGNUM_CMP_LT,  "cmp_bignum, MIN/2+2 < MAX/2-1",false },  // invalid
    {TEST_SIGNED_NUM_256b___maxd2,   TEST_SIGNED_NUM_256b_mind2p1,    BIGNUM_CMP_GT,  "cmp_bignum, MAX/2-0 > MIN/2+1",false },  // invalid
    {TEST_SIGNED_NUM_256b_mind2p1,   TEST_SIGNED_NUM_256b___maxd2,    BIGNUM_CMP_LT,  "cmp_bignum, MIN/2+1 < MAX/2-0",false },  // invalid

    {TEST_SIGNED_NUM_256b___maxm1,   TEST_SIGNED_NUM_256b___minp2,    BIGNUM_CMP_GT,  "cmp_bignum, MAX-1 > MIN+2",    true  },  // invalid
    {TEST_SIGNED_NUM_256b___minp2,   TEST_SIGNED_NUM_256b___maxm1,    BIGNUM_CMP_LT,  "cmp_bignum, MIN+2 < MAX-1",    true  },  // invalid
    {TEST_SIGNED_NUM_256b_____max,   TEST_SIGNED_NUM_256b___minp1,    BIGNUM_CMP_GT,  "cmp_bignum, MAX > MIN+1",      true  },  // invalid
    {TEST_SIGNED_NUM_256b___minp1,   TEST_SIGNED_NUM_256b_____max,    BIGNUM_CMP_LT,  "cmp_bignum, MIN+1 < MAX",      true  },  // invalid
};

typedef bignum_cmp_e (*TEST_FP_BIGNUM_CMP)(const bignum_s*, const bignum_s*);
void test_cmp_bignum_signed_256b(const char* test_fn_name, const TEST_FP_BIGNUM_CMP test_fp)
{
#define TEST_BIGNUM_CMP_WITH_SUB_BIT  256U // 32Bytes, 32bits 8ea
    bool cmp_result;

    ReturnType fr;
    bignum_cmp_e test_bignum_cmp        = BIGNUM_CMP_NU;
    bignum_cmp_e test_bignum_cmp_ref;
    bool test_intentional_invalid;

    bignum_s* test_bignum_Tmp0 = mkBigNum_signed(TEST_BIGNUM_CMP_WITH_SUB_BIT);
    bignum_s* test_bignum_Tmp1 = mkBigNum_signed(TEST_BIGNUM_CMP_WITH_SUB_BIT);
    bignum_s* test_bignum_NumA = mkBigNum_signed(TEST_BIGNUM_CMP_WITH_SUB_BIT);
    bignum_s* test_bignum_NumB = mkBigNum_signed(TEST_BIGNUM_CMP_WITH_SUB_BIT);

    for(size_t i = 0UL; i < sizeof(cmpTestSet)/sizeof(test_bignum_cmp_set_t); i++)
    {
        (void)memcpy(test_bignum_NumA->nums, cmpTestSet[i].bignumA, test_bignum_NumA->size);
        (void)memcpy(test_bignum_NumB->nums, cmpTestSet[i].bignumB, test_bignum_NumB->size);
        test_bignum_cmp_ref = cmpTestSet[i].cmp_ref;
        test_intentional_invalid = cmpTestSet[i].invalid_case;

        TICK_TIME_START(cmpTestSet[i].title);
        test_bignum_cmp = test_fp(test_bignum_NumA, test_bignum_NumB);
        TICK_TIME_END;

        sub_bignum(NULL, test_bignum_Tmp0, test_bignum_NumA, test_bignum_NumB, 0U);
        sub_bignum_with_add_twos(NULL, test_bignum_Tmp1, test_bignum_NumA, test_bignum_NumB, 0U);

        cmp_result = (test_bignum_cmp == test_bignum_cmp_ref);

        if((!cmp_result) || (test_intentional_invalid))
        {
            test_print_bignum(test_bignum_NumA, "A");
            test_print_bignum(test_bignum_NumB, "B");
            test_print_bignum_cmp(test_bignum_cmp);
            test_print_bignum(test_bignum_Tmp0, "sub_bignum");
            test_print_bignum(test_bignum_Tmp1, "sub_bignum_with_add_twos");
        }

        printf("%s() is %s\r\n", test_fn_name, ((cmp_result)?(MES_PASS):(test_intentional_invalid?MES_SKIP:MES_FAIL)));
        TEST_ASSERT((cmp_result) || (test_intentional_invalid));
    }

    rmBitNum(&test_bignum_Tmp0);
    rmBitNum(&test_bignum_Tmp1);
    rmBitNum(&test_bignum_NumA);
    rmBitNum(&test_bignum_NumB);

#undef TEST_BIGNUM_CMP_WITH_SUB_BIT
}

#define TEST_BIGNUM_127BIT  127u    //16Bytes
void test_sub_bignum_unsigned_127b(void)
{
    bool cmp_result;

    bignum_t  test_co;

    bignum_s* test_opA;
    bignum_s* test_opB;
    bignum_s* test_dst;
    bignum_s* test_ref;

    test_opA = mkBigNum(TEST_BIGNUM_127BIT);
    test_opB = mkBigNum(TEST_BIGNUM_127BIT);
    test_dst = mkBigNum(TEST_BIGNUM_127BIT);
    test_ref = mkBigNum(TEST_BIGNUM_127BIT);

    /* add_bignum test */
    for(unsigned int i = 0u; i < TV_U32_ADD_NUM; i++) {
        memset(test_opA->nums, 0x0u, (test_opA->size));
        memset(test_opB->nums, 0x0u, (test_opB->size));
        memset(test_ref->nums, 0x0u, (test_ref->size));

        memcpy(test_opA->nums, TV_u32_add_opAList[i], TV_u32_add_lenList[i]);
        memcpy(test_opB->nums, TV_u32_add_opBList[i], TV_u32_add_lenList[i]);
        memcpy(test_ref->nums, TV_u32_add_refList[i], TV_u32_add_lenList[i]);
        test_co = BIGNUM_MAX;

        TICK_TIME_START("add_bignum");
        add_bignum(&test_co, test_dst, test_opA, test_opB, TV_u32_add_carryInList[i]);
        TICK_TIME_END;
        cmp_result = (memcmp(test_ref->nums, test_dst->nums, (test_ref->size)) == 0);
        if(!cmp_result)
        {
            test_print_bignum(test_opA, "opA");
            test_print_bignum(test_opB, "opB");
            test_print_bignum(test_dst, "dst");
            test_print_bignum(test_ref, "ref");
            printf("[ref carry]\r\nc=0x%08x\r\n", TV_u32_add_carryInList[i]);
            printf("[out carry]\r\nc=0x%08x\r\n", test_co);
        }
        printf("add_bignum() is %s\r\n", ((cmp_result)?MES_PASS:MES_FAIL));
        TEST_ASSERT(cmp_result);
    }

    rmBitNum(&test_opA);
    rmBitNum(&test_opB);
    rmBitNum(&test_dst);
    rmBitNum(&test_ref);
}

#define TEST_BIGNUM_256BIT  256u    // 32Bytes
void test_add_bignum_unsigned_256b(void) {
    typedef struct {
        const bignum_t* nums___a;
        const bignum_t* nums___b;
        const bignum_t* nums_ref;
        const char*     title;
        const bool      invalid_case;
    } test_bignum_add_bignum_set_t;
    const test_bignum_add_bignum_set_t TEST_BIGNUM_add_bignum_set_LIST[] = {
        {
            TEST_BIGNUM_256b_RandomNum_______A_0, TEST_BIGNUM_256b_RandomNum_______B_0, TEST_BIGNUM_256b_RandomNum_Add_A_B_0,
            "add 256b bitnum A + B, link: https://defuse.ca/big-number-calculator.htm", false,
        },
        {
            TEST_BIGNUM_256b_signed____m1, TEST_BIGNUM_256b_signed____p1, TEST_BIGNUM_256b_signed__zero,
            "add 256b bitnum (-1) + (+1), link: https://defuse.ca/big-number-calculator.htm", false,
        },
        {
            TEST_BIGNUM_256b_signed____m1, TEST_BIGNUM_256b_signed____m2, TEST_BIGNUM_256b_signed____m3 ,
            "add 256b bitnum (-1) + (-2), link: https://defuse.ca/big-number-calculator.htm", false,
        },
    };

    bool cmp_result;
    bool intentional_invalid;

    bignum_t test_ci;
    bignum_t test_co;

    bignum_s* test_opA;
    bignum_s* test_opB;
    bignum_s* test_dst;
    bignum_s* test_ref;

    test_opA = mkBigNum_unsigned(TEST_BIGNUM_256BIT);
    test_opB = mkBigNum_unsigned(TEST_BIGNUM_256BIT);
    test_dst = mkBigNum_unsigned(TEST_BIGNUM_256BIT);
    test_ref = mkBigNum_unsigned(TEST_BIGNUM_256BIT);

    /* Add test */
    for(size_t i = 0UL; i <sizeof(TEST_BIGNUM_add_bignum_set_LIST)/sizeof(test_bignum_add_bignum_set_t); i++)
    {
        memcpy(test_opA->nums, TEST_BIGNUM_add_bignum_set_LIST[i].nums___a, test_opA->size);
        memcpy(test_opB->nums, TEST_BIGNUM_add_bignum_set_LIST[i].nums___b, test_opB->size);
        memcpy(test_ref->nums, TEST_BIGNUM_add_bignum_set_LIST[i].nums_ref, test_ref->size);
        intentional_invalid = TEST_BIGNUM_add_bignum_set_LIST[i].invalid_case;
        test_ci = 0;
        test_co = 0;

        TICK_TIME_START("add_bignum");
        add_bignum(&test_co, test_dst, test_opA, test_opB, test_ci);
        TICK_TIME_END;
        cmp_result = (memcmp(test_ref->nums, test_dst->nums, (test_ref->size)) == 0);
        if((!cmp_result))
        {
            test_print_bignum(test_opA, "opA");
            test_print_bignum(test_opB, "opB");
            test_print_bignum(test_dst, "dst");
            test_print_bignum(test_ref, "ref");
            printf("[carry  in]\r\nc=0x%08x\r\n", test_ci);
            printf("[carry out]\r\nc=0x%08x\r\n", test_co);

        }
        printf("add_bignum() is %s\r\n", ((cmp_result)?(MES_PASS):(intentional_invalid?MES_SKIP:MES_FAIL)));
        TEST_ASSERT((cmp_result) || (intentional_invalid));
    }

    rmBitNum(&test_ref);
    rmBitNum(&test_dst);
    rmBitNum(&test_opA);
    rmBitNum(&test_opB);
}

typedef ReturnType (*TEST_FP_BIGNUM_SUB)(bignum_t*, bignum_s*, const bignum_s*, const bignum_s*, const bignum_t);
void test_sub_bignum_unsigned_256b(const char* test_fn_name, const TEST_FP_BIGNUM_SUB test_fp)
{
    typedef struct {
        const bignum_t* nums___a;
        const bignum_t* nums___b;
        const bignum_t* nums_ref;
        const char*     title;
        const bool      invalid_case;
    } test_bignum_sub_bignum_set_t;
    const test_bignum_sub_bignum_set_t TEST_BIGNUM_sub_bignum_set_LIST[] = {
        {
            TEST_BIGNUM_256b_RandomNum_Add_A_B_0, TEST_BIGNUM_256b_RandomNum_______B_0, TEST_BIGNUM_256b_RandomNum_______A_0,
            "add 256b bitnum A - B, link: https://defuse.ca/big-number-calculator.htm", false,
        },
        {
            TEST_BIGNUM_256b_signed__zero, TEST_BIGNUM_256b_signed____p1, TEST_BIGNUM_256b_signed____m1,
            "add 256b bitnum 0 - (+1), link: https://defuse.ca/big-number-calculator.htm", false,
        },
        {
            TEST_BIGNUM_256b_signed____m3, TEST_BIGNUM_256b_signed____m2, TEST_BIGNUM_256b_signed____m1,
            "add 256b bitnum (-3) - (-2), link: https://defuse.ca/big-number-calculator.htm", false,
        },
    };

    bool cmp_result;
    bool intentional_invalid;

    bignum_t test_ci;
    bignum_t test_co;

    bignum_s* test_opA;
    bignum_s* test_opB;
    bignum_s* test_dst;
    bignum_s* test_ref;

    test_opA = mkBigNum_unsigned(TEST_BIGNUM_256BIT);
    test_opB = mkBigNum_unsigned(TEST_BIGNUM_256BIT);
    test_dst = mkBigNum_unsigned(TEST_BIGNUM_256BIT);
    test_ref = mkBigNum_unsigned(TEST_BIGNUM_256BIT);

    /* Sub test */
    for(size_t i = 0UL; i < sizeof(TEST_BIGNUM_sub_bignum_set_LIST)/sizeof(test_bignum_sub_bignum_set_t); i++)
    {
        memcpy(test_opA->nums, TEST_BIGNUM_sub_bignum_set_LIST[i].nums___a, test_opA->size);
        memcpy(test_opB->nums, TEST_BIGNUM_sub_bignum_set_LIST[i].nums___b, test_opB->size);
        memcpy(test_ref->nums, TEST_BIGNUM_sub_bignum_set_LIST[i].nums_ref, test_ref->size);
        intentional_invalid = TEST_BIGNUM_sub_bignum_set_LIST[i].invalid_case;
        test_ci = 0;
        test_co = 0;

        TICK_TIME_START(test_fn_name);
        test_fp(&test_co, test_dst, test_opA, test_opB, test_ci);
        TICK_TIME_END;
        cmp_result = (memcmp(test_ref->nums, test_dst->nums, (test_ref->size)) == 0);
        if((!cmp_result))
        {
            test_print_bignum(test_opA, "opA");
            test_print_bignum(test_opB, "opB");
            test_print_bignum(test_dst, "dst");
            test_print_bignum(test_ref, "ref");
            printf("[carry  in]\r\nc=0x%08x\r\n", test_ci);
            printf("[carry out]\r\nc=0x%08x\r\n", test_co);

        }
        printf("%s() is %s\r\n", test_fn_name, ((cmp_result)?(MES_PASS):(intentional_invalid?MES_SKIP:MES_FAIL)));
        TEST_ASSERT((cmp_result) || (intentional_invalid));
    }

    rmBitNum(&test_opA);
    rmBitNum(&test_opB);
    rmBitNum(&test_dst);
    rmBitNum(&test_ref);
}

#define TEST_MUL_BIGNUM_BS  1024U
const bignum_t TEST_BIGNUM_1024b_Num_MUL___A_0[] = {
    0xffffffffU, 0xffffffffU, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
};
const bignum_t TEST_BIGNUM_1024b_Num_MUL___B_0[] = {
    0xffffffffU, 0xffffffffU, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
};
const bignum_t TEST_BIGNUM_1024b_Num_MUL_Ref_0[] = {
    0x00000001U, 0x00000000U, 0xfffffffeU, 0xffffffffU, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
};

const bignum_t TEST_BIGNUM_1024b_Num_MUL___A_1[] = {
    0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
};
const bignum_t TEST_BIGNUM_1024b_Num_MUL___B_1[] = {
    0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
};
const bignum_t TEST_BIGNUM_1024b_Num_MUL_Ref_1[] = {
    0x00000001U, 0x00000000U, 0x00000000U, 0x00000000U, 0xfffffffeU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
};

const bignum_t TEST_BIGNUM_1024b_Num_MUL___A_2[] = {
    0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
};
const bignum_t TEST_BIGNUM_1024b_Num_MUL___B_2[] = {
    0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
};
const bignum_t TEST_BIGNUM_1024b_Num_MUL_Ref_2[] = {
    0x00000001U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0xffffffffU, 0xfffffffeU, 0xffffffffU, 
    0xffffffffU, 0xffffffffU, 0xffffffffU, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
};

const bignum_t TEST_BIGNUM_1024b_Num_MUL___A_3[] = {
    0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
};
const bignum_t TEST_BIGNUM_1024b_Num_MUL___B_3[] = {
    0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
};
const bignum_t TEST_BIGNUM_1024b_Num_MUL_Ref_3[] = {
    0x00000001U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0xffffffffU, 0xfffffffeU, 
    0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
};

const bignum_t TEST_BIGNUM_1024b_Num_MUL___A_4[] = {
    0x00000007U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
}; // 7
const bignum_t TEST_BIGNUM_1024b_Num_MUL___B_4[] = {
    0xfffffff2U, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 
    0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 
    0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 
    0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 
}; // -14
const bignum_t TEST_BIGNUM_1024b_Num_MUL_Ref_4[] = {
    0xffffff9eU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 
    0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 
    0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 
    0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 
    0x00000006U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
}; // -98

const bignum_t TEST_BIGNUM_1024b_Num_MUL___A_5[] = {
    0xfffffff2U, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 
    0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 
    0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 
    0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 
}; // -14
const bignum_t TEST_BIGNUM_1024b_Num_MUL___B_5[] = {
    0x00000007U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
}; // 7
const bignum_t TEST_BIGNUM_1024b_Num_MUL_Ref_5[] = {
    0xffffff9eU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 
    0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 
    0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 
    0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 
    0x00000006U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
}; // -98

typedef struct {
    const bignum_t* nums___a;
    const bignum_t* nums___b;
    const bignum_t* nums_ref;
    const char*     title;
    const bool      invalid_case;
} test_bignum_mul_bignum_set_t;

typedef ReturnType (*TEST_FP_BIGNUM_MUL)(bignum_s*, const bignum_s*, const bignum_s*);
void test_mul_bignum_1024b(const char* test_fn_name, const TEST_FP_BIGNUM_MUL test_fp)
{
    const test_bignum_mul_bignum_set_t TEST_BIGNUM_mul_bignum_set_LIST[] = {
        {
            TEST_BIGNUM_1024b_Num_MUL___A_0, TEST_BIGNUM_1024b_Num_MUL___B_0, TEST_BIGNUM_1024b_Num_MUL_Ref_0,
            NULL, false,
        },
        {
            TEST_BIGNUM_1024b_Num_MUL___A_1, TEST_BIGNUM_1024b_Num_MUL___B_1, TEST_BIGNUM_1024b_Num_MUL_Ref_1,
            NULL, false,
        },
        {
            TEST_BIGNUM_1024b_Num_MUL___A_2, TEST_BIGNUM_1024b_Num_MUL___B_2, TEST_BIGNUM_1024b_Num_MUL_Ref_2,
            NULL, false,
        },
        {
            TEST_BIGNUM_1024b_Num_MUL___A_3, TEST_BIGNUM_1024b_Num_MUL___B_3, TEST_BIGNUM_1024b_Num_MUL_Ref_3,
            NULL, false,
        },
        {
            TEST_BIGNUM_1024b_Num_MUL___A_4, TEST_BIGNUM_1024b_Num_MUL___B_4, TEST_BIGNUM_1024b_Num_MUL_Ref_4,
            NULL, false,
        },
        {
            TEST_BIGNUM_1024b_Num_MUL___A_5, TEST_BIGNUM_1024b_Num_MUL___B_5, TEST_BIGNUM_1024b_Num_MUL_Ref_5,
            NULL, false,
        },
    };

    bool cmp_result;
    bool intentional_invalid;
    ReturnType fr;

    bignum_s* test_opA = mkBigNum(TEST_MUL_BIGNUM_BS<<0U);
    bignum_s* test_opB = mkBigNum(TEST_MUL_BIGNUM_BS<<0U);
    bignum_s* test_dst = mkBigNum(TEST_MUL_BIGNUM_BS<<1U);
    bignum_s* test_ref = mkBigNum(TEST_MUL_BIGNUM_BS<<1U);

    for(size_t tvi = 0UL; tvi < sizeof(TEST_BIGNUM_mul_bignum_set_LIST)/sizeof(test_bignum_mul_bignum_set_t); tvi++)
    {
        (void)memcpy(test_opA->nums, TEST_BIGNUM_mul_bignum_set_LIST[tvi].nums___a, test_opA->size);
        (void)memcpy(test_opB->nums, TEST_BIGNUM_mul_bignum_set_LIST[tvi].nums___b, test_opB->size);
        (void)memcpy(test_ref->nums, TEST_BIGNUM_mul_bignum_set_LIST[tvi].nums_ref, test_ref->size);
        intentional_invalid = TEST_BIGNUM_mul_bignum_set_LIST[tvi].invalid_case;

        TICK_TIME_START(test_fn_name);
        if((fr = test_fp(test_dst, test_opA, test_opB)) != E_OK) {
            printReturnType(fr);
        }
        TICK_TIME_END;

        cmp_result = (memcmp(test_ref->nums, test_dst->nums, (test_ref->size)) == 0);
        if((!cmp_result))
        {
            printf("[tvi: %lu]\r\n", tvi);
            test_print_bignum(test_opA, "opA");
            test_print_bignum(test_opB, "opB");
            test_print_bignum(test_dst, "dst");
            test_print_bignum(test_ref, "ref");
        }
        printf("%s is %s\r\n", test_fn_name, ((cmp_result)?(MES_PASS):(intentional_invalid?MES_SKIP:MES_FAIL)));
        TEST_ASSERT((cmp_result) || (intentional_invalid));
    }

    rmBitNum(&test_opA);
    rmBitNum(&test_opB);
    rmBitNum(&test_dst);
    rmBitNum(&test_ref);
}

typedef ReturnType (*TEST_FP_BIGNUM_MUL)(bignum_s*, const bignum_s*, const bignum_s*);
void test_mul_bignum_1024b_sameBignumLength(const char* test_fn_name, const TEST_FP_BIGNUM_MUL test_fp)
{
    const test_bignum_mul_bignum_set_t TEST_BIGNUM_mul_bignum_set_LIST[] = {
        {
            TEST_BIGNUM_1024b_Num_MUL___A_0, TEST_BIGNUM_1024b_Num_MUL___B_0, TEST_BIGNUM_1024b_Num_MUL_Ref_0,
            NULL, true,
        },
        {
            TEST_BIGNUM_1024b_Num_MUL___A_1, TEST_BIGNUM_1024b_Num_MUL___B_1, TEST_BIGNUM_1024b_Num_MUL_Ref_1,
            NULL, true,
        },
        {
            TEST_BIGNUM_1024b_Num_MUL___A_2, TEST_BIGNUM_1024b_Num_MUL___B_2, TEST_BIGNUM_1024b_Num_MUL_Ref_2,
            NULL, true,
        },
        {
            TEST_BIGNUM_1024b_Num_MUL___A_3, TEST_BIGNUM_1024b_Num_MUL___B_3, TEST_BIGNUM_1024b_Num_MUL_Ref_3,
            NULL, true,
        },
        {
            TEST_BIGNUM_1024b_Num_MUL___A_4, TEST_BIGNUM_1024b_Num_MUL___B_4, TEST_BIGNUM_1024b_Num_MUL_Ref_4,
            NULL, true,
        },
        {
            TEST_BIGNUM_1024b_Num_MUL___A_5, TEST_BIGNUM_1024b_Num_MUL___B_5, TEST_BIGNUM_1024b_Num_MUL_Ref_5,
            NULL, true,
        },
    };

    bool cmp_result;
    bool intentional_invalid;
    ReturnType fr;

    bignum_s* test_opA = mkBigNum(TEST_MUL_BIGNUM_BS<<0U);
    bignum_s* test_opB = mkBigNum(TEST_MUL_BIGNUM_BS<<0U);
    bignum_s* test_dst = mkBigNum(TEST_MUL_BIGNUM_BS<<0U);
    bignum_s* test_ref = mkBigNum(TEST_MUL_BIGNUM_BS<<0U);

    for(size_t tvi = 0UL; tvi < sizeof(TEST_BIGNUM_mul_bignum_set_LIST)/sizeof(test_bignum_mul_bignum_set_t); tvi++)
    {
        (void)memcpy(test_opA->nums, TEST_BIGNUM_mul_bignum_set_LIST[tvi].nums___a, test_opA->size);
        (void)memcpy(test_opB->nums, TEST_BIGNUM_mul_bignum_set_LIST[tvi].nums___b, test_opB->size);
        (void)memcpy(test_ref->nums, TEST_BIGNUM_mul_bignum_set_LIST[tvi].nums_ref, test_ref->size);
        intentional_invalid = TEST_BIGNUM_mul_bignum_set_LIST[tvi].invalid_case;

        TICK_TIME_START(test_fn_name);
        if((fr = test_fp(test_dst, test_opA, test_opB)) != E_OK) {
            printReturnType(fr);
        }
        TICK_TIME_END;

        cmp_result = (memcmp(test_ref->nums, test_dst->nums, (test_ref->size)) == 0);
        if((!cmp_result))
        {
            printf("[tvi: %lu]\r\n", tvi);
            test_print_bignum(test_opA, "opA");
            test_print_bignum(test_opB, "opB");
            test_print_bignum(test_dst, "dst");
            test_print_bignum(test_ref, "ref");
        }
        printf("%s is %s\r\n", test_fn_name, ((cmp_result)?(MES_PASS):(intentional_invalid?MES_SKIP:MES_FAIL)));
        TEST_ASSERT((cmp_result) || (intentional_invalid));
    }

    rmBitNum(&test_opA);
    rmBitNum(&test_opB);
    rmBitNum(&test_dst);
    rmBitNum(&test_ref);
}

#define TEST_ADD_BIGNUM_CARRY_LOC_BIT_LEN 1024U
void test_add_bignum_carry_loc(void)
{
    bignum_s* test_opA;
    bignum_t test_opB;

    test_opA = mkBigNum(TEST_ADD_BIGNUM_CARRY_LOC_BIT_LEN);
    (void)memset(test_opA->nums, 0x0U, test_opA->size);
    test_print_bignum(test_opA, "cleared opA");

    /* Set first stage 1 */
    test_opB = 0x12345678U;
    for(size_t i = 0UL; i < test_opA->nlen; i++) {
        bignum_t tmp = add_bignum_carry_loc(test_opA, test_opB, i);
        if(tmp) {
            printf("[%lu] carry = %u \r\n", i, tmp);
        }
    }
    test_print_bignum(test_opA, "add loc result of opA");

    /* Set first stage 2 */
    test_opB = 0x87654321U;
    for(size_t i = 0UL; i < test_opA->nlen; i++) {
        bignum_t tmp = add_bignum_carry_loc(test_opA, test_opB, i);
        if(tmp) {
            printf("[%lu] carry = %u \r\n", i, tmp);
        }
    }
    test_print_bignum(test_opA, "add loc result of opA");

    /* Set first stage 3 */
    test_opB = 0x66666666U;
    for(size_t i = 0UL; i < test_opA->nlen; i++) {
        bignum_t tmp = add_bignum_carry_loc(test_opA, test_opB, i);
        if(tmp) {
            printf("[%lu] carry = %u \r\n", i, tmp);
        }
    }
    test_print_bignum(test_opA, "add loc result of opA");

    /* Set first stage 4 */
    test_opB = 0x00800000U;
    bignum_t tmp = add_bignum_carry_loc(test_opA, test_opB, 3);
    if(tmp) {
        printf("carry = %u \r\n", tmp);
    }
    test_print_bignum(test_opA, "Final Stage, add loc result of opA");

    rmBitNum(&test_opA);
}

#define TEST_MUL_BIGNUM_BS_NN_BIT_LEN   512U
void test_mul_bignum_bs_nn(void)
{
    bool test_cmp;
    bool intentional_invalid;
    ReturnType fr;

    bignum_s* test_opA = mkBigNum(TEST_MUL_BIGNUM_BS_NN_BIT_LEN);
    bignum_s* test_opB = mkBigNum(TEST_MUL_BIGNUM_BS_NN_BIT_LEN);
    bignum_s* test_dst = mkBigNum(TEST_MUL_BIGNUM_BS_NN_BIT_LEN);
    bignum_s* test_ref = mkBigNum(TEST_MUL_BIGNUM_BS_NN_BIT_LEN);

    /****************/
    /* TestVector 1, Negative x Negative */
    (void)memset(test_opA->nums, 0xffU, test_opA->size);
    (void)memset(test_opB->nums, 0xffU, test_opB->size);
    (void)memset(test_dst->nums, 0U,    test_dst->size);
    (void)memset(test_ref->nums, 0U,    test_ref->size);

    // set operand A -> -1
    //test_opA->nums[0];

    // set operand B
    //test_opB->nums[0];

    // set reference
    test_ref->nums[0]  = 0x00000001U;
    intentional_invalid = false;

    if(fr = mul_bignum_1bs_ext(test_dst, test_opA, test_opB, false)) {
        printReturnType(fr);
    } else { /* Do nothing */ }

    test_cmp = (memcmp(test_ref->nums, test_dst->nums, (test_ref->size)) == 0);
    if((!test_cmp))
    {
        test_print_bignum(test_opA, "opA");
        test_print_bignum(test_opB, "opB");
        test_print_bignum(test_dst, "dst");
        test_print_bignum(test_ref, "ref");
    }
    printf("mul_bignum_1bs() is %s\r\n", ((test_cmp)?(MES_PASS):(intentional_invalid?MES_SKIP:MES_FAIL)));
    TEST_ASSERT((test_cmp) || (intentional_invalid));

    rmBitNum(&test_opA);
    rmBitNum(&test_opB);
    rmBitNum(&test_dst);
    rmBitNum(&test_ref);
}

void test_bignum_bit_contol(void)
{
#define TEST_LOGIC_BIT_CONTROL_BIT_LEN  256U
    ReturnType fr;
    bignum_s* test_bignum;
    bignum_s* test_bignum_ref;

    bool cmp_result;

    test_bignum = mkBigNum(TEST_LOGIC_BIT_CONTROL_BIT_LEN);
    test_bignum_ref = mkBigNum(TEST_LOGIC_BIT_CONTROL_BIT_LEN);

    {
        // print not initialzed
        test_print_bignum(test_bignum, "test_bignum, not initialized");

        // print not initialzed, but inverted
        if(fr = inv_bignum(test_bignum)) {
            printReturnType(fr);
        } else { /* Do nothing */ }
        test_print_bignum(test_bignum, "test_bignum, not initialized, but inverted");

        // print cleared all bits
        memset(test_bignum_ref->nums, 0x00, test_bignum_ref->size);
        if(fr = clr_bignum(test_bignum)) {
            printReturnType(fr);
        } else { /* Do nothing */ }
        cmp_result = (memcmp(test_bignum->nums, test_bignum_ref->nums, test_bignum_ref->size) == 0);
        if(!cmp_result)
        {
            test_print_bignum(test_bignum, "test_bignum, cleared all bits");
        }
        printf("clr_bignum() is %s\r\n", ((cmp_result)?MES_PASS:MES_FAIL));
        TEST_ASSERT(cmp_result);
        // print cleared all bits and inverted
        memset(test_bignum_ref->nums, 0xFF, test_bignum_ref->size);
        if(fr = inv_bignum(test_bignum)) {
            printReturnType(fr);
        } else { /* Do nothing */ }
        cmp_result = (memcmp(test_bignum->nums, test_bignum_ref->nums, test_bignum_ref->size) == 0);
        if(!cmp_result)
        {
            test_print_bignum(test_bignum, "test_bignum, cleared all bits and inverted");
        }
        printf("inv_bignum() is %s\r\n", ((cmp_result)?MES_PASS:MES_FAIL));
        TEST_ASSERT(cmp_result);
        // print cleared all bits and inverted twice
        memset(test_bignum_ref->nums, 0x00, test_bignum_ref->size);
        if(fr = inv_bignum(test_bignum)) {
            printReturnType(fr);
        } else { /* Do nothing */ }
        cmp_result = (memcmp(test_bignum->nums, test_bignum_ref->nums, test_bignum_ref->size) == 0);
        if(!cmp_result)
        {
            test_print_bignum(test_bignum, "test_bignum, cleared all bits and inverted twice");
        }
        printf("inv_bignum() is %s\r\n", ((cmp_result)?MES_PASS:MES_FAIL));
        TEST_ASSERT(cmp_result);

        // print set all bits
        memset(test_bignum_ref->nums, 0xFF, test_bignum_ref->size);
        if(fr = set_bignum(test_bignum)) {
            printReturnType(fr);
        } else { /* Do nothing */ }
        cmp_result = (memcmp(test_bignum->nums, test_bignum_ref->nums, test_bignum_ref->size) == 0);
        if(!cmp_result)
        {
            test_print_bignum(test_bignum, "test_bignum, set all bits");
        }
        printf("set_bignum() is %s\r\n", ((cmp_result)?MES_PASS:MES_FAIL));
        TEST_ASSERT(cmp_result);
        // print set all bits and inverted
        memset(test_bignum_ref->nums, 0x00, test_bignum_ref->size);
        if(fr = inv_bignum(test_bignum)) {
            printReturnType(fr);
        } else { /* Do nothing */ }
        cmp_result = (memcmp(test_bignum->nums, test_bignum_ref->nums, test_bignum_ref->size) == 0);
        if(!cmp_result)
        {
            test_print_bignum(test_bignum, "test_bignum, set all bits and inverted");
        }
        printf("inv_bignum() is %s\r\n", ((cmp_result)?MES_PASS:MES_FAIL));
        TEST_ASSERT(cmp_result);
        // print set all bits and inverted twice
        memset(test_bignum_ref->nums, 0xFF, test_bignum_ref->size);
        if(fr = inv_bignum(test_bignum)) {
            printReturnType(fr);
        } else { /* Do nothing */ }
        cmp_result = (memcmp(test_bignum->nums, test_bignum_ref->nums, test_bignum_ref->size) == 0);
        if(!cmp_result)
        {
            test_print_bignum(test_bignum, "test_bignum, set all bits and inverted twice");
        }
        printf("inv_bignum() is %s\r\n", ((cmp_result)?MES_PASS:MES_FAIL));
        TEST_ASSERT(cmp_result);

        //printf("find_bignum_MSBL() is %s\r\n", ((test_ref_msbl == test_msbl)?MES_PASS:MES_FAIL));
        //TEST_ASSERT(test_ref_msbl == test_msbl);
    }

    {
        size_t test_total;
        size_t test_set1b_pass, test_clr1b_pass, test_inv_pass;
        size_t test_set1b_fail, test_clr1b_fail, test_inv_fail;

        if(fr = clr_bignum(test_bignum)) {
            printReturnType(fr);
        } else { /* Do nothing */ }
        memset(test_bignum_ref->nums, 0x0, test_bignum_ref->size);

        test_total = 0UL;
        test_set1b_pass = 0UL;
        test_clr1b_pass = 0UL;
        test_inv_pass = 0UL;
        test_set1b_fail = 0UL;
        test_clr1b_fail = 0UL;
        test_inv_fail = 0UL;
        for(size_t i = 0UL; i < TEST_LOGIC_BIT_CONTROL_BIT_LEN; i++)
        {
#define _I_(I)    ((I)>>5U)
#define _L_(I)    ((I)&0x1FU)
            test_bignum_ref->nums[_I_(i)]|=(((bignum_t)1U)<<((bignum_t)_L_(i)));
            if(fr = set1b_bignum(test_bignum, i)) {
                printReturnType(fr);
            } else { /* Do nothing */ }

            cmp_result = (memcmp(test_bignum->nums, test_bignum_ref->nums, test_bignum_ref->size) == 0);
            if(!cmp_result)
            {
                test_set1b_fail++;
                test_print_bignum(test_bignum, "test_bignum, set one bit at LOW side");
                test_print_bignum(test_bignum_ref, "test_bignum_ref");
                printf("set1b_bignum() is %s\r\n", ((cmp_result)?MES_PASS:MES_FAIL));
            }
            else
            {
                test_set1b_pass++;
            }
            TEST_ASSERT(cmp_result);

            for(size_t j = 0UL; j < test_bignum_ref->nlen; j++)
                test_bignum_ref->nums[j]=(~test_bignum_ref->nums[j]);
            if(fr = inv_bignum(test_bignum)) {
                printReturnType(fr);
            } else { /* Do nothing */ }

            cmp_result = (memcmp(test_bignum->nums, test_bignum_ref->nums, test_bignum_ref->size) == 0);
            if(!cmp_result)
            {
                test_inv_fail++;
                test_print_bignum(test_bignum, "test_bignum, set one bit at LOW side inverted");
                test_print_bignum(test_bignum_ref, "test_bignum_ref");
                printf("inv_bignum() is %s\r\n", ((cmp_result)?MES_PASS:MES_FAIL));
            }
            else
            {
                test_inv_pass++;
            }
            TEST_ASSERT(cmp_result);

            for(size_t j = 0UL; j < test_bignum_ref->nlen; j++)
                test_bignum_ref->nums[j]=(~test_bignum_ref->nums[j]);
            if(fr = inv_bignum(test_bignum)) {
                printReturnType(fr);
            } else { /* Do nothing */ }
#undef _I_
#undef _L_
            test_total++;
        }
        cmp_result = (test_set1b_pass == test_total);
        printf("total test %ld of %ld about set1b_bignum() is %s\r\n", test_total, test_set1b_pass, ((cmp_result)?MES_PASS:MES_FAIL));
        cmp_result = (test_inv_pass == test_total);
        printf("total test %ld of %ld about inv_bignum() is %s\r\n", test_total, test_inv_pass, ((cmp_result)?MES_PASS:MES_FAIL));

        test_total = 0UL;
        test_set1b_pass = 0UL;
        test_clr1b_pass = 0UL;
        test_inv_pass = 0UL;
        test_set1b_fail = 0UL;
        test_clr1b_fail = 0UL;
        test_inv_fail = 0UL;
        for(size_t i = 0UL; i < TEST_LOGIC_BIT_CONTROL_BIT_LEN; i++)
        {
#define _I_(I)    ((I)>>5U)
#define _L_(I)    ((I)&0x1FU)
            test_bignum_ref->nums[_I_(i)]&=(~(((bignum_t)1U)<<((bignum_t)_L_(i))));
            if(fr = clr1b_bignum(test_bignum, i)) {
                printReturnType(fr);
            } else { /* Do nothing */ }

            cmp_result = (memcmp(test_bignum->nums, test_bignum_ref->nums, test_bignum_ref->size) == 0);
            if(!cmp_result)
            {
                test_clr1b_pass++;
                test_print_bignum(test_bignum, "test_bignum, clr one bit at LOW side");
                test_print_bignum(test_bignum_ref, "test_bignum_ref");
                printf("clr1b_bignum() is %s\r\n", ((cmp_result)?MES_PASS:MES_FAIL));
            }
            else
            {
                test_clr1b_pass++;
            }
            TEST_ASSERT(cmp_result);

            for(size_t j = 0UL; j < test_bignum_ref->nlen; j++)
                test_bignum_ref->nums[j]=(~test_bignum_ref->nums[j]);
            if(fr = inv_bignum(test_bignum)) {
                printReturnType(fr);
            } else { /* Do nothing */ }

            cmp_result = (memcmp(test_bignum->nums, test_bignum_ref->nums, test_bignum_ref->size) == 0);
            if(!cmp_result)
            {
                test_inv_fail++;
                test_print_bignum(test_bignum, "test_bignum, clr one bit at LOW side inverted");
                test_print_bignum(test_bignum_ref, "test_bignum_ref");
                printf("inv_bignum() is %s\r\n", ((cmp_result)?MES_PASS:MES_FAIL));
            }
            else
            {
                test_inv_pass++;
            }
            TEST_ASSERT(cmp_result);

            for(size_t j = 0UL; j < test_bignum_ref->nlen; j++)
                test_bignum_ref->nums[j]=(~test_bignum_ref->nums[j]);
            if(fr = inv_bignum(test_bignum)) {
                printReturnType(fr);
            } else { /* Do nothing */ }
#undef _I_
#undef _L_
            test_total++;
        }
        cmp_result = (test_clr1b_pass == test_total);
        printf("total test %ld of %ld about clr1b_bignum() is %s\r\n", test_total, test_clr1b_pass, ((cmp_result)?MES_PASS:MES_FAIL));
        cmp_result = (test_inv_pass == test_total);
        printf("total test %ld of %ld about inv_bignum() is %s\r\n", test_total, test_inv_pass, ((cmp_result)?MES_PASS:MES_FAIL));

        test_total = 0UL;
        test_set1b_pass = 0UL;
        test_clr1b_pass = 0UL;
        test_inv_pass = 0UL;
        test_set1b_fail = 0UL;
        test_clr1b_fail = 0UL;
        test_inv_fail = 0UL;
        for(size_t i = (TEST_LOGIC_BIT_CONTROL_BIT_LEN-1UL); i < SIZE_MAX; i--)
        {
#define _I_(I)    ((I)>>5U)
#define _L_(I)    ((I)&0x1FU)
            test_bignum_ref->nums[_I_(i)]|=(((bignum_t)1U)<<((bignum_t)_L_(i)));
            if(fr = set1b_bignum(test_bignum, i)) {
                printReturnType(fr);
            } else { /* Do nothing */ }

            cmp_result = (memcmp(test_bignum->nums, test_bignum_ref->nums, test_bignum_ref->size) == 0);
            if(!cmp_result)
            {
                test_set1b_fail++;
                test_print_bignum(test_bignum, "test_bignum, set one bit at HIGH side");
                test_print_bignum(test_bignum_ref, "test_bignum_ref");
                printf("set1b_bignum() is %s\r\n", ((cmp_result)?MES_PASS:MES_FAIL));
            }
            else
            {
                test_set1b_pass++;
            }
            TEST_ASSERT(cmp_result);

            for(size_t j = 0UL; j < test_bignum_ref->nlen; j++)
                test_bignum_ref->nums[j]=(~test_bignum_ref->nums[j]);
            if(fr = inv_bignum(test_bignum)) {
                printReturnType(fr);
            } else { /* Do nothing */ }

            cmp_result = (memcmp(test_bignum->nums, test_bignum_ref->nums, test_bignum_ref->size) == 0);
            if(!cmp_result)
            {
                test_inv_fail++;
                test_print_bignum(test_bignum, "test_bignum, set one bit at HIGH side inverted");
                test_print_bignum(test_bignum_ref, "test_bignum_ref");
                printf("inv_bignum() is %s\r\n", ((cmp_result)?MES_PASS:MES_FAIL));
            }
            else
            {
                test_inv_pass++;
            }
            TEST_ASSERT(cmp_result);

            for(size_t j = 0UL; j < test_bignum_ref->nlen; j++)
                test_bignum_ref->nums[j]=(~test_bignum_ref->nums[j]);
            if(fr = inv_bignum(test_bignum)) {
                printReturnType(fr);
            } else { /* Do nothing */ }
#undef _I_
#undef _L_
            test_total++;
        }
        cmp_result = (test_set1b_pass == test_total);
        printf("total test %ld of %ld about set1b_bignum() is %s\r\n", test_total, test_set1b_pass, ((cmp_result)?MES_PASS:MES_FAIL));
        cmp_result = (test_inv_pass == test_total);
        printf("total test %ld of %ld about inv_bignum() is %s\r\n", test_total, test_inv_pass, ((cmp_result)?MES_PASS:MES_FAIL));

        test_total = 0UL;
        test_set1b_pass = 0UL;
        test_clr1b_pass = 0UL;
        test_inv_pass = 0UL;
        test_set1b_fail = 0UL;
        test_clr1b_fail = 0UL;
        test_inv_fail = 0UL;
        for(size_t i = (TEST_LOGIC_BIT_CONTROL_BIT_LEN-1UL); i < SIZE_MAX; i--)
        {
#define _I_(I)    ((I)>>5U)
#define _L_(I)    ((I)&0x1FU)
            test_bignum_ref->nums[_I_(i)]&=(~(((bignum_t)1U)<<((bignum_t)_L_(i))));
            if(fr = clr1b_bignum(test_bignum, i)) {
                printReturnType(fr);
            } else { /* Do nothing */ }

            cmp_result = (memcmp(test_bignum->nums, test_bignum_ref->nums, test_bignum_ref->size) == 0);
            if(!cmp_result)
            {
                test_clr1b_pass++;
                test_print_bignum(test_bignum, "test_bignum, clr one bit at HIGH side");
                test_print_bignum(test_bignum_ref, "test_bignum_ref");
                printf("clr1b_bignum() is %s\r\n", ((cmp_result)?MES_PASS:MES_FAIL));
            }
            else
            {
                test_clr1b_pass++;
            }
            TEST_ASSERT(cmp_result);

            for(size_t j = 0UL; j < test_bignum_ref->nlen; j++)
                test_bignum_ref->nums[j]=(~test_bignum_ref->nums[j]);
            if(fr = inv_bignum(test_bignum)) {
                printReturnType(fr);
            } else { /* Do nothing */ }

            cmp_result = (memcmp(test_bignum->nums, test_bignum_ref->nums, test_bignum_ref->size) == 0);
            if(!cmp_result)
            {
                test_inv_fail++;
                test_print_bignum(test_bignum, "test_bignum, clr one bit at HIGH side inverted");
                test_print_bignum(test_bignum_ref, "test_bignum_ref");
                printf("inv_bignum() is %s\r\n", ((cmp_result)?MES_PASS:MES_FAIL));
            }
            else
            {
                test_inv_pass++;
            }
            TEST_ASSERT(cmp_result);

            for(size_t j = 0UL; j < test_bignum_ref->nlen; j++)
                test_bignum_ref->nums[j]=(~test_bignum_ref->nums[j]);
            if(fr = inv_bignum(test_bignum)) {
                printReturnType(fr);
            } else { /* Do nothing */ }
#undef _I_
#undef _L_
            test_total++;
        }
        cmp_result = (test_clr1b_pass == test_total);
        printf("total test %ld of %ld about clr1b_bignum() is %s\r\n", test_total, test_clr1b_pass, ((cmp_result)?MES_PASS:MES_FAIL));
        cmp_result = (test_inv_pass == test_total);
        printf("total test %ld of %ld about inv_bignum() is %s\r\n", test_total, test_inv_pass, ((cmp_result)?MES_PASS:MES_FAIL));
    }
    rmBitNum(&test_bignum);
#undef TEST_LOGIC_BIT_CONTROL_BIT_LEN
}

void test_find_bignum_MSBL_LSBL(void)
{
#define TEST_MSBL_LSBL_BIT_LEN  256U
    bool cmp_result;
    bool intentional_invalid;

    bignum_s* test_tmp;
    size_t test_msbl, test_lsbl;
    size_t test_ref_msbl, test_ref_lsbl;
    size_t test_ref_bitnum;

    const bignum_t test_bignum_FINC_LOC_NUM_0[] = {
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, };
    const bignum_t test_bignum_FINC_LOC_NUM_1[] = {
        0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, };
    const bignum_t test_bignum_FINC_LOC_NUM_2[] = {
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000, };
    const bignum_t test_bignum_FINC_LOC_NUM_3[] = {
        0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000, };
    const bignum_t test_bignum_FINC_LOC_NUM_4[] = {
        0x00000000, 0x00000000, 0x00000000, 0x00000001, 0x80000000, 0x00000000, 0x00000000, 0x00000000, };
    const bignum_t test_bignum_FINC_LOC_NUM_5[] = {
        0x00018000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, };
    const bignum_t test_bignum_FINC_LOC_NUM_6[] = {
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00018000, };
    const bignum_t test_bignum_FINC_LOC_NUM_7[] = {
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00018000, 0x00000000, 0x00000000, 0x00000000, };
    const bignum_t test_bignum_FINC_LOC_NUM_8[] = {
        0x00000000, 0x00000000, 0x00000000, 0x00018000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, };
    const bignum_t test_bignum_FINC_LOC_NUM_9[] = {
        0x00000000, 0x00010000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00008000, 0x00000000, };
    typedef struct {
        const bignum_t* nums;
        const size_t ref_msbl;
        const size_t ref_lsbl;
        const size_t ref_bitnum;
        const bool invalid_case;
    } test_finf_bignum_MSBnLSB_t;

    test_finf_bignum_MSBnLSB_t tvSet[] = {
        {test_bignum_FINC_LOC_NUM_0, SIZE_MAX,                       SIZE_MAX,                       0UL,   false,  },
        {test_bignum_FINC_LOC_NUM_1, 0UL,                            0UL,                            1UL,   false,  },
        {test_bignum_FINC_LOC_NUM_2, TEST_MSBL_LSBL_BIT_LEN - 1UL,   TEST_MSBL_LSBL_BIT_LEN - 1UL,   1UL,   false,  },
        {test_bignum_FINC_LOC_NUM_3, TEST_MSBL_LSBL_BIT_LEN - 1UL,   0UL,                            2UL,   false,  },
        {test_bignum_FINC_LOC_NUM_4, (5UL * BIGNUM_BITS) - 1UL,      ((4UL - 1UL) * BIGNUM_BITS),    2UL,   false,  },
        {test_bignum_FINC_LOC_NUM_5, (32UL * (1UL - 1UL)) + 16UL,    (32UL * (1UL - 1UL)) + 15UL,    2UL,   false,  },
        {test_bignum_FINC_LOC_NUM_6, (32UL * (8UL - 1UL)) + 16UL,    (32UL * (8UL - 1UL)) + 15UL,    2UL,   false,  },
        {test_bignum_FINC_LOC_NUM_7, (32UL * (5UL - 1UL)) + 16UL,    (32UL * (5UL - 1UL)) + 15UL,    2UL,   false,  },
        {test_bignum_FINC_LOC_NUM_8, (32UL * (4UL - 1UL)) + 16UL,    (32UL * (4UL - 1UL)) + 15UL,    2UL,   false,  },
        {test_bignum_FINC_LOC_NUM_9, (32UL * (7UL - 1UL)) + 15UL,    (32UL * (2UL - 1UL)) + 16UL,    2UL,   false,  },
    };

    test_tmp = mkBigNum(TEST_MSBL_LSBL_BIT_LEN);

    /* find_bignum_MSBL, find_bignum_LSBL */
    for(size_t i = 0UL; i < sizeof(tvSet)/sizeof(test_finf_bignum_MSBnLSB_t); i++)
    {
        (void)memcpy(test_tmp->nums, tvSet[i].nums, test_tmp->size);
        test_ref_msbl = tvSet[i].ref_msbl;
        test_ref_lsbl = tvSet[i].ref_lsbl;

        printf("case%ld ", i);
        test_print_bignum(test_tmp, "test_tmp");
        // run test function 'find_bignum_MSBL'
        TICK_TIME_START("find_bignum_MSBL");
        if((test_msbl = find_bignum_MSBL(test_tmp)) != SIZE_MAX) {
            TICK_TIME_END;
            printf("find_bignum_MSBL(test_tmp) = 0x%lx, %lu\r\n", test_msbl, test_msbl);
        } else {
            TICK_TIME_END;
            printf("find_bignum_MSBL: can't find MSB location\r\n");
        }
        cmp_result = (test_ref_msbl == test_msbl);

        printf("find_bignum_MSBL() is %s\r\n", (cmp_result?MES_PASS:MES_FAIL));
        TEST_ASSERT(cmp_result);

        // run test function 'find_bignum_LSBL'
        TICK_TIME_START("find_bignum_LSBL");
        if((test_lsbl = find_bignum_LSBL(test_tmp)) != SIZE_MAX) {
            TICK_TIME_END;
            printf("find_bignum_LSBL(test_tmp) = 0x%lx, %lu\r\n", test_lsbl, test_lsbl);
        } else {
            TICK_TIME_END;
            printf("find_bignum_LSBL: can't find MSB location\r\n");
        }

        cmp_result = (test_ref_lsbl == test_lsbl);
        printf("find_bignum_LSBL() is %s\r\n", (cmp_result?MES_PASS:MES_FAIL));
        TEST_ASSERT(cmp_result);
    }

    /* find_bignum_MSBL_bitLoc, find_bignum_LSBL_bitLoc */
    for(size_t i = 0UL; i < sizeof(tvSet)/sizeof(test_finf_bignum_MSBnLSB_t); i++)
    {
        (void)memcpy(test_tmp->nums, tvSet[i].nums, test_tmp->size);
        test_ref_msbl = tvSet[i].ref_msbl;
        test_ref_lsbl = tvSet[i].ref_lsbl;
        test_ref_bitnum = tvSet[i].ref_bitnum;

        printf("case[%ld] first ", i);
        test_print_bignum(test_tmp, "test_tmp");
        // run test function 'find_bignum_MSBL_bitLoc'
        TICK_TIME_START("find_bignum_MSBL_bitLoc");
        if((test_msbl = find_bignum_MSBL_bitLoc(test_tmp, test_tmp->bits-1UL)) != SIZE_MAX) {
            TICK_TIME_END;
            printf("find_bignum_MSBL_bitLoc(test_tmp) = 0x%lx, %lu\r\n", test_msbl, test_msbl);
        } else {
            TICK_TIME_END;
            printf("find_bignum_MSBL_bitLoc: can't find MSB location\r\n");
        }

        cmp_result = (test_ref_msbl == test_msbl);
        printf("find_bignum_MSBL_bitLoc() is %s\r\n", (cmp_result?MES_PASS:MES_FAIL));
        TEST_ASSERT(cmp_result);

        // run test function 'find_bignum_LSBL_bitLoc'
        TICK_TIME_START("find_bignum_LSBL_bitLoc");
        if((test_lsbl = find_bignum_LSBL_bitLoc(test_tmp, 0UL)) != SIZE_MAX) {
            TICK_TIME_END;
            printf("find_bignum_LSBL_bitLoc(test_tmp) = 0x%lx, %lu\r\n", test_lsbl, test_lsbl);
        } else {
            TICK_TIME_END;
            printf("find_bignum_LSBL_bitLoc: can't find MSB location\r\n");
        }

        cmp_result = (test_ref_lsbl == test_lsbl);
        printf("find_bignum_LSBL_bitLoc() is %s\r\n", (cmp_result?MES_PASS:MES_FAIL));
        TEST_ASSERT(cmp_result);

        printf("case[%ld] next", i);
        test_print_bignum(test_tmp, "test_tmp");
        // run test function 'find_bignum_MSBL_bitLoc'
        TICK_TIME_START("find_bignum_MSBL_bitLoc");
        if((test_msbl = find_bignum_MSBL_bitLoc(test_tmp, test_msbl-1UL)) != SIZE_MAX) {
            TICK_TIME_END;
            printf("find_bignum_MSBL_bitLoc(test_tmp) = 0x%lx, %lu\r\n", test_msbl, test_msbl);
        } else {
            TICK_TIME_END;
            printf("find_bignum_MSBL_bitLoc: can't find MSB location\r\n");
        }

        if(test_ref_bitnum == 0)
        {
            cmp_result = (test_ref_msbl == test_msbl);
            printf("find_bignum_MSBL_bitLoc() is %s\r\n", (cmp_result?MES_PASS:MES_FAIL));
            TEST_ASSERT(cmp_result);
        }
        else if(test_ref_bitnum == 1)
        {
            cmp_result = (SIZE_MAX == test_msbl);
            printf("find_bignum_MSBL_bitLoc() is %s\r\n", (cmp_result?MES_PASS:MES_FAIL));
            TEST_ASSERT(cmp_result);
        }
        else
        {
            cmp_result = (test_ref_lsbl == test_msbl);
            printf("find_bignum_MSBL_bitLoc() is %s\r\n", (cmp_result?MES_PASS:MES_FAIL));
            TEST_ASSERT(cmp_result);
        }

        // run test function 'find_bignum_LSBL_bitLoc'
        TICK_TIME_START("find_bignum_LSBL_bitLoc");
        if((test_lsbl = find_bignum_LSBL_bitLoc(test_tmp, test_lsbl+1UL)) != SIZE_MAX) {
            TICK_TIME_END;
            printf("find_bignum_LSBL_bitLoc(test_tmp) = 0x%lx, %lu\r\n", test_lsbl, test_lsbl);
        } else {
            TICK_TIME_END;
            printf("find_bignum_LSBL_bitLoc: can't find MSB location\r\n");
        }

        if(test_ref_bitnum == 0)
        {
            cmp_result = (test_ref_lsbl == test_lsbl);
            printf("find_bignum_LSBL_bitLoc() is %s\r\n", (cmp_result?MES_PASS:MES_FAIL));
            TEST_ASSERT(cmp_result);
        }
        else if(test_ref_bitnum == 1)
        {
            cmp_result = (SIZE_MAX == test_lsbl);
            printf("find_bignum_LSBL_bitLoc() is %s\r\n", (cmp_result?MES_PASS:MES_FAIL));
            TEST_ASSERT(cmp_result);
        }
        else
        {
            cmp_result = (test_ref_msbl == test_lsbl);
            printf("find_bignum_LSBL_bitLoc() is %s\r\n", (cmp_result?MES_PASS:MES_FAIL));
            TEST_ASSERT(cmp_result);
        }
    }

    rmBitNum(&test_tmp);
#undef TEST_MSBL_LSBL_BIT_LEN
}

void test_lslb_bignum(void)
{
#define TEST_LSLB_BIGNUM_BIT_LEN    1024
    bool cmp_result;
    ReturnType fr;

    size_t test_total;
    size_t test_pass;

    bignum_s* test_refer;
    bignum_s* test_bkup;
    bignum_s* test_sftb;

    test_refer = mkBigNum(TEST_LSLB_BIGNUM_BIT_LEN);
    test_bkup = mkBigNum(TEST_LSLB_BIGNUM_BIT_LEN);
    test_sftb = mkBigNum(TEST_LSLB_BIGNUM_BIT_LEN);

    printf("<Shift sequence rand>\r\n");
    test_total = 0UL;
    test_pass = 0UL;
    for(size_t lsl = 0UL; lsl < TEST_LSLB_BIGNUM_BIT_LEN; lsl++)
    {
        (void)memset(test_refer->nums, 0x0U, test_refer->size);
        (void)memset(test_sftb->nums, 0x0U, test_sftb->size);

        srand(time(NULL));
        for(size_t rvg = 0UL; rvg < TEST_LSLB_BIGNUM_BIT_LEN; rvg++)
        {
            bignum_t rbit = (rand()&0x1);
            // set reference
            if(((rvg+lsl)>>5U) < (TEST_LSLB_BIGNUM_BIT_LEN>>5U))
            {
                test_refer->nums[((rvg+lsl)>>5U)] |= (rbit<<((rvg+lsl)&0x1F));
            }

            // set init vector
            test_sftb->nums[(rvg>>5U)] |= (rbit<<(rvg&0x1F));
        }
        // backup(bkup)
        memcpy(test_bkup->nums, test_sftb->nums, test_sftb->size);

        // run test function
        if(fr = lslb_bignum_self(test_sftb, lsl)) {
            printf("lslb_bignum_self(test_sftb, %lu) = %d\r\n", lsl, fr);
        }

        cmp_result = (memcmp(test_refer->nums, test_sftb->nums, (test_refer->size)) == 0);
        if(!cmp_result)
        {
            printf("[lsl: %4lu]", lsl);
            test_print_bignum(test_bkup , "lslb(before)");
            test_print_bignum(test_refer, "refer");
            test_print_bignum(test_sftb, "lslb(after)");
        }
        else
        {
            test_pass++;
        }
        test_total++;
    }
    cmp_result = (test_total == test_pass);
    printf("total test %lu of %lu about lslb_bignum_self() is %s\r\n", test_total, test_pass, ((cmp_result)?MES_PASS:MES_FAIL));
    TEST_ASSERT(cmp_result);

    rmBitNum(&test_refer);
    rmBitNum(&test_bkup);
    rmBitNum(&test_sftb);
#undef TEST_LSLB_BIGNUM_BIT_LEN
}

void test_lsrb_bignum(void)
{
#define TEST_LSRB_BIGNUM_BIT_LEN    1024
    bool cmp_result;
    ReturnType fr;

    size_t test_total;
    size_t test_pass;

    bignum_s* test_refer;
    bignum_s* test_bkup;
    bignum_s* test_sftb;

    test_refer = mkBigNum(TEST_LSRB_BIGNUM_BIT_LEN);
    test_bkup = mkBigNum(TEST_LSRB_BIGNUM_BIT_LEN);
    test_sftb = mkBigNum(TEST_LSRB_BIGNUM_BIT_LEN);

    printf("<Shift sequence rand>\r\n");
    test_total = 0UL;
    test_pass = 0UL;
    for(size_t lsr = 0UL; lsr < TEST_LSRB_BIGNUM_BIT_LEN; lsr++)
    {
        (void)memset(test_refer->nums, 0x0U, test_refer->size);
        (void)memset(test_sftb->nums, 0x0U, test_sftb->size);

        srand(time(NULL));
        for(size_t rvg = 0UL; rvg < TEST_LSRB_BIGNUM_BIT_LEN; rvg++)
        {
            bignum_t rbit = (rand()&0x1);
            // set reference
            if(((rvg-lsr)>>5U) < (TEST_LSRB_BIGNUM_BIT_LEN>>5U))
            {
                test_refer->nums[((rvg-lsr)>>5U)] |= (rbit<<((rvg-lsr)&0x1F));
            }

            // set init vector
            test_sftb->nums[(rvg>>5U)] |= (rbit<<(rvg&0x1F));
        }
        //backup(bkup)
        memcpy(test_bkup->nums, test_sftb->nums, test_sftb->size);

        // run test function
        if(fr = lsrb_bignum_self(test_sftb, lsr)) {
            printf("lsrb_bignum_self(test_sftb, %lu) = %d\r\n", lsr, fr);
        }

        cmp_result = (memcmp(test_refer->nums, test_sftb->nums, (test_refer->size)) == 0);
        if(!cmp_result)
        {
            printf("[lsr: %4lu]", lsr);
            test_print_bignum(test_bkup, "lsrb(before)");
            test_print_bignum(test_refer, "refer");
            test_print_bignum(test_sftb, "lsrb(after)");
        }
        else
        {
            test_pass++;
        }
        test_total++;
    }
    cmp_result = (test_total == test_pass);
    printf("total test %lu of %lu about lsrb_bignum_self() is %s\r\n", test_total, test_pass, ((cmp_result)?MES_PASS:MES_FAIL));
    TEST_ASSERT(cmp_result);

    rmBitNum(&test_refer);
    rmBitNum(&test_bkup);
    rmBitNum(&test_sftb);
#undef TEST_LSRB_BIGNUM_BIT_LEN
}

void test_lslnb_bignum_self(void)
{
#define TEST_LSLNB_BIGNUM_BIT_LEN    1024
#define TEST_LSLNB_BIGNUM_NUM_LEN    32
#define _FIRST_IDX_ 0U
    bool cmp_result;
    bool test_cmp_co;
    ReturnType fr;

    size_t test_total;
    size_t test_pass;

    bignum_s* test_refer;
    bignum_t test_ref_co;
    bignum_s* test_bkup;
    bignum_s* test_sftb;
    bignum_t test_ci, test_co;

    test_refer = mkBigNum(TEST_LSLNB_BIGNUM_BIT_LEN);
    test_bkup = mkBigNum(TEST_LSLNB_BIGNUM_BIT_LEN);
    test_sftb = mkBigNum(TEST_LSLNB_BIGNUM_BIT_LEN);

    printf("<Shift sequence rand>\r\n");
    test_total = 0UL;
    test_pass = 0UL;
    for(size_t lsl = 0UL; lsl < TEST_LSLNB_BIGNUM_NUM_LEN; lsl++)
    {
        (void)memset(test_refer->nums, 0x0U, test_refer->size);
        (void)memset(test_sftb->nums, 0x0U, test_sftb->size);
        test_ci = 0U;
        test_ref_co = 0U;

        srand(time(NULL));
        /* carry into LSB */
        for(size_t cbi = 0UL; cbi < lsl; cbi++)
        {
            bignum_t rbit = (rand()&0x1);
            test_ci |= (rbit<<cbi);
        }
        // set reference
        test_refer->nums[_FIRST_IDX_] |= test_ci;

        /* shifted */
        for(size_t rvg = 0UL; rvg < TEST_LSLNB_BIGNUM_BIT_LEN; rvg++)
        {
            bignum_t rbit = (rand()&0x1);
            // set reference
            if(((rvg+lsl)>>5U) < (TEST_LSLNB_BIGNUM_BIT_LEN>>5U))
            {
                /* in bignum */
                test_refer->nums[((rvg+lsl)>>5U)] |= (rbit<<((rvg+lsl)&0x1F));
            }
            else
            {
                /* carry out */
                test_ref_co |= (rbit<<((rvg+lsl)&0x1F));
            }

            // set init vector
            test_sftb->nums[(rvg>>5U)] |= (rbit<<(rvg&0x1F));
        }
        memcpy(test_bkup->nums, test_sftb->nums, test_sftb->size);

        // run test function
        if(fr = lslnb_bignum_self(test_sftb, &test_co, test_ci, lsl)) {
            printf("lslnb_bignum_self(test_sftb, %lu) = %d\r\n", lsl, fr);
        }

        cmp_result = (memcmp(test_refer->nums, test_sftb->nums, (test_refer->size)) == 0);
        test_cmp_co = (test_ref_co == test_co);
        if((!cmp_result) || (!test_cmp_co))
        {
            printf("[lsl: %4lu]", lsl);
            printf("cin: 0x%08x\n", test_ci);
            test_print_bignum(test_bkup, "lslnb(before)");
            test_print_bignum(test_refer, "refer");
            printf("ref cout: 0x%08x\n", test_ref_co);
            test_print_bignum(test_sftb, "lslnb(after)");
            printf("cout: 0x%08x\n", test_co);
        }
        else
        {
            test_pass++;
        }
        test_total++;
    }
    cmp_result = (test_total == test_pass);
    printf("total test %lu of %lu about lslnb_bignum_self() is %s\r\n", test_total, test_pass, (cmp_result?MES_PASS:MES_FAIL));
    TEST_ASSERT(cmp_result);

    rmBitNum(&test_refer);
    rmBitNum(&test_bkup);
    rmBitNum(&test_sftb);
#undef TEST_LSLNB_BIGNUM_BIT_LEN
#undef TEST_LSLNB_BIGNUM_NUM_LEN
#undef _FIRST_IDX_
}

void test_lsrnb_bignum_self(void)
{
#define TEST_LSRNB_BIGNUM_BIT_LEN   1024
#define TEST_LSRNB_BIGNUM_NUM_LEN   32
#define _LAST_IDX_  ((TEST_LSRNB_BIGNUM_BIT_LEN/BIGNUM_BITS)-1U)
    bool cmp_result;
    bool test_cmp_co;
    ReturnType fr;

    size_t test_total;
    size_t test_pass;

    bignum_s* test_refer;
    bignum_t test_ref_co;
    bignum_s* test_bkup;
    bignum_s* test_sftb;
    bignum_t test_ci, test_co;

    test_refer = mkBigNum(TEST_LSRNB_BIGNUM_BIT_LEN);
    test_bkup = mkBigNum(TEST_LSRNB_BIGNUM_BIT_LEN);
    test_sftb = mkBigNum(TEST_LSRNB_BIGNUM_BIT_LEN);

    printf("<Shift sequence rand>\r\n");
    test_total = 0UL;
    test_pass = 0UL;
    for(size_t lsr = 0UL; lsr < TEST_LSRNB_BIGNUM_NUM_LEN; lsr++)
    {
        (void)memset(test_refer->nums, 0x0U, test_refer->size);
        (void)memset(test_sftb->nums, 0x0U, test_sftb->size);
        test_ci = 0U;
        test_ref_co = 0U;

        srand(time(NULL));
        /* carry into MSB */
        for(size_t cbi = 0UL; cbi < lsr; cbi++)
        {
            bignum_t rbit = (rand()&0x1);
            test_ci |= (rbit<<(BIGNUM_BITS-1U)-cbi);
        }
        // set reference
        test_refer->nums[_LAST_IDX_] |= test_ci;

        for(size_t rvg = 0UL; rvg < TEST_LSRNB_BIGNUM_BIT_LEN; rvg++)
        {
            bignum_t rbit = (rand()&0x1);
            // set reference
            if(((rvg-lsr)>>5U) < (TEST_LSRNB_BIGNUM_BIT_LEN>>5U))
            {
                /* in bignum */
                test_refer->nums[((rvg-lsr)>>5U)] |= (rbit<<((rvg-lsr)&0x1F));
            }
            else
            {
                /* carry out */
                test_ref_co |= (rbit<<((rvg-lsr)&0x1F));
            }

            // set init vector
            test_sftb->nums[(rvg>>5U)] |= (rbit<<(rvg&0x1F));
        }
        memcpy(test_bkup->nums, test_sftb->nums, test_sftb->size);

        // run test function
        if(fr = lsrnb_bignum_self(test_sftb, &test_co, test_ci, lsr)) {
            printf("lsrnb_bignum_self(test_sftb, %lu) = %d\r\n", lsr, fr);
        }

        cmp_result = (memcmp(test_refer->nums, test_sftb->nums, (test_refer->size)) == 0);
        test_cmp_co = (test_ref_co == test_co);
        if((!cmp_result) || (!test_cmp_co))
        {
            printf("[lsr: %4lu]", lsr);
            printf("cin: 0x%08x\n", test_ci);
            test_print_bignum(test_bkup, "lsrnb(before)");
            test_print_bignum(test_refer, "refer");
            printf("ref cout: 0x%08x\n", test_ref_co);
            test_print_bignum(test_sftb, "lsrnb(after)");
            printf("cout: 0x%08x\n", test_co);
        }
        else
        {
            test_pass++;
        }
        test_total++;
    }
    cmp_result = (test_total == test_pass);
    printf("total test %lu of %lu about lsrnb_bignum_self() is %s\r\n", test_total, test_pass, (cmp_result?MES_PASS:MES_FAIL));
    TEST_ASSERT(cmp_result);

    rmBitNum(&test_refer);
    rmBitNum(&test_bkup);
    rmBitNum(&test_sftb);
#undef TEST_LSRNB_BIGNUM_BIT_LEN
#undef TEST_LSRNB_BIGNUM_NUM_LEN
#undef _LAST_IDX_
}

void test_lsl1b_bignum_self(void)
{
#define TEST_LSL1B_BIGNUM_BIT_LEN   1024U
#define TEST_LSL1B_BIGNUM_REF       0x08108051U
#define TEST_LSL1B_BIGNUM_VAL       0x84084028U
    int test_cmp;
    ReturnType fr;

    bignum_s* test_refer;
    bignum_s* test_sft1b;
    bignum_t test_ovf;

    test_refer = mkBigNum(TEST_LSL1B_BIGNUM_BIT_LEN);
    test_sft1b = mkBigNum(TEST_LSL1B_BIGNUM_BIT_LEN);

    /* Shift sequence 1 */
    (void)memset(test_refer->nums, 0x0U, test_refer->size);
    (void)memset(test_sft1b->nums, 0x0U, test_sft1b->size);

    // set reference
    test_refer->nums[0] = 0x2U;

    // set init vector
    test_sft1b->nums[0] = 0x1U;

    test_print_bignum(test_sft1b, "sft1b(before)");
    // run test function
    TICK_TIME_START("lsl1b_bignum_self");
    if(fr = lsl1b_bignum_self(test_sft1b, &test_ovf, 0U)) {
        TICK_TIME_END;
        printf("lsl1b_bignum_self(test_sft1b, &test_ovf) = %d\r\n", fr);
    } else {
        TICK_TIME_END;
    }

    test_cmp = memcmp(test_refer->nums, test_sft1b->nums, (test_refer->size));
    test_print_bignum(test_refer, "refer");
    test_print_bignum(test_sft1b, "sft1b(after)");
    printf("lsl1b_bignum_self() is %s\r\n", ((test_cmp == 0)?MES_PASS:MES_FAIL));
    TEST_ASSERT(test_cmp == 0);

    /* Shift sequence 2 */
    (void)memset(test_refer->nums, 0x0U, test_refer->size);
    (void)memset(test_sft1b->nums, 0x0U, test_sft1b->size);

    // set reference
    for(size_t i = 0U; i < test_refer->nlen; i++) {
        test_refer->nums[i] = TEST_LSL1B_BIGNUM_REF;
    }

    // set init vector
    for(size_t i = 0U; i < test_sft1b->nlen; i++) {
        test_sft1b->nums[i] = TEST_LSL1B_BIGNUM_VAL;
    }

    test_print_bignum(test_sft1b, "sft1b(before)");
    // run test function
    TICK_TIME_START("lsl1b_bignum_self");
    if(fr = lsl1b_bignum_self(test_sft1b, &test_ovf, 1U)) {
        TICK_TIME_END;
        printf("lsl1b_bignum_self(test_sft1b, &test_ovf) = %d\r\n", fr);
    } else {
        TICK_TIME_END;
    }

    test_cmp = memcmp(test_refer->nums, test_sft1b->nums, (test_refer->size));
    test_print_bignum(test_refer, "refer");
    test_print_bignum(test_sft1b, "sft1b(after)");
    printf("lsl1b_bignum_self() is %s\r\n", ((test_cmp == 0)?MES_PASS:MES_FAIL));

    rmBitNum(&test_refer);
    rmBitNum(&test_sft1b);
#undef TEST_LSL1B_BIGNUM_BIT_LEN
#undef TEST_LSL1B_BIGNUM_REF
#undef TEST_LSL1B_BIGNUM_VAL
}

const bignum_t TV_NUMERATOR_1024b_0[] = {
    0x4369ae20, 0x29577b17, 0x58486b5a, 0x19d20572, 0x3f7f2036, 0x910a0724, 0xaf1583d5, 0x8bbfa569, 
    0x6d9b27c2, 0xc5f0b7f2, 0xb64cd781, 0x35772bea, 0xe8a7b4b4, 0xb2f102a3, 0xbde33e63, 0x92d3623e, 
    0x2b44bba5, 0xc05999bc, 0xdf9ef131, 0xf7f17c42, 0x48fa3269, 0x88d59f70, 0xbd054d17, 0x66900125, 
    0x193ba1a9, 0xc8766ff0, 0x4ef15d32, 0x15af50e9, 0x38891448, 0xb6afddd4, 0x90beb8c8, 0xb64fbc85, 
};
const bignum_t TV_DENOMINATOR_1024b_0[] = {
    0xf9d3b27b, 0x8cfa1316, 0x3ec62e31, 0xeb0ca221, 0x5a207330, 0x4c52f100, 0x2a7eebeb, 0x950f0c27, 
    0xfd13fe57, 0x1e98733b, 0x7d351fa8, 0x0022c21f, 0xa8e7ee49, 0x8eabde5d, 0xcfb8fe21, 0x095d2940, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};
const bignum_t TV_QUOTIENT_1024b_0[] = {
    0xae65dcf1, 0xe4d55616, 0x8a39ae15, 0x3e299c30, 0x0be397a4, 0x6e090208, 0xdafa658f, 0xef2f249d, 
    0xada23430, 0x58dcd9f4, 0xdddcd407, 0x74f501e1, 0xc527b7e3, 0xa8ccb137, 0x066fb7a1, 0x7836d323, 
    0x00000013, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};
const bignum_t TV_REMAINDER_1024b_0[] = {
    0x2135f455, 0xc127a75d, 0x230fbfd3, 0x7a0c5fd4, 0x1e6d12ac, 0xea276e96, 0xdf2421ee, 0x6ce4848a, 
    0x0144f4f8, 0x835f5bdc, 0x5cb2d774, 0x3deec3ed, 0xa77436eb, 0xe3e66287, 0x11577bf5, 0x02eb9703, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};
/****************************************************************************************************/

const bignum_t TV_NUMERATOR_1024b_1[] = {
    0xfaf1899d, 0xf3240f25, 0x3495f9e7, 0xcfc02f7d, 0x1d870e18, 0x959caba6, 0x9d460ee1, 0x91fa189f, 
    0x82bf2837, 0x8f58c1e8, 0xc371a10d, 0x75db1b2f, 0xe83c8e2a, 0x6805a562, 0x77e801c2, 0x77011aa0, 
    0xc30ae377, 0x59a3995a, 0xeacd51cc, 0x66154eff, 0xc0bf90e0, 0xe0c1e7d0, 0x799c3358, 0xb78f74bd, 
    0x45aa2467, 0xd3c1cff4, 0x2c145750, 0x408fa12d, 0xfaf0c207, 0x5e8dc681, 0x49cd5172, 0xc4e93a9c, 
};
const bignum_t TV_DENOMINATOR_1024b_1[] = {
    0x0e787209, 0xf60aa92f, 0x7300b29c, 0x5ae5227f, 0x980b9400, 0x8eb4459f, 0xa4a3bfbf, 0x83a577aa, 
    0x126d6da0, 0x3d79eff3, 0x91a2e7da, 0xa60ac8ba, 0x79e7b872, 0x25e34daa, 0x3d304e24, 0x88c5f495, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};
const bignum_t TV_QUOTIENT_1024b_1[] = {
    0x1bdfc9cc, 0xac2d9380, 0x6eb01bd9, 0x1decbd03, 0x82c5b3b0, 0x2f558ef1, 0xea9df955, 0x33eebc13, 
    0xcd103da5, 0x2e106968, 0xd48da85f, 0x6c1ce220, 0xcd9c5983, 0xff576ba7, 0x5e96f05d, 0x708f801c, 
    0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};
const bignum_t TV_REMAINDER_1024b_1[] = {
    0x98969971, 0xb001ccd7, 0x23544342, 0xc4c3788e, 0xd99348eb, 0x472a2c29, 0x9fe85669, 0x9c025b9d, 
    0xc27ed433, 0x1016747f, 0xf472b0c1, 0xc6839c22, 0xb74aa3d5, 0x8475d720, 0x76dc3a5c, 0x32be743d, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};
/****************************************************************************************************/

const bignum_t TV_NUMERATOR_1024b_2[] = {
    0x3820e0a9, 0xbc46364f, 0x033134af, 0x0b0f017b, 0xfec8eac5, 0x06c6fffd, 0xc0ab735c, 0x74f0cc2b, 
    0xe7e647ea, 0x6088005f, 0xc35b1b75, 0x29d38f2d, 0x6d3b6e0d, 0x8a9582ef, 0x813c6ae8, 0x145482b0, 
    0x28c175d9, 0x795e381a, 0x1ce50afc, 0xcc25e33b, 0x98dac9de, 0x87d13bcb, 0x9544d126, 0x6c4840b8, 
    0xdda4b3a4, 0x592bd7f0, 0x120bd11f, 0x8c258e79, 0x211ffedd, 0x1fab0ed6, 0xd9a73800, 0x2dd826b6, 
};
const bignum_t TV_DENOMINATOR_1024b_2[] = {
    0x439ed3eb, 0xb8dc904b, 0x1053dd11, 0x0c67019d, 0x8b274f94, 0xd121af1d, 0xebefba0a, 0xce38ba8e, 
    0x4953d964, 0x541ea44e, 0x075270c1, 0x894bf14e, 0x92c7782b, 0x686a9413, 0x17f12898, 0x378027c2, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};
const bignum_t TV_QUOTIENT_1024b_2[] = {
    0xc687dca0, 0xe44c97a9, 0x6d3f201b, 0x00bcfa47, 0xaf1933ae, 0xd37cf269, 0x679c536e, 0x6b5b4e52, 
    0x0fc5e12d, 0x6fd662c3, 0x65e8fde9, 0x8b2e6e58, 0xa3153f13, 0x3188e363, 0x13cacf04, 0xd375ba3a, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};
const bignum_t TV_REMAINDER_1024b_2[] = {
    0xf3d179c9, 0xcfd0555b, 0x401cd294, 0xabfbac76, 0xbc0386f0, 0x11c5e069, 0x269eb2d5, 0x9cc84abe, 
    0xc550e201, 0x8803d895, 0xd859705e, 0x167e6107, 0x51064615, 0x14f85c94, 0x8eaf2234, 0x127024a8, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};
/****************************************************************************************************/

const bignum_t TV_NUMERATOR_1024b_3[] = {
    0xa0926d45, 0x870f4cb0, 0x2fb5c028, 0x12bfbe38, 0x94ac8292, 0x7e38d912, 0xabaa9bd1, 0xe0d00b25, 
    0xb94556ea, 0x58be8753, 0xbc17160d, 0x223e96d5, 0xc9140710, 0xbc652978, 0x17bda4ac, 0xb29edd06, 
    0x1285c6c9, 0x40c9fe0a, 0x92a3bba9, 0x91cd3a07, 0xa2422259, 0xf38f8285, 0x22f7947d, 0x6837dc7f, 
    0x262af60d, 0x4117a18e, 0x53c9309b, 0x8c654a0b, 0xf6be08b2, 0xc4a2ece6, 0x9bc38c6d, 0x9618c589, 
};
const bignum_t TV_DENOMINATOR_1024b_3[] = {
    0x13794946, 0xd52a8165, 0x2fb7ad7b, 0x77b5ddf0, 0xf2cdc86a, 0xd7ec2e65, 0xba3d6a6d, 0xc2b5252c, 
    0xb7e71962, 0x41fe227f, 0x971dd036, 0x0b8989a6, 0x7d5e5c5e, 0x2e9ec4a6, 0x5659022f, 0x9d05982d, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};
const bignum_t TV_QUOTIENT_1024b_3[] = {
    0x84845e80, 0x3b50c21f, 0xaa757dc1, 0x4489ec98, 0xc43806a9, 0xb23ca303, 0x57425411, 0xd6694be5, 
    0xc7743723, 0x5921a2e2, 0xea3a93b8, 0xbda3662b, 0xae8b7bba, 0x1ede7eca, 0x1ca434ec, 0xf4b5af53, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};
const bignum_t TV_REMAINDER_1024b_3[] = {
    0x7aee1645, 0x330bfd34, 0xf2eafbc6, 0x87f59f70, 0x01150232, 0xb7426296, 0xb8807926, 0x5a3cbe55, 
    0x538d4d04, 0x0a3cd84a, 0xf3a16b0a, 0x68d3cbba, 0xcdbac9dc, 0xd1bd4f8d, 0x1996ac0f, 0x0b94d376, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};
/****************************************************************************************************/

const bignum_t TV_NUMERATOR_1024b_4[] = {
    0x4264c4a4, 0xf9eba54b, 0x9a4bbd26, 0x97fa6782, 0xe5b25b56, 0x31b376e5, 0x0067417d, 0x7c080fdf, 
    0xc859faf7, 0x72581148, 0xd60e1ff5, 0x0c7a32ea, 0xbfe9d15e, 0x0ae1cecc, 0xb171b8aa, 0x399fe3cd, 
    0x84d132cb, 0xd326ad0b, 0x8deb6f4e, 0x729d3988, 0xb1b21f2d, 0x725d4fe8, 0x7617f4f9, 0x2c40afec, 
    0xab27b620, 0xdffe5671, 0xf1b01a09, 0x86030dcb, 0x33b95816, 0xb0d5ae26, 0x1aa0395e, 0xd354ceb9, 
};
const bignum_t TV_DENOMINATOR_1024b_4[] = {
    0x6b979f34, 0xec6ac3f0, 0xc62ea9d3, 0xcef9564e, 0xed59d37e, 0x02aea1fb, 0x256f7eb8, 0x02e8fa54, 
    0x1ea84261, 0x6a2748ea, 0x50cde0a4, 0x57829c2f, 0xa2e92a07, 0xd1175505, 0xba6675dc, 0x1c4e49cd, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};
const bignum_t TV_QUOTIENT_1024b_4[] = {
    0x37c6d868, 0xc05e736b, 0xb33b0a5f, 0x53920afb, 0x3af619d1, 0xac7195dc, 0xc81deb93, 0x052b6dce, 
    0xdec23152, 0xc204efea, 0xc59099db, 0x89534e47, 0x25d943c2, 0x9a4c2e4c, 0xcf7bd76c, 0x774bf2df, 
    0x00000007, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};
const bignum_t TV_REMAINDER_1024b_4[] = {
    0x50403784, 0x1c2c7fa2, 0xe641e9b7, 0x1efc761b, 0xceee0c62, 0xb1bff1f4, 0x3b43a565, 0xe61d9046, 
    0x26e66d26, 0x79538463, 0x7ae45b68, 0xcd5cdce5, 0x5bf36d45, 0x8d77aa30, 0x7391e0b6, 0x1a711823, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};
/****************************************************************************************************/

const bignum_t TV_NUMERATOR_1024b_5[] = {
    0x7ff1a049, 0x45465c34, 0x7916b3a4, 0xda202fdf, 0xd6fb1151, 0xf30ad4e9, 0x478e634c, 0x915adb97, 
    0x46981d4c, 0xbcef47c9, 0x4a3ae092, 0x044f72f5, 0xcf4ad2ef, 0x430c194b, 0x89171091, 0x7f2fdd4b, 
    0x3c9d0192, 0x6c37a7da, 0xd6df304b, 0xb88b3a5d, 0xaf8c3cca, 0xba3845ab, 0xbfb44d41, 0xe0774189, 
    0xc88b97c8, 0xc01cc085, 0x69b42aa4, 0x8af1a721, 0x5252aa75, 0xf8a79a52, 0x4e85203a, 0x9863140f, 
};
const bignum_t TV_DENOMINATOR_1024b_5[] = {
    0x20a19afd, 0x64c5c88d, 0xd3496d3e, 0xf21f760a, 0x8e203ca2, 0x3c54370a, 0xc67c0256, 0x30f7c87f, 
    0x95fe1824, 0x448709c1, 0x1d17d10e, 0xc2322b5a, 0x9be3e81a, 0xadc996a9, 0xe8a07720, 0xcabc0151, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};
const bignum_t TV_QUOTIENT_1024b_5[] = {
    0xf89cb9b5, 0xf955c36b, 0x9a8451db, 0xe3da3c9e, 0x051519f0, 0x61d8bf41, 0xd47e4019, 0xd5e52ac0, 
    0x2f842c09, 0x5696224e, 0xd45436db, 0x42179c8a, 0xd0807408, 0x5de6dd7a, 0x4df1602a, 0xc06cb079, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};
const bignum_t TV_REMAINDER_1024b_5[] = {
    0x1a823668, 0xe249a479, 0x37d06135, 0xe018c89d, 0x04982da3, 0x2b9f7c78, 0xcc4dd976, 0x43580531, 
    0xb0381043, 0xddc8c64d, 0x296515d3, 0xc0f652b4, 0x94194be5, 0x39f7b160, 0xc7a7059a, 0x01ce11dd, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};
/****************************************************************************************************/

const bignum_t TV_NUMERATOR_1024b_6[] = {
    0x9575d4fb, 0x166940e5, 0x60aa4334, 0xde3768bb, 0x075475a2, 0x5d87f7f7, 0xbcc075a5, 0xd7e124c4, 
    0x86b43ec1, 0xe0b75b1d, 0xad47e79b, 0x84c910e1, 0x21d594e3, 0x49a970ac, 0xbced59c7, 0x3810eea9, 
    0x6e70f165, 0xe529a312, 0x59fe346f, 0x4f61e2c8, 0x20a66543, 0xfd21d7ba, 0x1f0bb404, 0xa0c2c86c, 
    0x97cdd148, 0x08e38369, 0x9e439e4e, 0x52d953ac, 0x4d3896d6, 0xcc83dce8, 0xb3c96103, 0x200a950d, 
};
const bignum_t TV_DENOMINATOR_1024b_6[] = {
    0x6f1c3162, 0x23f5177e, 0xb17060fa, 0x54175109, 0xf5b30688, 0xa2841f54, 0x62059f33, 0x4e871b69, 
    0x0e3dd3c6, 0xeabe3ffe, 0xd7342862, 0xe353b522, 0x87d911bb, 0x334e4c9a, 0x5b1489a9, 0x9871c599, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};
const bignum_t TV_QUOTIENT_1024b_6[] = {
    0x7b991b14, 0x621b4c09, 0xb7227639, 0x2d786ce2, 0x87440678, 0x70b2db42, 0x86a0ad87, 0xea0313b4, 
    0xf5c6b554, 0xb65383ad, 0x287f42b6, 0x615eec88, 0xe6c33306, 0x0ac9b310, 0x269bbeff, 0x35ce99d0, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};
const bignum_t TV_REMAINDER_1024b_6[] = {
    0x547aa353, 0xa3d94d47, 0x445e03f8, 0x53a25e43, 0x7dd1374f, 0x63a2ca2a, 0x945d4fbd, 0x27758ff6, 
    0xaddabf86, 0x78557eaa, 0x34771b8b, 0xc34af029, 0xcce4d9bc, 0xe7dd960f, 0x7ec77867, 0x7552e8fa, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};
/****************************************************************************************************/

const bignum_t TV_NUMERATOR_1024b_7[] = {
    0x77af3cce, 0x725b42b2, 0x593b282b, 0xf7274ace, 0x67a2f852, 0x54da40fa, 0x0f43a86a, 0xb26cb7b3, 
    0x5bafe94b, 0x00e2ac3c, 0xbdf81dd1, 0xd8cdd4bf, 0x960ae503, 0x297af2e1, 0x3aeabc5f, 0xf953d52b, 
    0xcf72c971, 0xeb85eba6, 0x2357a11d, 0xbd7bb78d, 0x5e642e49, 0xd31355c3, 0xb273708d, 0xa37e431c, 
    0x62856a9c, 0x33a9257f, 0x5caa59d0, 0x21e09f35, 0x07522266, 0x494170bf, 0x86e7b562, 0x1ac70979, 
};
const bignum_t TV_DENOMINATOR_1024b_7[] = {
    0xe5cad925, 0x82bc2ada, 0x8f3bd899, 0x3f708e05, 0x1dc3da78, 0x91e4db09, 0xe7a0132a, 0x8c611be8, 
    0x14b150a5, 0xf6d36ce4, 0xf4dcf064, 0x9d7d453b, 0x97c1b611, 0xe82a33c3, 0x8ba402c5, 0x268d82e4, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};
const bignum_t TV_QUOTIENT_1024b_7[] = {
    0xa473601a, 0xeb0ca473, 0x23f1319d, 0xe38dde3e, 0x519fc94e, 0xeea78b20, 0x73eb626c, 0x0b196866, 
    0x0158c20e, 0x0b87d796, 0x3f8697ba, 0xd20b0d3f, 0x7d804be3, 0x8770e211, 0x9a07d3a6, 0xb1cf24d9, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};
const bignum_t TV_REMAINDER_1024b_7[] = {
    0xd0084f0c, 0xcdaa6570, 0x423b9a7e, 0xc474ae2c, 0xcdfb33e1, 0xb5a0973d, 0x9d2a29b8, 0x45b8a995, 
    0x42b2ad7f, 0x3f317ccf, 0x4fd61c91, 0xb00c3c46, 0xb9e2259f, 0x734eae94, 0x6ced245b, 0x09b51f93, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};
/****************************************************************************************************/

const bignum_t TV_NUMERATOR_1024b_8[] = {
    0x3c5486e9, 0xabd9377b, 0x9479bcd1, 0x7bbe870e, 0x3d831a86, 0x7a0018ac, 0x64682e6a, 0x5b05ff72, 
    0x00985985, 0x62ab7191, 0x3cf6242d, 0x32b7b4ac, 0x7b703bcf, 0xbef57053, 0x11225d9f, 0xe16d275c, 
    0x11e10580, 0xa4738c76, 0x5de069b1, 0xed8f971e, 0x2668ffd2, 0x0fe45e70, 0x182006bb, 0xadf98d2d, 
    0x09bfdb92, 0x18ad3267, 0xba758d9c, 0xf7a70524, 0x741d0f04, 0x2983016d, 0x3441a407, 0xc4e13a31, 
};
const bignum_t TV_DENOMINATOR_1024b_8[] = {
    0x7dcda015, 0x6f957ad3, 0x2b290b07, 0x1422d010, 0x4d893fdf, 0x47760c40, 0xe27bb7b0, 0x07a65df1, 
    0xd08473fd, 0xf43f19ed, 0x341f6824, 0x18494238, 0xc265d281, 0x8f09dbde, 0x83718592, 0xdf8a17e2, 
    0x77b00e8a, 0x4c6bef28, 0x90818a58, 0x4ea8cacc, 0x7a100d9c, 0x7a0919e8, 0x80fe7a9e, 0x1b608891, 
    0xbf921097, 0x570bfdff, 0x54e88c88, 0xf2a29056, 0x866db29e, 0x6a0176cc, 0x82ebfff1, 0x1e9e4b87, 
};
const bignum_t TV_QUOTIENT_1024b_8[] = {
    0x00000006, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};
const bignum_t TV_REMAINDER_1024b_8[] = {
    0x4982c66b, 0x0e585686, 0x91837aa5, 0x02eda6ad, 0x6c4b9b4c, 0xcd3bcf2a, 0x1581e048, 0x2d1fcbc7, 
    0x1d7da197, 0xa930d5fe, 0x0439b34f, 0xa100275b, 0xed0d4cc8, 0x64ba491a, 0xfc793c30, 0xa430980c, 
    0x43c0ae3f, 0xd9ebf183, 0xfad72b9f, 0x159ad652, 0x4a08ae29, 0x33adc2fd, 0x12292704, 0x09b659c4, 
    0x8c537808, 0x0e653e68, 0xbd02426a, 0x47d7a31e, 0x4d8adf4b, 0xad7a38a2, 0x22b9a45e, 0x0d2b7504, 
};

const bignum_t* TV_LIST_NUMERATOR_1024b[] = {
    TV_NUMERATOR_1024b_0,
    TV_NUMERATOR_1024b_1,
    TV_NUMERATOR_1024b_2,
    TV_NUMERATOR_1024b_3,
    TV_NUMERATOR_1024b_4,
    TV_NUMERATOR_1024b_5,
    TV_NUMERATOR_1024b_6,
    TV_NUMERATOR_1024b_7,
    TV_NUMERATOR_1024b_8,
};
const bignum_t* TV_LIST_DENOMINATOR_1024b[] = {
    TV_DENOMINATOR_1024b_0,
    TV_DENOMINATOR_1024b_1,
    TV_DENOMINATOR_1024b_2,
    TV_DENOMINATOR_1024b_3,
    TV_DENOMINATOR_1024b_4,
    TV_DENOMINATOR_1024b_5,
    TV_DENOMINATOR_1024b_6,
    TV_DENOMINATOR_1024b_7,
    TV_DENOMINATOR_1024b_8,
};
const bignum_t* TV_LIST_QUOTIENT_1024b[] = {
    TV_QUOTIENT_1024b_0,
    TV_QUOTIENT_1024b_1,
    TV_QUOTIENT_1024b_2,
    TV_QUOTIENT_1024b_3,
    TV_QUOTIENT_1024b_4,
    TV_QUOTIENT_1024b_5,
    TV_QUOTIENT_1024b_6,
    TV_QUOTIENT_1024b_7,
    TV_QUOTIENT_1024b_8,
};
const bignum_t* TV_LIST_REMAINDER_1024b[] = {
    TV_REMAINDER_1024b_0,
    TV_REMAINDER_1024b_1,
    TV_REMAINDER_1024b_2,
    TV_REMAINDER_1024b_3,
    TV_REMAINDER_1024b_4,
    TV_REMAINDER_1024b_5,
    TV_REMAINDER_1024b_6,
    TV_REMAINDER_1024b_7,
    TV_REMAINDER_1024b_8,
};

typedef ReturnType (*TEST_FP_BIGNUM_MUL)(bignum_s*, const bignum_s*, const bignum_s*);
void test_mul_bignum_sameBignumLength_with_mod_value(const char* test_fn_name, const TEST_FP_BIGNUM_MUL test_fp)
{
#define TEST_MUL_BIGNUM_BIT_LEN   1024U
    char keyin;
    int test_memcmp0;
    ReturnType fr;

    bool manually = false;

    bignum_s* multiplier = mkBigNum(TEST_MUL_BIGNUM_BIT_LEN);
    bignum_s* multiplicand = mkBigNum(TEST_MUL_BIGNUM_BIT_LEN);
    bignum_s* product = mkBigNum(TEST_MUL_BIGNUM_BIT_LEN);

#define _KEYIN_DO_TEST_0_(c, TEST_FUNC_NAME) { \
    (c) = '\0'; \
    do { \
        printf("%s: ", (TEST_FUNC_NAME)); \
        (c) = getchar(); \
        getchar(); \
        if('A' <= (c) && (c) <= 'Z')    break; \
        if('a' <= (c) && (c) <= 'z')    break; \
    } while(((c) != 'y' ) && ((c) != 'Y' )); \
    if('A' <= (c) && (c) <= 'Z')    (c) += 0x20; \
}
#define _COND_DO_TEST_0_(c)   if((c) == 'y')
    _KEYIN_DO_TEST_0_(keyin, "Test Manually?(y/n)");
    _COND_DO_TEST_0_(keyin) manually = true;

    if(!manually)
    {
        bignum_s* addedNumber = mkBigNum(TEST_MUL_BIGNUM_BIT_LEN);
        bignum_s* productAddRem = mkBigNum(TEST_MUL_BIGNUM_BIT_LEN);

        for(size_t i = 0UL; i < sizeof(TV_LIST_REMAINDER_1024b)/sizeof(bignum_t*); i++)
        {
            memcpy(multiplier->nums, TV_LIST_QUOTIENT_1024b[i], multiplier->size);
            memcpy(multiplicand->nums, TV_LIST_DENOMINATOR_1024b[i], multiplicand->size);

            memcpy(addedNumber->nums, TV_LIST_REMAINDER_1024b[i], addedNumber->size);


            TICK_TIME_START(test_fn_name);
            fr = test_fp(product, multiplier, multiplicand);
            TICK_TIME_END;
#if 1 /*_mod_values_are_only_valid_in_unsafety_multiplication_functions_*/
            printf("%s() = ", test_fn_name);
            printReturnType(fr);
#endif/*_mod_values_are_only_valid_in_unsafety_multiplication_functions_*/

            if(fr = add_bignum(NULL, productAddRem, product, addedNumber, 0U)) {
                printReturnType(fr);
            } else { /* Do nothing */ }

            test_memcmp0 = memcmp(productAddRem->nums, TV_LIST_NUMERATOR_1024b[i], productAddRem->size);
            if(test_memcmp0 != 0)
            {
                test_print_bignum(multiplier, "multiplier");
                test_print_bignum(multiplicand, "multiplicand");
                test_print_bignum(product, "product");
            }
            printf("[%lu] %s() then add to remainder is %s\r\n", i, test_fn_name, ((test_memcmp0 == 0)?MES_PASS:MES_FAIL));
#if 0 /*_mod_values_are_only_valid_in_unsafety_multiplication_functions_*/
            TEST_ASSERT(test_memcmp0 == 0);
#endif/*_mod_values_are_only_valid_in_unsafety_multiplication_functions_*/
        }

        rmBitNum(&productAddRem);
        rmBitNum(&addedNumber);
    }
    else
    {
        for(size_t i = 0UL; i < 0x10UL; i++)
        {
            (void)memset(multiplier->nums, 0U, multiplier->size);
            (void)memset(multiplicand->nums, 0U, multiplicand->size);
            (void)memset(product->nums, 0U, product->size);
            /* set test vector*/

            srand(time(NULL)+i);
            for(size_t byte = 0UL; byte < (multiplier->size)>>1UL; byte++)
            {
                ((uint8_t*)multiplier->nums)[byte] = (rand()&0xFFU);
            }
            for(size_t byte = 0UL; byte < (multiplicand->size)>>1UL; byte++)
            {
                ((uint8_t*)multiplicand->nums)[byte] = (rand()&0xFFU);
            }

            /* multiplier */
            TICK_TIME_START(test_fn_name);
            fr = test_fp(product, multiplier, multiplicand);
            TICK_TIME_END;
            printf("%s() = ", test_fn_name);
            printReturnType(fr);
            printf("********************************************************************************\n");
            printf("TEST RANDOM_NUMBERS, MANUALLY 'COMPARE WITH https://defuse.ca/big-number-calculator.htm'\n");
            printf("%s()", test_fn_name);
            test_print_bignum(multiplier, "multiplier");
            test_print_bignum(multiplicand, "multiplicand");
            test_print_bignum(product, "product");

            printf("[PRODUCT]\n");
            test_print_bignum_value_only(multiplier);
            printf("*");
            test_print_bignum_value_only(multiplicand);
            printf("\n");
            test_print_bignum_value_only(product);
            printf("\n");

            printf("********************************************************************************\n");
            _KEYIN_DO_TEST_0_(keyin, "check result(y)");
        }
    }
#undef _KEYIN_DO_TEST_0_
#undef _COND_DO_TEST_0_

    rmBitNum(&multiplier);
    rmBitNum(&multiplicand);
    rmBitNum(&product);
#undef TEST_MUL_BIGNUM_BIT_LEN
}

void test_div_bignum_with_mod(void)
{
#define TEST_DIV_BIGNUM_BIT_LEN   1024U
    char keyin;
    int test_memcmp0, test_memcmp1;
    ReturnType fr;

    bignum_s* numerator = mkBigNum(TEST_DIV_BIGNUM_BIT_LEN);
    bignum_s* denominator = mkBigNum(TEST_DIV_BIGNUM_BIT_LEN);
    bignum_s* quotient = mkBigNum(TEST_DIV_BIGNUM_BIT_LEN);
    bignum_s* remainder = mkBigNum(TEST_DIV_BIGNUM_BIT_LEN);

    bool manually = false;

#define _KEYIN_DO_TEST_0_(c, TEST_FUNC_NAME) { \
    (c) = '\0'; \
    do { \
        printf("%s: ", (TEST_FUNC_NAME)); \
        (c) = getchar(); \
        getchar(); \
        if('A' <= (c) && (c) <= 'Z')    break; \
        if('a' <= (c) && (c) <= 'z')    break; \
    } while(((c) != 'y' ) && ((c) != 'Y' )); \
    if('A' <= (c) && (c) <= 'Z')    (c) += 0x20; \
}
#define _COND_DO_TEST_0_(c)   if((c) == 'y')
    _KEYIN_DO_TEST_0_(keyin, "Test Manually?(y/n)");
    _COND_DO_TEST_0_(keyin) manually = true;

    if(!manually)
    {
        for(size_t i = 0UL; i < sizeof(TV_LIST_REMAINDER_1024b)/sizeof(bignum_t*); i++)
        {
            memcpy(numerator->nums, TV_LIST_NUMERATOR_1024b[i], numerator->size);
            memcpy(denominator->nums, TV_LIST_DENOMINATOR_1024b[i], denominator->size);

            /* Divide with Modulo: 'n'umerator = 'q'uotient * 'd'enominator + 'r'emainder */
            TICK_TIME_START("div_bignum_with_mod");
            if(fr = div_bignum_with_mod(quotient, remainder, numerator, denominator)) {
                printReturnType(fr);
            } else { /* Do nothing */ }
            TICK_TIME_END;

            test_memcmp0 = memcmp(quotient->nums, TV_LIST_QUOTIENT_1024b[i], quotient->size);
            test_memcmp1 = memcmp(remainder->nums, TV_LIST_REMAINDER_1024b[i], remainder->size);
            printf("[%lu] div_bignum_with_mod() divide is %s\r\n", i, ((test_memcmp0 == 0)?MES_PASS:MES_FAIL));
            printf("[%lu] div_bignum_with_mod() modulo is %s\r\n", i, ((test_memcmp1 == 0)?MES_PASS:MES_FAIL));
            if((test_memcmp0 != 0) || (test_memcmp1 != 0))
            {
                test_print_bignum(numerator, "numerator");
                test_print_bignum(denominator, "denominator");
                test_print_bignum(quotient, "quotient");
                test_print_bignum(remainder, "remainder");
#if 0 /* TEST */
                printf("[ref quotient]\r\n");
                printf("quotient->size: %lu\r\n", quotient->size);
                test_print_bignum_array(TV_LIST_QUOTIENT_1024b[i], quotient->nlen);
                printf("[ref remainder]\r\n");
                printf("remainder->size: %lu\r\n", remainder->size);
                test_print_bignum_array(TV_LIST_REMAINDER_1024b[i], remainder->nlen);
#endif/* TEST */

            }
            TEST_ASSERT((test_memcmp0 == 0) && (test_memcmp1 == 0));
        }
    }
    else
    {
        for(size_t i = 0UL; i < 0x10UL; i++)
        {
            (void)memset(numerator->nums, 0U, numerator->size);
            (void)memset(denominator->nums, 0U, denominator->size);
            (void)memset(quotient->nums, 0U, quotient->size);
            (void)memset(remainder->nums, 0U, remainder->size);
            /* set test vector*/

            srand(time(NULL)+i);
            for(size_t byte = 0UL; byte < numerator->size; byte++)
            {
                ((uint8_t*)numerator->nums)[byte] = (rand()&0xFFU);
            }
            for(size_t byte = 0UL; byte < (denominator->size)>>1UL; byte++)
            {
                ((uint8_t*)denominator->nums)[byte] = (rand()&0xFFU);
            }

            /* Divide with Modulo: 'n'umerator = 'q'uotient * 'd'enominator + 'r'emainder */
            TICK_TIME_START("div_bignum_with_mod");
            if(fr = div_bignum_with_mod(quotient, remainder, numerator, denominator)) {
                printReturnType(fr);
            } else { /* Do nothing */ }
            TICK_TIME_END;
            printf("********************************************************************************\n");
            printf("TEST RANDOM_NUMBERS, MANUALLY 'COMPARE WITH https://defuse.ca/big-number-calculator.htm'\n");
            test_print_bignum(numerator, "numerator");
            test_print_bignum(denominator, "denominator");
            test_print_bignum(quotient, "quotient");
            test_print_bignum(remainder, "remainder");

            printf("[DIVIDE]\n");
            test_print_bignum_value_only(numerator);
            printf("/");
            test_print_bignum_value_only(denominator);
            printf("\n");
            test_print_bignum_value_only(quotient);
            printf("\n");

            printf("[MODULO]\n");
            test_print_bignum_value_only(numerator);
            printf("%%");
            test_print_bignum_value_only(denominator);
            printf("\n");
            test_print_bignum_value_only(remainder);
            printf("\n");

            printf("********************************************************************************\n");
            _KEYIN_DO_TEST_0_(keyin, "check result(y)");
        }
    }
#undef _KEYIN_DO_TEST_0_
#undef _COND_DO_TEST_0_

    rmBitNum(&numerator);
    rmBitNum(&denominator);
    rmBitNum(&quotient);
    rmBitNum(&remainder);
#undef TEST_DIV_BIGNUM_BIT_LEN
}

void test_gcd_bignum(void)
{
#define TEST_GCD_BIGNUM_BIT_LEN   1024U
    char keyin;
    int test_memcmp0, test_memcmp1;
    ReturnType fr;

    bignum_s* num_a = mkBigNum(TEST_GCD_BIGNUM_BIT_LEN);
    bignum_s* num_b = mkBigNum(TEST_GCD_BIGNUM_BIT_LEN);
    bignum_s* num_g = mkBigNum(TEST_GCD_BIGNUM_BIT_LEN);
    bignum_s* num_s = mkBigNum(TEST_GCD_BIGNUM_BIT_LEN);
    bignum_s* num_t = mkBigNum(TEST_GCD_BIGNUM_BIT_LEN);
    bignum_s* prod_as = mkBigNum(TEST_GCD_BIGNUM_BIT_LEN);
    bignum_s* prod_bt = mkBigNum(TEST_GCD_BIGNUM_BIT_LEN);
    bignum_s* sum = mkBigNum(TEST_GCD_BIGNUM_BIT_LEN);
    bignum_cmp_e num_cmp;

    bool manually = false;

#define _KEYIN_DO_TEST_0_(c, TEST_FUNC_NAME) { \
    (c) = '\0'; \
    do { \
        printf("%s: ", (TEST_FUNC_NAME)); \
        (c) = getchar(); \
        getchar(); \
        if('A' <= (c) && (c) <= 'Z')    break; \
        if('a' <= (c) && (c) <= 'z')    break; \
    } while(((c) != 'y' ) && ((c) != 'Y' )); \
    if('A' <= (c) && (c) <= 'Z')    (c) += 0x20; \
}
#define _COND_DO_TEST_0_(c)   if((c) == 'y')
    _KEYIN_DO_TEST_0_(keyin, "Test Manually?(y/n)");
    _COND_DO_TEST_0_(keyin) manually = true;

#if 0 /* NO_MANUALL_YET */
    if(!manually)
    {
        for(size_t i = 0UL; i < sizeof(TV_LIST_REMAINDER_1024b)/sizeof(bignum_t*); i++)
        {
            memcpy(num_a->nums, TV_LIST_NUMERATOR_1024b[i], num_a->size);
            memcpy(num_b->nums, TV_LIST_DENOMINATOR_1024b[i], num_b->size);

            /* Divide with Modulo: 'n'umerator = 'q'uotient * 'd'enominator + 'r'emainder */
            TICK_TIME_START("div_bignum_with_mod");
            if(fr = TEST_FUNCTION_NAME(...)) {
                printReturnType(fr);
            } else { /* Do nothing */ }
            TICK_TIME_END;

            test_memcmp0 = memcmp(num_g->nums, TV_LIST_QUOTIENT_1024b[i], quotient->size);
            test_memcmp1 = memcmp(num_s->nums, TV_LIST_REMAINDER_1024b[i], num_s->size);
            printf("TEST_FUNCTION_NAME() divide is %s\r\n", ((test_memcmp0 == 0)?MES_PASS:MES_FAIL));
            printf("TEST_FUNCTION_NAME() modulo is %s\r\n", ((test_memcmp1 == 0)?MES_PASS:MES_FAIL));
            TEST_ASSERT((test_memcmp0 == 0) && (test_memcmp1 == 0));
        }
    }
    else
    {
#endif/* NO_MANUALL_YET */
        /* 
         * Value Example: https://ko.wikipedia.org/wiki/%EC%9C%A0%ED%81%B4%EB%A6%AC%EB%93%9C_%ED%98%B8%EC%A0%9C%EB%B2%95
         *            GLUE     SEQ     SEQ     SEQ     SEQ    GLUE      GLUE     SEQ     SEQ    GLUE      GLUE
         * | index |     q | old r |     r | old s |     s |    qs | olds-qs | old t |     t |    qt | oldt-qt |
         * |  init |     4 | 78696 | 19332 |     1 |     0 |     0 |       1 |     0 |     1 |     4 |      -4 |
         * |     0 |    14 | 19332 |  1368 |     0 |     1 |    14 |     -14 |     1 |    -4 |    -5 |      57 |
         * |     1 |     7 |  1368 |   180 |     1 |   -14 |   -98 |      99 |    -4 |    57 |   399 |    -403 |
         * |     2 |     1 |   180 |   108 |   -14 |    99 |    99 |    -113 |    57 |  -403 |  -403 |     460 |
         * |     3 |     1 |   108 |    72 |    99 |  -113 |  -113 |     212 |  -403 |   460 |   460 |    -863 |
         * |     4 |     2 |    72 |    36 |  -113 |   212 |   424 |    -537 |   460 |  -863 | -1726 |    2186 |
         * |     5 |   INF |    36 |     0 |   212 |  -537 |     0 |     212 |  -863 |  2186 |     0 |    -863 |
         * a       :     78696
         * s(old_s):       212
         * b       :     19332
         * t(old_t):      -863
         * as      :  16683552
         *      bt : -16683516
         * as + bt :        36
         */
        (void)memset(num_a->nums, 0U, num_a->size);
        (void)memset(num_b->nums, 0U, num_b->size);
        (void)memset(num_g->nums, 0U, num_g->size);
        (void)memset(num_s->nums, 0U, num_s->size);
        (void)memset(num_t->nums, 0U, num_t->size);
        /* set test vector*/
        num_a->nums[0] = 78696U;
        num_b->nums[0] = 19332;

        /* Divide with Modulo: 'n'umerator = 'q'uotient * 'd'enominator + 'r'emainder */
        TICK_TIME_START("gcd_bignum");
        if(fr = gcd_bignum(num_g, num_s, num_t, num_a, num_b)) {
            printReturnType(fr);
        } else { /* Do nothing */ }
        TICK_TIME_END;
        printf("********************************************************************************\n");
        printf("TEST RANDOM_NUMBERS, MANUALLY 'COMPARE WITH https://defuse.ca/big-number-calculator.htm'\n");
        test_print_bignum(num_a, "num_a");
        test_print_bignum(num_b, "num_b");
        test_print_bignum(num_g, "gcd");
        test_print_bignum(num_s, "coef s");
        test_print_bignum(num_t, "coef t");

        if((fr = mul_bignum_unsafe(prod_as, num_a, num_s)) != E_OK)     { /* has error */ printf("%s, line:%d, fr: %d\n", __func__, __LINE__, fr); };
        if((fr = mul_bignum_unsafe(prod_bt, num_b, num_t)) != E_OK)     { /* has error */ printf("%s, line:%d, fr: %d\n", __func__, __LINE__, fr); };
        if((fr = add_bignum(NULL, sum, prod_as, prod_bt, 0UL)) != E_OK) { /* has error */ printf("%s, line:%d, fr: %d\n", __func__, __LINE__, fr); };
        test_print_bignum(prod_as, "prod_as");
        test_print_bignum(prod_bt, "prod_bt");
        test_print_bignum(num_b, "num_b");

        num_cmp = cmp_bignum_logical(sum, num_g);
        printf("a*s+b*t=gcd(a,b) is %s\r\n", ((num_cmp == BIGNUM_CMP_EQ)?MES_PASS:MES_FAIL));


        printf("********************************************************************************\n");
        _KEYIN_DO_TEST_0_(keyin, "check result(y)");
#if 0 /* NO_MANUALL_YET */
    }
#endif/* NO_MANUALL_YET */
#undef _KEYIN_DO_TEST_0_
#undef _COND_DO_TEST_0_

    rmBitNum(&num_a);
    rmBitNum(&num_b);
    rmBitNum(&num_g);
    rmBitNum(&num_s);
    rmBitNum(&num_t);
    rmBitNum(&prod_as);
    rmBitNum(&prod_bt);
    rmBitNum(&sum);
#undef TEST_GCD_BIGNUM_BIT_LEN
}

const ReturnType TEST_MMI_FR_0 = E_OK;
const bignum_t TEST_MMI_NUM_A_0[] = {
    0xf93aebfa, 0x9e703695, 0x099f8d99, 0x3cedab8d, 0x7a102514, 0x079267be, 0x5987565e, 0x62a8b168, 
    0x315be29c, 0xb2cfcb19, 0xe5bb6e58, 0x2e21a819, 0x8ca832cd, 0xf7933b99, 0xf9501a91, 0x685bf8cb, 
    0xf499b7db, 0xdba66982, 0xf1c061d7, 0xd71fe20a, 0xad63c714, 0x94a4f602, 0xdc8df411, 0xc844e9ed, 
    0x22bcdea0, 0x1efd6247, 0xcd0fbec3, 0xb4a52ea0, 0xf86108f6, 0x108c05ff, 0xe6ec1af9, 0xa3ae3103, 
};
const bignum_t TEST_MMI_NUM_N_0[] = {
    0x56c56a0f, 0x9074c3cc, 0x215d8481, 0xa8d502b2, 0x0aa1360b, 0x341a2d3b, 0x4a1b0647, 0x46edc937, 
    0x009cb334, 0xf7901176, 0x4718ee95, 0xfbf0edf0, 0x5e059123, 0x06921fbe, 0x5d50ad26, 0xaba43e77, 
    0x67ab40f1, 0xe65e3c51, 0x1a2e762a, 0x86161e63, 0x6de41baf, 0x6173763b, 0x9bbec424, 0xf3466202, 
    0xf45af1a3, 0x57dbb82d, 0x9172092e, 0xd6178827, 0xde43fba3, 0x953fb771, 0x7d30fe7b, 0x03707660, 
};
const bignum_t TEST_MMI_NUM_REF_I_0[] = {
    0x49a13ac5, 0x048c186a, 0x12a8bc47, 0xf79be521, 0x0b3ec456, 0x3e180ac1, 0x6711c2c6, 0x1ab394a8, 
    0x837548a4, 0x8ee8e18e, 0xe815a450, 0x6a1c6c78, 0x8c768fad, 0xc5da6a3c, 0x458f2d5b, 0x02dcb8ad, 
    0x3554a202, 0xcecfc14d, 0x881fe362, 0x5b6f4f88, 0x4a082494, 0xc24c0032, 0x7bf71efe, 0xb6d8900f, 
    0x65935f0c, 0x04ff483d, 0x81d542af, 0x241b22c4, 0x9bfe2e9a, 0x8e7c2657, 0xa22f7a4e, 0x003de6a5, 
};

const ReturnType TEST_MMI_FR_1 = E_OK;
const bignum_t TEST_MMI_NUM_A_1[] = {
    0x3c5486e9, 0xabd9377b, 0x9479bcd1, 0x7bbe870e, 0x3d831a86, 0x7a0018ac, 0x64682e6a, 0x5b05ff72, 
    0x00985985, 0x62ab7191, 0x3cf6242d, 0x32b7b4ac, 0x7b703bcf, 0xbef57053, 0x11225d9f, 0xe16d275c, 
    0x11e10580, 0xa4738c76, 0x5de069b1, 0xed8f971e, 0x2668ffd2, 0x0fe45e70, 0x182006bb, 0xadf98d2d, 
    0x09bfdb92, 0x18ad3267, 0xba758d9c, 0xf7a70524, 0x741d0f04, 0x2983016d, 0x3441a407, 0xc4e13a31, 
};
const bignum_t TEST_MMI_NUM_N_1[] = {
    0x7dcda015, 0x6f957ad3, 0x2b290b07, 0x1422d010, 0x4d893fdf, 0x47760c40, 0xe27bb7b0, 0x07a65df1, 
    0xd08473fd, 0xf43f19ed, 0x341f6824, 0x18494238, 0xc265d281, 0x8f09dbde, 0x83718592, 0xdf8a17e2, 
    0x77b00e8a, 0x4c6bef28, 0x90818a58, 0x4ea8cacc, 0x7a100d9c, 0x7a0919e8, 0x80fe7a9e, 0x1b608891, 
    0xbf921097, 0x570bfdff, 0x54e88c88, 0xf2a29056, 0x866db29e, 0x6a0176cc, 0x82ebfff1, 0x1e9e4b87, 
};
const bignum_t TEST_MMI_NUM_REF_I_1[] = {
    0x924219bb, 0x671bc348, 0xe4852813, 0x0cb5c867, 0x048b7dd3, 0x228bdfd5, 0x0a070819, 0xb2fa9a0e, 
    0x63eaaa8f, 0x37b1098b, 0xd6500c79, 0x6d7a4f69, 0xe12c94fe, 0x7e87c6b3, 0x38152123, 0x1a0ad841, 
    0xf179d1a8, 0x0d0a0b8e, 0x380e5aa4, 0x13ae2173, 0x9022a8a5, 0x5080795a, 0xeda634d9, 0xac1b3653, 
    0x3240adf9, 0x2fe8e2f7, 0x674ec54f, 0xe6383740, 0xcaf34776, 0x8e14c39e, 0xf1721d80, 0x12ad318f, 
};

const ReturnType TEST_MMI_FR_2 = E_HAS_NO_VALUE;
const bignum_t TEST_MMI_NUM_A_2[] = {
    0x8bd09f9e, 0x0e49eefe, 0xc09cdfcb, 0x59447a9b, 0x19cb2b9b, 0x0c4393fd, 0xa0935cc8, 0x850b35e6, 
    0xd210dbd4, 0x95e15aca, 0xd5557d39, 0x922e9af7, 0xc2acf9c5, 0x54ceef8c, 0x32f4624c, 0x6bb7ff97, 
    0xa53ec8db, 0x5b3a1f22, 0x93308f9c, 0xee265e29, 0xe3b0d257, 0x0d377fc1, 0x78402ce1, 0x06e3f72b, 
    0xe1ab21bf, 0xdc3de540, 0x9e706d75, 0x238d96cc, 0x29073d68, 0x9d373ebc, 0x9615776a, 0x2e9cf96e, 
};
const bignum_t TEST_MMI_NUM_N_2[] = {
    0x5b0f481a, 0xa2374c2d, 0x8641a7ba, 0xa5a9ce3d, 0xc8cfb00b, 0x596506ef, 0xebef7b7d, 0x8e198c74, 
    0x01e929d4, 0x2fa42175, 0x06b5e5c8, 0xbeab5fb3, 0xfe867a0f, 0xfd58ec80, 0xdbe94767, 0xa76902d3, 
    0xa1a9532b, 0x3cd04d74, 0xe5428632, 0xf4a3eee5, 0xe9f32a68, 0x7de64b16, 0x6658cf92, 0xfd0dc1d2, 
    0x889eb614, 0x35c56f03, 0xda1a07f5, 0x5ecebef5, 0xfe47c1e8, 0x9f7b2d0c, 0xcf05d3fd, 0xa9cc1294, 
};
const bignum_t TEST_MMI_NUM_REF_I_2[] = {
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};

const ReturnType TEST_MMI_FR_3 = E_HAS_NO_VALUE;
const bignum_t TEST_MMI_NUM_A_3[] = {
    0xa8bd34cc, 0xf8b3f5e3, 0xc709b570, 0xf4d07e12, 0xbb113e3b, 0xdf342aa0, 0x25694318, 0x20804d54, 
    0x65c83d82, 0xa25d7b32, 0x426a6630, 0x20373ae5, 0x19dc4878, 0x8af81072, 0xa8b06254, 0x31c930af, 
    0xa096916d, 0x3d42f40d, 0x3f80ac5a, 0x5f60b7e7, 0x71783cff, 0xa0fc714c, 0x8249acd3, 0x49b412dc, 
    0xb0e94aa3, 0x99ee2c3e, 0xbfd86ed8, 0x241f3825, 0xc1959774, 0xdb619108, 0x195eaa3d, 0x606312bc, 
};
const bignum_t TEST_MMI_NUM_N_3[] = {
    0x9b104c5c, 0x5134fe78, 0x91100c6c, 0xb9b52f45, 0xcf7a4bc7, 0x1aabdcdc, 0x43330986, 0x77a3961b, 
    0x5b12b3e3, 0x1eac46b2, 0x98b0bd53, 0xb35165ec, 0x8d83ccb0, 0x2ea72ea8, 0x5271da37, 0x54c91471, 
    0x7aafdcc8, 0x75985c22, 0x050d4819, 0x5eb95fae, 0xd3eb3c2b, 0xa101926a, 0xdef3736d, 0x4f32bc87, 
    0xbbc9e198, 0x5630623d, 0x585c3eaa, 0xc8b7159d, 0xbb9ba251, 0xa25c9c35, 0x97804f0f, 0xa4e6b20b, 
};
const bignum_t TEST_MMI_NUM_REF_I_3[] = {
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};

const ReturnType TEST_MMI_FR_4 = E_HAS_NO_VALUE;
const bignum_t TEST_MMI_NUM_A_4[] = {
    0x2fa24344, 0xfb337e32, 0x4b0ff990, 0x6c43ae19, 0xba82adfe, 0x02314333, 0x7961e378, 0xf18dfaad, 
    0x6f20303d, 0x3f6b54ae, 0x668a7a4d, 0x27d3cd28, 0xade1557a, 0x10af1298, 0xa38911f6, 0x4895170b, 
    0xf5b8b547, 0x56342309, 0xc5bdbe9d, 0x06ec908b, 0x7eb3cee5, 0xd68e63e0, 0x7f7a1874, 0x76c70f2f, 
    0xce6b7fc4, 0x3f24a0a2, 0xea05e15e, 0x57f0f171, 0xa0d5a3bf, 0x7a766306, 0xaaf9f07b, 0xc420c1ff, 
};
const bignum_t TEST_MMI_NUM_N_4[] = {
    0xe3928c40, 0x8a22b62c, 0x09742798, 0xd8606419, 0x0e783508, 0x1489ef99, 0xdfbf82df, 0x84a3df43, 
    0x9767356b, 0x832289eb, 0xca8d96b1, 0x03a2edfb, 0xbc111b23, 0xe9d09a0a, 0x60c88f1d, 0xdae46b6f, 
    0x8c724ba0, 0x860f94d5, 0x25509c2a, 0xad28f28a, 0x17693a0d, 0xf10139d4, 0x3852c9c9, 0xd5123635, 
    0x57618482, 0x43dd7118, 0x97682d0d, 0x2d44911f, 0x9f44adcb, 0xb09145e7, 0x44e8e30f, 0x9b19fa19, 
};
const bignum_t TEST_MMI_NUM_REF_I_4[] = {
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};

const ReturnType TEST_MMI_FR_5 = E_OK;
const bignum_t TEST_MMI_NUM_A_5[] = {
    0xf06c29db, 0x52e285db, 0xf09e4635, 0xd8d43afd, 0x65b9af3f, 0xf051b72f, 0xb908c2cf, 0xc102d0e6, 
    0xd4b16ff9, 0x292694f4, 0xd819c5da, 0x3eb0edff, 0xcca3699d, 0xefbdf420, 0x9ca8c5b6, 0x8e5dab95, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};
const bignum_t TEST_MMI_NUM_N_5[] = {
    0x0e620e1a, 0x7d3789a2, 0x4d55504e, 0xdb8b053e, 0x8ea72e6e, 0xd87e6422, 0xbe742629, 0xeb4cd1d1, 
    0x82f9afdf, 0x86ff3038, 0xbfd35481, 0xc79a5e59, 0xae55418c, 0xcf86d3a6, 0xcb8efafa, 0xaab7dacb, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};
const bignum_t TEST_MMI_NUM_REF_I_5[] = {
    0x4812319d, 0xf7493842, 0x8d677e46, 0x8b38c5ef, 0x8c68d671, 0x13151e23, 0x749a958c, 0xf28ec6af, 
    0x50f3b4bb, 0x009f4221, 0x34252b11, 0xd4487d3c, 0xe4608e9d, 0x201c0cec, 0x023becf5, 0x41770dd8, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};

const ReturnType TEST_MMI_FR_6 = E_OK;
const bignum_t TEST_MMI_NUM_A_6[] = {
    0x747e1fef, 0x390e9e4c, 0xea4e399d, 0x2b7eecb7, 0x1a3efab3, 0xd6796a9d, 0x5bd60157, 0x3063d940, 
    0x44a4e2f8, 0x1d7eb280, 0xa207cceb, 0x6bcd85b8, 0x1d850c7f, 0xcdf3fe76, 0x4028c9ff, 0x9b708ca2, 
    0xeedf146e, 0xb10b5dc6, 0xe1531229, 0x164c2097, 0xa233d12c, 0xcf7026cf, 0x920f98f0, 0x922d7f24, 
    0x59800d93, 0x940a8b6a, 0x34755d9d, 0xaa4bc27d, 0x634c7e93, 0x9532bca5, 0x79274155, 0x530c55c0, 
};
const bignum_t TEST_MMI_NUM_N_6[] = {
    0xccac8c62, 0xb560b618, 0x90ead613, 0x2b3a3598, 0x588e87b3, 0x98edc043, 0xc1121501, 0xcc141e6a, 
    0xc298c0aa, 0x8978f976, 0x671a62cf, 0x4a925497, 0x1fa321db, 0xe3b790e1, 0x0fa4c9a5, 0x92dbb9e7, 
    0xf0547479, 0x3c79cc6d, 0xc5a3932e, 0xc31035e8, 0x38e2b356, 0xe91b9a43, 0x4bf8bf63, 0xf2ddd478, 
    0xb5e23148, 0x2cf15bfe, 0xd7f294ef, 0x209a02c9, 0xf8587db5, 0x7ae17317, 0xabc5da32, 0xf69da2ae, 
};
const bignum_t TEST_MMI_NUM_REF_I_6[] = {
    0xaf359aed, 0x4fe987c2, 0xfbadb9a4, 0xe6186ee7, 0x867eb832, 0xa158b1b7, 0x65c31233, 0x103d7eb4, 
    0xb25d968d, 0x7ab2c810, 0x33f6eca6, 0x90d01190, 0x20168674, 0x196463c3, 0x2bf86377, 0x90721bfa, 
    0x8f0e5383, 0x507b0b48, 0x221eb208, 0x3f2cc791, 0x0b1a7eae, 0xd0f4937b, 0xa035abe0, 0xc3f9a41c, 
    0x074cbf59, 0x922edd2f, 0xfabbf8f5, 0x5ac1e067, 0x441c5f5e, 0xa3ad5f72, 0x686bba28, 0x06e6bd16, 
};

const ReturnType TEST_MMI_FR_7 = E_OK;
const bignum_t TEST_MMI_NUM_A_7[] = {
    0x7a66ca45, 0xef6ad63e, 0xa4b4f471, 0x6d6fb1e4, 0x4e996e23, 0xeac0ba7b, 0xfbedd72a, 0xd0249a8b, 
    0xa34a8b65, 0xd292b461, 0x8d7647a8, 0x1bfae6f8, 0xcf6a9354, 0x77b92a4d, 0x8c72a701, 0xa65c9641, 
    0x8249a621, 0x0355dc5b, 0x1b90cb23, 0x06368ab1, 0x6ad5a01d, 0xcce18fcb, 0x77595336, 0x0b1eb5ea, 
    0xb78e675c, 0x66bae343, 0x60814bae, 0xf366b8d5, 0x235d3b58, 0x00f03fca, 0x7c784992, 0x5a8896fe, 
};
const bignum_t TEST_MMI_NUM_N_7[] = {
    0x411116fd, 0xa7a7ccf9, 0xec072917, 0x39df6de1, 0x735d3da9, 0x0e744d7c, 0x948bec96, 0x7fef1382, 
    0x22c00029, 0xe3c968cc, 0x72d0d191, 0xe7abaf3e, 0x685b08ec, 0xeb77cf55, 0x3d8002bb, 0x3ebc6f15, 
    0x3c607d6f, 0x761f29e5, 0x39e8effa, 0x8b20939f, 0xf1f47b9c, 0x05dd6b4a, 0x82425d6d, 0x3bc0ffcc, 
    0x6177207c, 0x44d79749, 0x257dbf86, 0xeeb19d52, 0x63e0a519, 0x7d69bd10, 0xe6ffab1a, 0x2621bfaa, 
};
const bignum_t TEST_MMI_NUM_REF_I_7[] = {
    0x12e4027c, 0x66b7ffbc, 0x356c94e6, 0x201e255a, 0xaf61ab75, 0x59b90095, 0x52c4c14a, 0x95fee112, 
    0x5cf82df7, 0x0532c12a, 0xa72e795e, 0x36e02f6a, 0x8ef8a7ed, 0xc49b9ad8, 0xded17051, 0xa219de2a, 
    0xbe7fbf0a, 0xd52999d3, 0xb6edfde3, 0xf69bafaf, 0x7d65fe7c, 0xc054eeac, 0xf5f20110, 0x28aaf72d, 
    0xc52e7e4b, 0x717b9181, 0xac8fae39, 0xb0b51634, 0x254c9be6, 0xb5de513a, 0xb0020c3d, 0x05e66b53,
};

const ReturnType TEST_MMI_FR_8 = E_OK;
const bignum_t TEST_MMI_NUM_A_8[] = {
    0x5dccc61e, 0x9e93aab6, 0xd9fa4f13, 0xdf3cf749, 0x1873b4a5, 0xbefd63c8, 0x3e6b9f25, 0x60c1a442, 
    0x21be8d6b, 0x4abf5137, 0xe923b9a0, 0x55c85fb0, 0xdc6d3b13, 0xc49a6b9f, 0x4d02060a, 0x15adc3aa, 
    0x88366b50, 0x5dd2f5bc, 0x5f46f6ae, 0x69b40f55, 0xe945224a, 0x97aedf8d, 0x90e4b0e5, 0xc4a59274, 
    0xba4cdcfd, 0x80171fd1, 0x6adf5d15, 0xb7d3936c, 0x42a018b5, 0xddda4ef8, 0x736dbeff, 0x4e371350, 
};
const bignum_t TEST_MMI_NUM_N_8[] = {
    0xc00884ef, 0xb8401fa3, 0xe9221f7c, 0x68a0f6b3, 0x06ab400e, 0x8ee4858f, 0x94015143, 0x53e23864, 
    0x5f14eabc, 0x85175409, 0x276e3a74, 0x3e8f0e30, 0xde453a4f, 0x036c29bf, 0xdf976d7a, 0x623279a5, 
    0x6cc14663, 0x0ff1d99b, 0x43366013, 0xbd81c56e, 0xbf9bc600, 0x6ac207ef, 0x1a495974, 0x357c7bd2, 
    0x5da13dc2, 0x296c9316, 0x616ca2f3, 0x671fee67, 0xa427bab4, 0x360ee9c2, 0x15505743, 0x944bccd2, 
};
const bignum_t TEST_MMI_NUM_REF_I_8[] = {
    0x0e8fdba5, 0xbb758970, 0x015b2a7c, 0xba48427c, 0x2488cf30, 0x20fd4839, 0x9e8473f8, 0x4cf6d58a, 
    0x09a40ae2, 0xffb905e4, 0x9e2e1d16, 0x45777fab, 0x2c9547c5, 0x0ff1be22, 0x6095d45f, 0xb84b1059, 
    0x6a570d9c, 0x87dd28fc, 0xe853796f, 0xbb0a9d2f, 0xfd66c4af, 0x5ea9d644, 0xdd80f348, 0x0c697724, 
    0x595484f6, 0x7b21aae2, 0x2d9ba361, 0xd3b04665, 0x4c9abd1d, 0xce49e75b, 0xde381bd6, 0x1fde5b2c, 
};

const ReturnType TEST_MMI_FR_9 = E_OK;
const bignum_t TEST_MMI_NUM_A_9[] = {
    0xa93ac8d9, 0x95394ef4, 0xd48a6c44, 0xef159a59, 0x9caf7794, 0xce08d2f6, 0x218762fa, 0xcabcd4f1, 
    0x9074f69c, 0x8925ad45, 0x725db019, 0xde61734a, 0xe17a10ea, 0xddaf82e3, 0xd5fe37e4, 0xa8a0ba0b, 
    0xf63814b1, 0xdb7f5ec1, 0x584ddc0e, 0x3a36af4f, 0xa21bb0bf, 0x1680ca32, 0x0deb7e01, 0xeab58b39, 
    0x61e0ed9f, 0x593c5f4b, 0x8bb1893b, 0xf8c5e738, 0xc99ae097, 0xacdf1aaa, 0xd2b9cb99, 0xf6bc6e56, 
};
const bignum_t TEST_MMI_NUM_N_9[] = {
    0xa7579c5b, 0x360093fb, 0x55c1b21c, 0x314d8699, 0x11fae766, 0x9bbdda02, 0xfb6d76a5, 0x3ff129e4, 
    0xc0e648c5, 0xf8f6e7db, 0x324db899, 0xa5639a3e, 0x83b65e81, 0xdd1e7338, 0xcdd88be9, 0x790ccab4, 
    0xee39f312, 0x73e630da, 0x26a533e8, 0x4ecb09cd, 0x9fd28167, 0xdd7cf0f4, 0x30aa547c, 0x31aab71e, 
    0x841fe3aa, 0xfbf70513, 0x05229c38, 0x0c53eda5, 0x63ab256f, 0x92412716, 0x9ac2eb7c, 0x4ccb6ca2, 
};
const bignum_t TEST_MMI_NUM_REF_I_9[] = {
    0xdb17f478, 0x8f212379, 0x95e8004d, 0xe7f2ecdb, 0x7be30c50, 0xa985267c, 0x1ba5ea1d, 0x0f7feb9e, 
    0x373fd918, 0x227dfa46, 0x66b78d92, 0x9a832a2c, 0xf5356a9d, 0x7575c004, 0xbf6b39b2, 0x302ef886, 
    0x279fa199, 0xb89737fb, 0x29732cdb, 0x508c29c1, 0xb74e638d, 0xad90109d, 0xd80d8ec5, 0x3884682f, 
    0x1e28a00b, 0x5abc2775, 0xdf86c87b, 0x3c8b704a, 0xdb9592a4, 0x626a44d8, 0x63109624, 0x2b2e28f2, 
};

const ReturnType TEST_MMI_FR_A = E_OK;
const bignum_t TEST_MMI_NUM_A_A[] = {
    0xa712013a, 0xcdb5dbca, 0xc1e7ddee, 0x170ed4cb, 0xf0f87aa5, 0x33b1e050, 0x21672662, 0x4bbcc611, 
    0x91f3cfc7, 0x995fa8aa, 0x505a4685, 0xbf67681a, 0x32b05fe2, 0xa265613f, 0x98c3cc87, 0x59e37f92, 
    0xf9ebd64e, 0x03924a7e, 0xab53ec90, 0x376aba55, 0x596a1a1a, 0x02fbcf7b, 0x2e9abe9c, 0x8c887e3e, 
    0xd3857354, 0x4dd617bd, 0x59f82a04, 0xfe9063e4, 0xf958fa7d, 0x66fb53ca, 0x50949612, 0x68dc1c14, 
};
const bignum_t TEST_MMI_NUM_N_A[] = {
    0x4c3b628f, 0x7d9a1279, 0x20d6923c, 0x731f67f5, 0x2b6c7761, 0xdc9167ca, 0x112c26fd, 0xd27a0942, 
    0xe41eb56b, 0x0362b8c7, 0x4024384b, 0x01b3439f, 0x842c1fba, 0x8461be87, 0x26968de4, 0x01f81096, 
    0x8de617c5, 0x1a9048cf, 0x205bb480, 0xb1210ef7, 0xb5364d2e, 0xef39970b, 0xbb16cf24, 0xa5bc0edf, 
    0xf532a225, 0x6b0fc2ea, 0x6e8b6a77, 0xa720ac79, 0x055c56f9, 0x11f495ed, 0x44cc0a65, 0x3ee98919, 
};
const bignum_t TEST_MMI_NUM_REF_I_A[] = {
    0x3155781d, 0x860f4215, 0x5ac1003d, 0xe7b620c1, 0x5e46f8aa, 0x5bd12018, 0x0a441c83, 0xd585cee2, 
    0x1aacb514, 0x3bed7bef, 0x9574dac6, 0x20b816d4, 0x28bfdf9c, 0xd41a8310, 0x10e63621, 0xced07fbb, 
    0x2a7d6e17, 0x67e365d0, 0x830139df, 0x7d1ed952, 0x447cea43, 0x157863bc, 0x97effeff, 0x9dc0819f, 
    0x5dc6265e, 0x52bd9178, 0x32ccdd65, 0xd558a116, 0x3a62c6f7, 0x1d930a7e, 0x12cff19d, 0x13dc618a, 
};

const ReturnType TEST_MMI_FR_B = E_OK;
const bignum_t TEST_MMI_NUM_A_B[] = {
    0xa43c586b, 0x0fe172e8, 0x65af21f1, 0xf1dc2432, 0x119ff56a, 0x28f30bb7, 0x0ebc347f, 0x43dd06d7, 
    0x47e7195f, 0x7c56c98b, 0x1ce206ea, 0x940dbe2a, 0x6aa6adb3, 0x379299b8, 0xa5464ecd, 0xb4e82355, 
    0xc8fbcf3d, 0x83455298, 0x829f2758, 0x9916ade5, 0x1203bc5a, 0x234a9656, 0x39c890e4, 0xf0edb0b3, 
    0x18b9e980, 0x939bfe3b, 0x0a153b25, 0x42a32be8, 0x3e54a7e8, 0x21619e3d, 0xe25b2a2e, 0x5ad248da, 
};
const bignum_t TEST_MMI_NUM_N_B[] = {
    0x6c738b31, 0xaeff0e89, 0x31b91449, 0x28735c40, 0x4066c803, 0x9562c766, 0xcc77bdf1, 0x37264905, 
    0x5ea399d5, 0xf10da3a8, 0xf723c6b7, 0x261f9622, 0xc566855e, 0x3e5ac84d, 0x8b0ad185, 0xefc2311a, 
    0x724e65ca, 0xc0645b08, 0x43b78721, 0x7c69d71d, 0xa941d05c, 0x1ee89b98, 0x86a9f26c, 0xee766b23, 
    0xd960c4d0, 0x4099c41f, 0x6983504b, 0x84e5ed27, 0x552d26bd, 0x2d7315c1, 0x2bb31c08, 0x58192987, 
};
const bignum_t TEST_MMI_NUM_REF_I_B[] = {
    0xf3322e45, 0x1dd9ef51, 0x78577a7a, 0x4f377e97, 0xd1229f61, 0x0cab820d, 0x53c5a157, 0x6e34bea7, 
    0x7ceb4ae7, 0x046656c9, 0x082278ad, 0x0b1aa607, 0x65324c3b, 0xcc597023, 0xc65d04ba, 0x8452f522, 
    0xc7fd76b2, 0x9fc6e4d2, 0x6abf648f, 0xc8c96dc6, 0xd7d12dc5, 0xf376f236, 0x39a01e53, 0x2b5f426b, 
    0xf4736419, 0x7e8166a4, 0x5f6df605, 0xb4cdec3c, 0xaa9365cc, 0xe644cf12, 0xf399e309, 0x536e1902, 
};

const ReturnType TEST_MMI_FR_C = E_OK;
const bignum_t TEST_MMI_NUM_A_C[] = {
    0xef4d2575, 0xae11966e, 0x6150eebb, 0x55972c3c, 0xd42c635f, 0x10655708, 0xf5032cc6, 0x87454012, 
    0xd4769266, 0xe4828729, 0xb146d275, 0x5e06ddfe, 0x48323240, 0x50589789, 0xd5455bc3, 0x025d8a9c, 
    0x46d6d31d, 0xd02a595b, 0x2a82702b, 0x8e88884d, 0x44d6babb, 0x14942f51, 0x26e9da8a, 0x81284664, 
    0x75c7ff1a, 0x8345f258, 0xb0adc762, 0x0b3e3550, 0x404f14ef, 0xce54e443, 0x22f43ebe, 0x9ea41d84, 
};
const bignum_t TEST_MMI_NUM_N_C[] = {
    0x74136b1c, 0xc0f7595d, 0x7070a520, 0xca7baeda, 0x060acbc2, 0x6dd45faf, 0x218fc89d, 0x01c033e5, 
    0xfc75d39f, 0x4dbc6d2c, 0xecbd2c12, 0x9db639da, 0xb3a3c104, 0xbd207720, 0x25deaf3f, 0x82269ee3, 
    0x9e7e9c72, 0x1beb3b09, 0x4207a967, 0xe6dfbee2, 0x9f99827f, 0x385cb9f9, 0x4b5d3a68, 0x4bcd84d9, 
    0x29e94c20, 0xee44d587, 0x60304b7e, 0x88460f09, 0x8a27df91, 0x00c38398, 0x974c20be, 0xc4e219a4, 
};
const bignum_t TEST_MMI_NUM_REF_I_C[] = {
    0xaf9b1a4d, 0x33fe64f8, 0x44528734, 0x205827fb, 0xd401c048, 0xfa0c240c, 0x08f67062, 0xcf40bfbc, 
    0xade06848, 0xf5cc22a8, 0x030d9183, 0x4eca36f1, 0x015d9528, 0xbc4fa162, 0xcc0dd3c2, 0x23b32cc9, 
    0xb8d28005, 0x8237d6f0, 0x8b098b3a, 0xcd8dc493, 0x82452f86, 0x4a6db772, 0x60cbc9c1, 0x9e4729f4, 
    0xf1a921b1, 0xac1f9fc4, 0x0043f3ad, 0x02848fae, 0xbe8e2408, 0xf892a694, 0xeb4ae7c3, 0x88ae4485, 
};

const ReturnType TEST_MMI_FR_D = E_OK;
const bignum_t TEST_MMI_NUM_A_D[] = {
    0xe19c2ce9, 0x6e2b3d84, 0xc500bf9e, 0x9bba858e, 0x1ef22fb7, 0xf0753f1b, 0xc7fc35e2, 0xc86f5cdf, 
    0x0caa0b88, 0xe77ad548, 0x23ac7b94, 0xb8be6600, 0xb0d6b195, 0xd2a04cf0, 0x609a9c81, 0x802909f8, 
    0x5d8dd315, 0x3c4407a8, 0x835ff082, 0xeb3b1e56, 0xbf9b11cf, 0xdf913c5d, 0xd13f2bd8, 0x4a516835, 
    0xe3a7de3b, 0x6820ece6, 0x33eb7fdc, 0x6c1e269d, 0x952bba38, 0xce74bdf6, 0x1d9fb4e8, 0x5867f11c, 
};
const bignum_t TEST_MMI_NUM_N_D[] = {
    0xb53b0fcf, 0xd71e5bfb, 0x780a09db, 0x68e52930, 0xd9fd10e3, 0xb6a772cd, 0x42d34726, 0x079a3b38, 
    0x45bdd64a, 0x0c1cdb31, 0x148527e4, 0x337c6a50, 0x480c7a7a, 0x12feb3ec, 0x3254d1fa, 0x563aef0c, 
    0xf69bf7c5, 0xb603b8d2, 0x2fcb88df, 0x6c6247f2, 0xadb46ec1, 0x1cbfb221, 0x904e1484, 0xc8e78803, 
    0x51be827f, 0x1908c13a, 0x3b48d349, 0xdca8aa1a, 0x3a895c18, 0x9356490f, 0x6023a45d, 0xac280a2d, 
};
const bignum_t TEST_MMI_NUM_REF_I_D[] = {
    0x15877acb, 0x2527411e, 0x951b454e, 0x00b1eebc, 0xa1e0aeb3, 0x873f6226, 0x2a107063, 0x5ed9d4ed, 
    0x03a1a91e, 0x26f0c588, 0x94d6a02d, 0x13ecfb20, 0x7b2185cb, 0x17cd09ad, 0xa5d6fb6f, 0xa4a4914e, 
    0xf150b827, 0x51e81993, 0x574fd04e, 0x2c782c65, 0x214b687b, 0xfc86128a, 0x6cbe12ba, 0xebf42bb6, 
    0x34d29bd6, 0xbcf60306, 0x18dfd810, 0x957a2735, 0xc77109fa, 0x603199c0, 0x853e8364, 0x5c104818, 
};

const ReturnType TEST_MMI_FR_E = E_OK;
const bignum_t TEST_MMI_NUM_A_E[] = {
    0xf2c5ed61, 0xa80b4d6a, 0xe19c9208, 0xd7157139, 0x9699c663, 0x88b01623, 0x6efece95, 0x6afceb09, 
    0x435cc1d9, 0x16eb670e, 0x33f788f9, 0x5c0a0cf9, 0xf6f2a3d3, 0x4f7fa3ba, 0x7abe7d71, 0x42e5ba69, 
    0x8985417b, 0xa29f70a9, 0xf1d596f8, 0x754ee0a2, 0x3d6c4083, 0x558debe3, 0xd1cf4b68, 0x8013b405, 
    0x9f0998f6, 0x0141a809, 0xe0f3173e, 0x7a5641f7, 0x65b8c281, 0x15ba45ad, 0x95e78990, 0x3415fa3e, 
};
const bignum_t TEST_MMI_NUM_N_E[] = {
    0x9cd31e93, 0x049d14c6, 0x22e4902b, 0x539d3ad1, 0xa9b855fc, 0x2abf729a, 0x39bfa6fb, 0x336dd4a0, 
    0xb8cf40f2, 0x80bc6d55, 0xcfa3a0fd, 0xd72240db, 0x2f81da95, 0x4759404c, 0x868118e6, 0xdebaeeec, 
    0x8496892f, 0xf40452f6, 0xcdc3a7f2, 0x7ca5e5e7, 0x0bab26bf, 0x4c520466, 0x08d2d31c, 0xf1e68cc2, 
    0x0c757c16, 0xc10079ce, 0x088ec321, 0x678533a8, 0xbf723059, 0x510bc535, 0x5a5ade98, 0x804b406a, 
};
const bignum_t TEST_MMI_NUM_REF_I_E[] = {
    0x400a165b, 0x53d3cb40, 0x0cbcd6ee, 0x22676fc2, 0xc88387f8, 0x02af0d0a, 0x1f862e18, 0x1e4292ee, 
    0x6722af34, 0xf7ce8d16, 0xda6a7f78, 0x78b503f3, 0x2a574b04, 0x6a8854bc, 0x4bc33bac, 0x52dd70ce, 
    0x4767adbc, 0xb34f9cbf, 0x7d6f362e, 0x8cec2017, 0x5987aac8, 0x5ae45854, 0x8786231d, 0x351573ba, 
    0x4d970cfe, 0xa978e5c9, 0x09f94154, 0xfd5f2aff, 0xdb7ae25a, 0xafccc0ab, 0x85ea4e65, 0x36a69dcf, 
};

const ReturnType TEST_MMI_FR_F = E_HAS_NO_VALUE;
const bignum_t TEST_MMI_NUM_A_F[] = {
    0x2af073d0, 0x44355cbf, 0xf79d131c, 0xccdd82c7, 0x26ec2852, 0xac8896e9, 0xd47fdd49, 0xd14f4101, 
    0x74fb3fb4, 0xb8b8309c, 0x0bb05544, 0x29d78dd7, 0x9e50c3b5, 0xa24ad859, 0xb677cab5, 0xc087c60b, 
    0xa2348206, 0xf75aecb3, 0x18020a41, 0x4d42d998, 0xf5ec929c, 0x2098366a, 0x0cd60f00, 0xdbcc5ed5, 
    0x937d00e0, 0x2d8ad8ec, 0x7a458ce2, 0x01c88765, 0x84f7b419, 0xeba48fea, 0x73f77a9e, 0xb94fc3d8, 
};
const bignum_t TEST_MMI_NUM_N_F[] = {
    0xaf4cccc3, 0x87dcd7a4, 0xc9012163, 0xc2cac9a9, 0x6846c17d, 0xee53ea50, 0x3d624a65, 0xd0f6b10d, 
    0x227f437d, 0x7da95b1a, 0x2546aa7c, 0xf1e81174, 0x23592ed2, 0x7e11ac19, 0x03bb73f6, 0xa2d3b224, 
    0x0fc452f5, 0x2a8c6dad, 0x8b4fd317, 0xb67d37e4, 0x7fd9d666, 0x79fdeb83, 0x837db85e, 0x5f25506a, 
    0x506ee9a3, 0x6d7afb56, 0xb2f9cace, 0x67687601, 0xcfe6424c, 0x8b49e32d, 0x060ec69c, 0xb9663316, 
};
const bignum_t TEST_MMI_NUM_REF_I_F[] = {
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};

const ReturnType TEST_MMI_FR_10 = E_HAS_NO_VALUE;
const bignum_t TEST_MMI_NUM_A_10[] = {
    0x8cbcccd4, 0x9c072e2c, 0x69783446, 0xddf535cf, 0xee04621d, 0xd3891b85, 0x9e260b33, 0xc7d39ef3, 
    0x96538f6a, 0x04325abe, 0x5d6daa8e, 0xfc3a62df, 0x4aea3ec5, 0x8d1d735a, 0x712b437e, 0x4b38ffe1, 
    0x4ce18b8e, 0x745113e6, 0x9cd2bebd, 0xe6980c21, 0xa530824b, 0x74324df6, 0x72e65d90, 0xebbd1e5c, 
    0x90379faa, 0x700488b2, 0x680cd647, 0x2e4ea5e3, 0x1dd37e27, 0x5b9205cb, 0xbfcd7862, 0x40aa8b96, 
};
const bignum_t TEST_MMI_NUM_N_10[] = {
    0xdcd0e12a, 0xb14cd56a, 0x8e1959ab, 0x25bc67fe, 0xb0438fe5, 0xf70bd594, 0xe3b6d94d, 0x8e246064, 
    0xab6af441, 0x755cb7c9, 0x0e037510, 0xc133c0dc, 0xe471764f, 0x98db7d4b, 0xba7c9156, 0x3248a0f1, 
    0x5edeb294, 0x79d33a69, 0x8c87d6b0, 0xe64ebb96, 0x7dcabf31, 0x9215a53c, 0x274c9136, 0xc6599431, 
    0xb0243747, 0x222af772, 0x64aeb1cd, 0x9e4afc6c, 0xf81b14bc, 0xef8b30b9, 0xf316d7c2, 0xb3b96f6c, 
};
const bignum_t TEST_MMI_NUM_REF_I_10[] = {
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
};

const ReturnType TEST_MMI_FR_LIST[] = {
    TEST_MMI_FR_0, TEST_MMI_FR_1, TEST_MMI_FR_2, TEST_MMI_FR_3, 
    TEST_MMI_FR_4, TEST_MMI_FR_5, TEST_MMI_FR_6, TEST_MMI_FR_7, 
    TEST_MMI_FR_8, TEST_MMI_FR_9, TEST_MMI_FR_A, TEST_MMI_FR_B, 
    TEST_MMI_FR_C, TEST_MMI_FR_D, TEST_MMI_FR_E, TEST_MMI_FR_F, 
    TEST_MMI_FR_10,
};
const bignum_t* TEST_MMI_NUM_A_LIST[] = {
    TEST_MMI_NUM_A_0, TEST_MMI_NUM_A_1, TEST_MMI_NUM_A_2, TEST_MMI_NUM_A_3, 
    TEST_MMI_NUM_A_4, TEST_MMI_NUM_A_5, TEST_MMI_NUM_A_6, TEST_MMI_NUM_A_7, 
    TEST_MMI_NUM_A_8, TEST_MMI_NUM_A_9, TEST_MMI_NUM_A_A, TEST_MMI_NUM_A_B, 
    TEST_MMI_NUM_A_C, TEST_MMI_NUM_A_D, TEST_MMI_NUM_A_E, TEST_MMI_NUM_A_F, 
    TEST_MMI_NUM_A_10,
};
const bignum_t* TEST_MMI_NUM_N_LIST[] = {
    TEST_MMI_NUM_N_0, TEST_MMI_NUM_N_1, TEST_MMI_NUM_N_2, TEST_MMI_NUM_N_3, 
    TEST_MMI_NUM_N_4, TEST_MMI_NUM_N_5, TEST_MMI_NUM_N_6, TEST_MMI_NUM_N_7, 
    TEST_MMI_NUM_N_8, TEST_MMI_NUM_N_9, TEST_MMI_NUM_N_A, TEST_MMI_NUM_N_B, 
    TEST_MMI_NUM_N_C, TEST_MMI_NUM_N_D, TEST_MMI_NUM_N_E, TEST_MMI_NUM_N_F, 
    TEST_MMI_NUM_N_10,
};
const bignum_t* TEST_MMI_NUM_REF_I_LIST[] = {
    TEST_MMI_NUM_REF_I_0, TEST_MMI_NUM_REF_I_1, TEST_MMI_NUM_REF_I_2, TEST_MMI_NUM_REF_I_3, 
    TEST_MMI_NUM_REF_I_4, TEST_MMI_NUM_REF_I_5, TEST_MMI_NUM_REF_I_6, TEST_MMI_NUM_REF_I_7, 
    TEST_MMI_NUM_REF_I_8, TEST_MMI_NUM_REF_I_9, TEST_MMI_NUM_REF_I_A, TEST_MMI_NUM_REF_I_B, 
    TEST_MMI_NUM_REF_I_C, TEST_MMI_NUM_REF_I_D, TEST_MMI_NUM_REF_I_E, TEST_MMI_NUM_REF_I_F, 
    TEST_MMI_NUM_REF_I_10,
};

void test_mmi_bignum(void)
{
#define TEST_MMI_BIGNUM_BIT_LEN   1024U
    char keyin;
    int test_memcmp0;
    ReturnType fr;

    bignum_s* num_a = mkBigNum(TEST_MMI_BIGNUM_BIT_LEN);
    bignum_s* num_n = mkBigNum(TEST_MMI_BIGNUM_BIT_LEN);
    bignum_s* num_i = mkBigNum(TEST_MMI_BIGNUM_BIT_LEN);
    bignum_cmp_e num_cmp;

    bool manually = false;

#define _KEYIN_DO_TEST_0_(c, TEST_FUNC_NAME) { \
    (c) = '\0'; \
    do { \
        printf("%s: ", (TEST_FUNC_NAME)); \
        (c) = getchar(); \
        getchar(); \
        if('A' <= (c) && (c) <= 'Z')    break; \
        if('a' <= (c) && (c) <= 'z')    break; \
    } while(((c) != 'y' ) && ((c) != 'Y' )); \
    if('A' <= (c) && (c) <= 'Z')    (c) += 0x20; \
}
#define _COND_DO_TEST_0_(c)   if((c) == 'y')
    _KEYIN_DO_TEST_0_(keyin, "Test Manually?(y/n)");
    _COND_DO_TEST_0_(keyin) manually = true;

    if(!manually)
    {
        for(size_t i = 0UL; i < sizeof(TEST_MMI_FR_LIST)/sizeof(ReturnType); i++)
        {
            (void)memcpy(num_a->nums, TEST_MMI_NUM_A_LIST[i], num_a->size);
            (void)memcpy(num_n->nums, TEST_MMI_NUM_N_LIST[i], num_n->size);
            (void)memset(num_i->nums, 0xffU, num_i->size);
            /* set test vector*/

            TICK_TIME_START("mmi_bignum");
            if(fr = mmi_bignum(num_i, num_a, num_n)) {
                printf("mmi_bignum() = ");
                printReturnType(fr);
            } else { /* Do nothing */ }
            TICK_TIME_END;
            test_memcmp0 = memcmp(num_i->nums, TEST_MMI_NUM_REF_I_LIST[i], num_i->size);
            if(TEST_MMI_FR_LIST[i] != E_HAS_NO_VALUE)
            {
                printf("[%lu] mmi_bignum() is %s\r\n", i, ((test_memcmp0 == 0)?MES_PASS:MES_FAIL));
            }
            else
            {
                printf("[%lu] mmi_bignum() is %s\r\n", i, ((test_memcmp0 != 0)?MES_PASS:MES_FAIL));
            }

            if(test_memcmp0 != 0)
            {
                if(TEST_MMI_FR_LIST[i] == E_HAS_NO_VALUE)
                {
                    printf("[E_HAS_NO_VALUE CASES: has no coprime]\r\n");
                }
                else
                {
                    printf("[IS ERROR]\r\n");
                }
                test_print_bignum(num_a, "num_a");
                test_print_bignum(num_n, "num_n");
                test_print_bignum(num_i, "a^-1 mod n(inverse mod n)");
                printf("ref a^-1 mod n(inverse mod n)\r\n");
                test_print_bignum_array(TEST_MMI_NUM_REF_I_LIST[i], num_i->nlen);
            }
            TEST_ASSERT((test_memcmp0 == 0) || (TEST_MMI_FR_LIST[i] == E_HAS_NO_VALUE));
        }
    }
    else
    {
        for(size_t i = 0UL; i < 0x10UL; i++)
        {
            (void)memset(num_a->nums, 0U, num_a->size);
            (void)memset(num_n->nums, 0U, num_n->size);
            (void)memset(num_i->nums, 0U, num_i->size);
            /* set test vector*/

            srand(time(NULL)+i);
            for(size_t byte = 0UL; byte < (num_a->size); byte++)
            {
                ((uint8_t*)num_a->nums)[byte] = (rand()&0xFFU);
            }
            for(size_t byte = 0UL; byte < (num_n->size); byte++)
            {
                ((uint8_t*)num_n->nums)[byte] = (rand()&0xFFU);
            }

            TICK_TIME_START("mmi_bignum");
            if(fr = mmi_bignum(num_i, num_a, num_n)) {
                printf("mmi_bignum() = ");
                printReturnType(fr);
            } else { /* Do nothing */ }
            TICK_TIME_END;
            printf("********************************************************************************\n");
            printf("TEST RANDOM_NUMBERS, MANUALLY 'COMPARE WITH https://www.boxentriq.com/code-breaking/big-number-calculator'\n");
            test_print_bignum(num_a, "num_a");
            test_print_bignum(num_n, "num_n");
            test_print_bignum(num_i, "a^-1 mod n(inverse mod n)");

            printf("********************************************************************************\n");
            _KEYIN_DO_TEST_0_(keyin, "check result(y)");
        }
    }
#undef _KEYIN_DO_TEST_0_
#undef _COND_DO_TEST_0_

    rmBitNum(&num_a);
    rmBitNum(&num_n);
    rmBitNum(&num_i);
#undef TEST_MMI_BIGNUM_BIT_LEN
}

#include "common/bitwise.h"
#include "ghash/gf128.h"
int test_ghash(void)
{
    clock_t _s_clk, _e_clk, _d_clk, _a_clk;
    size_t _loopLimit = 0UL;
    uint32_t tv_x[GHASH_U32_LEN];
    uint32_t tv_y[GHASH_U32_LEN];
    uint32_t tv_z[GHASH_U32_LEN];
    bool tv_c_o;

    uint8_t u8_x;
    uint8_t u8_y;

    tv_x[0] = 0x5a5a5a5aU;
    tv_x[1] = 0x5a5a5a5aU;
    tv_x[2] = 0x5a5a5a5aU;
    tv_x[3] = 0x5a5a5a5aU;
    tv_y[0] = 0xffffffffU;
    tv_y[1] = 0xffffffffU;
    tv_y[2] = 0xffffffffU;
    tv_y[3] = 0xffffffffU;
    xor_u32(tv_z, tv_x, tv_y, GHASH_U32_LEN);
    printHex((void*)tv_x, GHASH_SIZE, "tv_x", GHASH_SIZE);
    printHex((void*)tv_y, GHASH_SIZE, "tv_y", GHASH_SIZE);
    printHex((void*)tv_z, GHASH_SIZE, "xor_u32(tv_z, tv_x, tv_y, GHASH_U32_LEN)", GHASH_SIZE);

    printf("\r\n");
    tv_x[0] = 0xffffffffU;
    tv_x[1] = 0xffffffffU;
    tv_x[2] = 0xffffffffU;
    tv_x[3] = 0xffffffffU;
    tv_y[0] = 0xa5a5a5a5U;
    tv_y[1] = 0xa5a5a5a5U;
    tv_y[2] = 0xa5a5a5a5U;
    tv_y[3] = 0xa5a5a5a5U;
    xor_u32(tv_z, tv_x, tv_y, GHASH_U32_LEN);
    printHex((void*)tv_x, GHASH_SIZE, "tv_x", GHASH_SIZE);
    printHex((void*)tv_y, GHASH_SIZE, "tv_y", GHASH_SIZE);
    printHex((void*)tv_z, GHASH_SIZE, "xor_u32(tv_z, tv_x, tv_y, GHASH_U32_LEN)", GHASH_SIZE);

    printf("\r\n");
    printf("\r\n");
    tv_c_o = false;
    tv_z[3] = 0x00000000U;
    tv_z[2] = 0x00000000U;
    tv_z[1] = 0x00000000U;
    tv_z[0] = 0x00000001U;
    printf("init value of sftl_u32()\r\n");
    printHex((void*)tv_z, GHASH_SIZE, "sftl_u32(tv_z, tv_z, GHASH_U32_LEN);", GHASH_SIZE);
    _loopLimit = 128UL + 1UL;
    while(!tv_c_o)
    {
        tv_c_o = sftl_u32(tv_z, tv_z, GHASH_U32_LEN);
        printf("tv_c_o = %s: ", tv_c_o?"true":"false");
        printHex((void*)tv_z, GHASH_SIZE, "sftl_u32(tv_z, tv_z, GHASH_U32_LEN);", GHASH_SIZE);
        if(--_loopLimit == 0UL)
        {
            printf("exceed loop limit\r\n");
            break;
        }
    }

    printf("\r\n");
    printf("\r\n");
    tv_c_o = false;
    tv_z[3] = 0x80000000U;
    tv_z[2] = 0x00000000U;
    tv_z[1] = 0x00000000U;
    tv_z[0] = 0x00000000U;
    printf("init value of sftr_u32()\r\n");
    printHex((void*)tv_z, GHASH_SIZE, "sftr_u32(tv_z, tv_z, GHASH_U32_LEN);", GHASH_SIZE);
    _loopLimit = 128UL + 1UL;
    while(!tv_c_o)
    {
        tv_c_o = sftr_u32(tv_z, tv_z, GHASH_U32_LEN);
        printf("tv_c_o = %s: ", tv_c_o?"true":"false");
        printHex((void*)tv_z, GHASH_SIZE, "sftr_u32(tv_z, tv_z, GHASH_U32_LEN);", GHASH_SIZE);
        if(--_loopLimit == 0UL)
        {
            printf("exceed loop limit\r\n");
            break;
        }
    }


    printf("\r\n");
    printf("\r\n");
    printf("[bitReflect8_u8]\r\n");
    u8_x = 0xd6U;
    u8_y = 0x00U;
    bitReflect8_u8(&u8_y, &u8_x, 1UL);
    printf("u8_x = 0x%x, u8_y = 0x%x ", u8_x, u8_y);


    printf("\r\n");
    printf("\r\n");
    printf("[gf128_mul_sftl_u32]\r\n");
    tv_x[0] = 0x00000001U;
    tv_x[1] = 0x00000000U;
    tv_x[2] = 0x00000000U;
    tv_x[3] = 0x00000000U;
    tv_y[0] = 0x00000000U;
    tv_y[1] = 0x00000000U;
    tv_y[2] = 0x00000000U;
    tv_y[3] = 0x80000000U;
    for(unsigned int i = 0U; i < 128U; i++)
    {
        printHex((void*)tv_x, GHASH_SIZE, "tv_x", GHASH_SIZE);
        printHex((void*)tv_y, GHASH_SIZE, "tv_y", GHASH_SIZE);

        gf128_mul_sftl_u32(tv_z, tv_x, tv_y);
        sftl_u32(tv_x, tv_x, GHASH_U32_LEN);

        printHex((void*)tv_z, GHASH_SIZE, "gf128_mul_sftl_u32(tv_z, tv_x, tv_y)", GHASH_SIZE);
        printf("\r\n");
    }

    printf("\r\n");
    printf("\r\n");
    printf("[gf128_mul_sftr_u32]\r\n");
    tv_x[0] = 0x00000000U;
    tv_x[1] = 0x00000000U;
    tv_x[2] = 0x00000000U;
    tv_x[3] = 0x80000000U;
    tv_y[0] = 0x00000001U;
    tv_y[1] = 0x00000000U;
    tv_y[2] = 0x00000000U;
    tv_y[3] = 0x00000000U;
    for(unsigned int i = 0U; i < 128U; i++)
    {
        printHex((void*)tv_x, GHASH_SIZE, "tv_x", GHASH_SIZE);
        printHex((void*)tv_y, GHASH_SIZE, "tv_y", GHASH_SIZE);

        gf128_mul_sftr_u32(tv_z, tv_x, tv_y);
        sftr_u32(tv_x, tv_x, GHASH_U32_LEN);

        printHex((void*)tv_z, GHASH_SIZE, "gf128_mul_sftr_u32(tv_z, tv_x, tv_y)", GHASH_SIZE);
        printf("\r\n");
    }


    printf("\r\n");
    printf("\r\n");
    printf("[gf128_mul_sftl_u32]\r\n");
    tv_x[0] = 0x00000002U;
    tv_x[1] = 0x00000000U;
    tv_x[2] = 0x00000000U;
    tv_x[3] = 0x00000000U;
    tv_y[0] = 0x10010110U;
    tv_y[1] = 0x01011010U;
    tv_y[2] = 0x01100110U;
    tv_y[3] = 0x01011010U;
    gf128_mul_sftl_u32(tv_z, tv_x, tv_y);
    printHex((void*)tv_x, GHASH_SIZE, "tv_x", GHASH_SIZE);
    printHex((void*)tv_y, GHASH_SIZE, "tv_y", GHASH_SIZE);
    printHex((void*)tv_z, GHASH_SIZE, "gf128_mul_sftl_u32(tv_z, tv_x, tv_y)", GHASH_SIZE);

    printf("[gf128_mul_sftl_u32]\r\n");
    tv_x[0] = 0x000000FFU;
    tv_x[1] = 0x00000000U;
    tv_x[2] = 0x00000000U;
    tv_x[3] = 0x00000000U;
    tv_y[0] = 0x01010101U;
    tv_y[1] = 0x01010101U;
    tv_y[2] = 0x01010101U;
    tv_y[3] = 0x01010101U;
    gf128_mul_sftl_u32(tv_z, tv_y, tv_x);
    printHex((void*)tv_x, GHASH_SIZE, "tv_x", GHASH_SIZE);
    printHex((void*)tv_y, GHASH_SIZE, "tv_y", GHASH_SIZE);
    printHex((void*)tv_z, GHASH_SIZE, "gf128_mul_sftl_u32(tv_z, tv_y, tv_x)", GHASH_SIZE);

    printf("\r\n");
    printf("\r\n");
    printf("<<__X0 mul H to __X1>>\r\n");
    uint8_t ____H[] = {
        0x73, 0xA2, 0x3D, 0x80, 0x12, 0x1D, 0xE2, 0xD5, 0xA8, 0x50, 0x25, 0x3F, 0xCF, 0x43, 0x12, 0x0E, 
    };
    uint8_t ___X0[] = { 0xD6, 0x09, 0xB1, 0xF0, 0x56, 0x63, 0x7A, 0x0D, 0x46, 0xDF, 0x99, 0x8D, 0x88, 0xE5, 0x22, 0x2A };
    uint8_t ___x1[] = { 0x6B, 0x0B, 0xE6, 0x8D, 0x67, 0xC6, 0xEE, 0x03, 0xEF, 0x79, 0x98, 0xE3, 0x99, 0xC0, 0x1C, 0xA4 };
    uint8_t ___X1[16];

#define TEST_LOOP_COUNT 1000UL
    //this
    memset(___X1, 0, sizeof(___X1));
    _a_clk = 0UL;
    for(size_t _l = 0UL; _l < TEST_LOOP_COUNT; _l++)
    {
        _s_clk = clock();
        gf128_mul_sftl_u32_byte_reflect((uint32_t*)___X1, (uint32_t*)___X0, (uint32_t*)____H);
        _e_clk = clock();
        _d_clk = _e_clk - _s_clk;
        if(_d_clk > 1000UL) continue;
        _a_clk += _d_clk;
    }
    printHex(____H, GHASH_SIZE, "____H", GHASH_SIZE);
    printHex(___X0, GHASH_SIZE, "___X0", GHASH_SIZE);
    printHex(___X1, GHASH_SIZE, "gf128_mul_sftl_u32_byte_reflect: ___X1", GHASH_SIZE);
    printf("clk: %lu\r\n", _a_clk);
    chkVector(___x1, ___X1, GHASH_SIZE);

    // this
    memset(___X1, 0, sizeof(___X1));
    _a_clk = 0UL;
    for(size_t _l = 0UL; _l < TEST_LOOP_COUNT; _l++)
    {
        _s_clk = clock();
        gf128_mul_sftr_u32_byte_swap((uint32_t*)___X1, (uint32_t*)___X0, (uint32_t*)____H);
        _e_clk = clock();
        _d_clk = _e_clk - _s_clk;
        if(_d_clk > 1000UL) continue;
        _a_clk += _d_clk;
    }
    printHex(____H, GHASH_SIZE, "____H", GHASH_SIZE);
    printHex(___X0, GHASH_SIZE, "___X0", GHASH_SIZE);
    printHex(___X1, GHASH_SIZE, "gf128_mul_sftr_u32_byte_swap: ___X1", GHASH_SIZE);
    printf("clk: %lu\r\n", _a_clk);
    chkVector(___x1, ___X1, GHASH_SIZE);
#undef TEST_LOOP_COUNT

    printf("\r\n");
    printf("\r\n");
    printf("2.1.1 54-byte Packet Authentication Using GCM-AES-128\r\n");
    uint8_t tv_H[] = {
        0x73, 0xA2, 0x3D, 0x80, 0x12, 0x1D, 0xE2, 0xD5, 0xA8, 0x50, 0x25, 0x3F, 0xCF, 0x43, 0x12, 0x0E, 
    };
    uint8_t tv_A[] = {
        0xD6, 0x09, 0xB1, 0xF0, 0x56, 0x63, 0x7A, 0x0D, 0x46, 0xDF, 0x99, 0x8D, 0x88, 0xE5, 0x22, 0x2A, 
        0xB2, 0xC2, 0x84, 0x65, 0x12, 0x15, 0x35, 0x24, 0xC0, 0x89, 0x5E, 0x81, 0x08, 0x00, 0x0F, 0x10, 
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 
        0x31, 0x32, 0x33, 0x34, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    };
    uint8_t tv_ref[] = {
        0x6B, 0x0B, 0xE6, 0x8D, 0x67, 0xC6, 0xEE, 0x03, 0xEF, 0x79, 0x98, 0xE3, 0x99, 0xC0, 0x1C, 0xA4, 
        0x5A, 0xAB, 0xAD, 0xF6, 0xD7, 0x80, 0x6E, 0xC0, 0xCC, 0xCB, 0x02, 0x84, 0x41, 0x19, 0x7B, 0x22, 
        0xFE, 0x07, 0x2B, 0xFE, 0x28, 0x11, 0xA6, 0x8A, 0xD7, 0xFD, 0xB0, 0x68, 0x71, 0x92, 0xD2, 0x93, 
        0xA4, 0x72, 0x52, 0xD1, 0xA7, 0xE0, 0x9B, 0x49, 0xFB, 0x35, 0x6E, 0x43, 0x5D, 0xBB, 0x4C, 0xD0, 
        0x18, 0xEB, 0xF4, 0xC6, 0x5C, 0xE8, 0x9B, 0xF6, 0x9E, 0xFB, 0x49, 0x81, 0xCE, 0xE1, 0x3D, 0xB9, 
    };
    uint8_t tv_ghash[GHASH_SIZE];

    memset(tv_x, 0, sizeof(tv_x));
    memset(tv_y, 0, sizeof(tv_y));

    gf128_ghash(tv_ghash, tv_H, tv_A, 1U<<4U);
    printHex(tv_ghash, GHASH_SIZE, "X[1]", GHASH_SIZE);
    chkVector(&tv_ref[0UL<<4UL], tv_ghash, (size_t)GHASH_SIZE);

    gf128_ghash(tv_ghash, tv_H, tv_A, 2U<<4U);
    printHex(tv_ghash, GHASH_SIZE, "X[2]", GHASH_SIZE);
    chkVector(&tv_ref[1UL<<4UL], tv_ghash, (size_t)GHASH_SIZE);

    gf128_ghash(tv_ghash, tv_H, tv_A, 3U<<4U);
    printHex(tv_ghash, GHASH_SIZE, "X[3]", GHASH_SIZE);
    chkVector(&tv_ref[2UL<<4UL], tv_ghash, (size_t)GHASH_SIZE);

    gf128_ghash(tv_ghash, tv_H, tv_A, 4U<<4U);
    printHex(tv_ghash, GHASH_SIZE, "X[4]", GHASH_SIZE);
    chkVector(&tv_ref[3UL<<4UL], tv_ghash, (size_t)GHASH_SIZE);

    gf128_ghash(tv_ghash, tv_H, tv_A, 5U<<4U);
    printHex(tv_ghash, GHASH_SIZE, "X[5]", GHASH_SIZE);
    chkVector(&tv_ref[4UL<<4UL], tv_ghash, (size_t)GHASH_SIZE);

    return 0;
}

#ifdef TEST_AES
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "aes/aes.h"

#define TEST_AES_RUN(STATEMENTS, FRTN)              \
{                                                   \
    if(((FRTN) = (STATEMENTS)) != 0)                \
    {                                               \
        printf("%s=%d\r\n", "STATEMENT", (FRTN));   \
    }                                               \
}

#define TEST_AES_EXAM(STATEMENTS, DESCRIPTION)                      \
{                                                                   \
    bool examResult = ((STATEMENTS));                               \
    printf("%s:%s\r\n", (examResult?MES_PASS:MES_FAIL), (DESCRIPTION)); \
}

/* 
 * TestVectors Ref.
 * [Title]  Advanced Encryption Standard (AES), FIPS 197
 * [Link]   https://csrc.nist.gov/pubs/fips/197/final
 * [Title]  Cryptographic Standards and Guidelines, Examples with Intermediate Values
 * [Link]   https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
 */

uint8_t tv_AES128_key[] = 
{
    0x2bU, 0x7eU, 0x15U, 0x16U, 
    0x28U, 0xaeU, 0xd2U, 0xa6U, 
    0xabU, 0xf7U, 0x15U, 0x88U, 
    0x09U, 0xcfU, 0x4fU, 0x3cU, 
};

uint8_t tv_AES192_key[] = 
{
    0x8eU, 0x73U, 0xb0U, 0xf7U, 
    0xdaU, 0x0eU, 0x64U, 0x52U, 
    0xc8U, 0x10U, 0xf3U, 0x2bU, 
    0x80U, 0x90U, 0x79U, 0xe5U, 
    0x62U, 0xf8U, 0xeaU, 0xd2U, 
    0x52U, 0x2cU, 0x6bU, 0x7bU, 
};

uint8_t tv_AES256_key[] = 
{
    0x60U, 0x3dU, 0xebU, 0x10U, 
    0x15U, 0xcaU, 0x71U, 0xbeU, 
    0x2bU, 0x73U, 0xaeU, 0xf0U, 
    0x85U, 0x7dU, 0x77U, 0x81U, 
    0x1fU, 0x35U, 0x2cU, 0x07U, 
    0x3bU, 0x61U, 0x08U, 0xd7U, 
    0x2dU, 0x98U, 0x10U, 0xa3U, 
    0x09U, 0x14U, 0xdfU, 0xf4U, 
};

uint8_t tv_AES128_FIPS197_pTxt_ref[] = {
    0x32U, 0x43U, 0xf6U, 0xa8U, 
    0x88U, 0x5aU, 0x30U, 0x8dU, 
    0x31U, 0x31U, 0x98U, 0xa2U, 
    0xe0U, 0x37U, 0x07U, 0x34U, 
};

uint8_t tv_AES128_FIPS197_cTxt_ref[] = {
    0x39U, 0x25U, 0x84U, 0x1dU, 
    0x02U, 0xdcU, 0x09U, 0xfbU, 
    0xdcU, 0x11U, 0x85U, 0x97U, 
    0x19U, 0x6aU, 0x0bU, 0x32U, 
};

uint8_t tv_AES_NIST_Ex_pTxt_ref[4U][AES_S_SIZE] = {
    { 0x6bU, 0xc1U, 0xbeU, 0xe2U, 0x2eU, 0x40U, 0x9fU, 0x96U, 0xe9U, 0x3dU, 0x7eU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2aU, }, 
    { 0xaeU, 0x2dU, 0x8aU, 0x57U, 0x1eU, 0x03U, 0xacU, 0x9cU, 0x9eU, 0xb7U, 0x6fU, 0xacU, 0x45U, 0xafU, 0x8eU, 0x51U, }, 
    { 0x30U, 0xc8U, 0x1cU, 0x46U, 0xa3U, 0x5cU, 0xe4U, 0x11U, 0xe5U, 0xfbU, 0xc1U, 0x19U, 0x1aU, 0x0aU, 0x52U, 0xefU, }, 
    { 0xf6U, 0x9fU, 0x24U, 0x45U, 0xdfU, 0x4fU, 0x9bU, 0x17U, 0xadU, 0x2bU, 0x41U, 0x7bU, 0xe6U, 0x6cU, 0x37U, 0x10U, }, 
};

uint8_t tv_AES128_NIST_Ex_cTxt_ref[4U][AES_S_SIZE] = {
    { 0x3aU, 0xd7U, 0x7bU, 0xb4U, 0x0dU, 0x7aU, 0x36U, 0x60U, 0xa8U, 0x9eU, 0xcaU, 0xf3U, 0x24U, 0x66U, 0xefU, 0x97U, }, 
    { 0xf5U, 0xd3U, 0xd5U, 0x85U, 0x03U, 0xb9U, 0x69U, 0x9dU, 0xe7U, 0x85U, 0x89U, 0x5aU, 0x96U, 0xfdU, 0xbaU, 0xafU, }, 
    { 0x43U, 0xb1U, 0xcdU, 0x7fU, 0x59U, 0x8eU, 0xceU, 0x23U, 0x88U, 0x1bU, 0x00U, 0xe3U, 0xedU, 0x03U, 0x06U, 0x88U, }, 
    { 0x7bU, 0x0cU, 0x78U, 0x5eU, 0x27U, 0xe8U, 0xadU, 0x3fU, 0x82U, 0x23U, 0x20U, 0x71U, 0x04U, 0x72U, 0x5dU, 0xd4U, }, 
};

uint8_t tv_AES192_NIST_Ex_cTxt_ref[4U][AES_S_SIZE] = {
    { 0xbdU, 0x33U, 0x4fU, 0x1dU, 0x6eU, 0x45U, 0xf2U, 0x5fU, 0xf7U, 0x12U, 0xa2U, 0x14U, 0x57U, 0x1fU, 0xa5U, 0xccU, }, 
    { 0x97U, 0x41U, 0x04U, 0x84U, 0x6dU, 0x0aU, 0xd3U, 0xadU, 0x77U, 0x34U, 0xecU, 0xb3U, 0xecU, 0xeeU, 0x4eU, 0xefU, }, 
    { 0xefU, 0x7aU, 0xfdU, 0x22U, 0x70U, 0xe2U, 0xe6U, 0x0aU, 0xdcU, 0xe0U, 0xbaU, 0x2fU, 0xacU, 0xe6U, 0x44U, 0x4eU, }, 
    { 0x9aU, 0x4bU, 0x41U, 0xbaU, 0x73U, 0x8dU, 0x6cU, 0x72U, 0xfbU, 0x16U, 0x69U, 0x16U, 0x03U, 0xc1U, 0x8eU, 0x0eU, }, 
};

uint8_t tv_AES256_NIST_Ex_cTxt_ref[4U][AES_S_SIZE] = {
    { 0xf3U, 0xeeU, 0xd1U, 0xbdU, 0xb5U, 0xd2U, 0xa0U, 0x3cU, 0x06U, 0x4bU, 0x5aU, 0x7eU, 0x3dU, 0xb1U, 0x81U, 0xf8U, }, 
    { 0x59U, 0x1cU, 0xcbU, 0x10U, 0xd4U, 0x10U, 0xedU, 0x26U, 0xdcU, 0x5bU, 0xa7U, 0x4aU, 0x31U, 0x36U, 0x28U, 0x70U, }, 
    { 0xb6U, 0xedU, 0x21U, 0xb9U, 0x9cU, 0xa6U, 0xf4U, 0xf9U, 0xf1U, 0x53U, 0xe7U, 0xb1U, 0xbeU, 0xafU, 0xedU, 0x1dU, }, 
    { 0x23U, 0x30U, 0x4bU, 0x7aU, 0x39U, 0xf9U, 0xf3U, 0xffU, 0x06U, 0x7dU, 0x8dU, 0x8fU, 0x9eU, 0x24U, 0xecU, 0xc7U, }, 
};

uint8_t test_AES_out[AES_S_SIZE];

void test_aesEncV1(void)
{
    printf("%s:%d:%s\r\n", __FILE__, __LINE__, __func__);

    int fRtn;

    printf("[AES128 Encryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES_NIST_Ex_pTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        TEST_AES_RUN(aesEncV1(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], tv_AES128_key, sizeof(tv_AES128_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        TEST_AES_EXAM(memcmp(test_AES_out, tv_AES128_NIST_Ex_cTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES128 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Encrypt Values", AES_S_SIZE);
    }

    printf("[AES192 Encryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES_NIST_Ex_pTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        TEST_AES_RUN(aesEncV1(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], tv_AES192_key, sizeof(tv_AES192_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        TEST_AES_EXAM(memcmp(test_AES_out, tv_AES192_NIST_Ex_cTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES192 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Encrypt Values", AES_S_SIZE);
    }

    printf("[AES256 Encryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES_NIST_Ex_pTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        TEST_AES_RUN(aesEncV1(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], tv_AES256_key, sizeof(tv_AES256_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        TEST_AES_EXAM(memcmp(test_AES_out, tv_AES256_NIST_Ex_cTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES256 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Encrypt Values", AES_S_SIZE);
    }
}

void test_aesDecV1(void)
{
    printf("%s:%d:%s\r\n", __FILE__, __LINE__, __func__);

    int fRtn;

    printf("[AES128 Decryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES128_NIST_Ex_cTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        TEST_AES_RUN(aesDecV1(test_AES_out, tv_AES128_NIST_Ex_cTxt_ref[tvi], tv_AES128_key, sizeof(tv_AES128_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        TEST_AES_EXAM(memcmp(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES128 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Decrypt Values", AES_S_SIZE);
    }

    printf("[AES192 Decryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES192_NIST_Ex_cTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        TEST_AES_RUN(aesDecV1(test_AES_out, tv_AES192_NIST_Ex_cTxt_ref[tvi], tv_AES192_key, sizeof(tv_AES192_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        TEST_AES_EXAM(memcmp(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES192 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Decrypt Values", AES_S_SIZE);
    }

    printf("[AES256 Decryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES256_NIST_Ex_cTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        TEST_AES_RUN(aesDecV1(test_AES_out, tv_AES256_NIST_Ex_cTxt_ref[tvi], tv_AES256_key, sizeof(tv_AES256_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        TEST_AES_EXAM(memcmp(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES256 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Decrypt Values", AES_S_SIZE);
    }
}

void test_aesDecV2(void)
{
    int fRtn;
    printf("%s:%d:%s\r\n", __FILE__, __LINE__, __func__);

    printf("[AES128 Decryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES128_NIST_Ex_cTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        TEST_AES_RUN(aesDecV2(test_AES_out, tv_AES128_NIST_Ex_cTxt_ref[tvi], tv_AES128_key, sizeof(tv_AES128_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        TEST_AES_EXAM(memcmp(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES128 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Decrypt Values", AES_S_SIZE);
    }

    printf("[AES192 Decryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES192_NIST_Ex_cTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        TEST_AES_RUN(aesDecV2(test_AES_out, tv_AES192_NIST_Ex_cTxt_ref[tvi], tv_AES192_key, sizeof(tv_AES192_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        TEST_AES_EXAM(memcmp(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES192 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Decrypt Values", AES_S_SIZE);
    }

    printf("[AES256 Decryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES256_NIST_Ex_cTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        TEST_AES_RUN(aesDecV2(test_AES_out, tv_AES256_NIST_Ex_cTxt_ref[tvi], tv_AES256_key, sizeof(tv_AES256_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        TEST_AES_EXAM(memcmp(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES256 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Decrypt Values", AES_S_SIZE);
    }

}

void test_aes_blanks(void)
{
    printf("%s:%d:%s\r\n", __FILE__, __LINE__, __func__);

    uint8_t test_allZero[AES_S_SIZE];
    uint8_t test_gcm211_key[] = { 0xAD, 0x7A, 0x2B, 0xD0, 0x3E, 0xAC, 0x83, 0x5A, 0x6F, 0x62, 0x0F, 0xDC, 0xB5, 0x06, 0xB3, 0x45 };

    (void)memset(test_allZero, 0x0, AES_S_SIZE);
    (void)memset(test_AES_out, 0x0, AES_S_SIZE);
    aesEncV1(test_AES_out, test_allZero, test_gcm211_key, sizeof(test_gcm211_key));
    printHex(test_AES_out, sizeof(test_AES_out), "2.1.1. GCM, H", AES_S_SIZE);
}

void test_aesEncSUP(void)
{
    printf("%s:%d:%s\r\n", __FILE__, __LINE__, __func__);

    int fRtn;

    for(size_t tvi = 0UL; tvi < sizeof(tv_AES_NIST_Ex_pTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        TEST_AES_RUN(startAes(tv_AES128_key, sizeof(tv_AES128_key), AES_ENCRYPT), fRtn);
        TEST_AES_RUN(updateAes(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], sizeof(tv_AES_NIST_Ex_pTxt_ref[tvi])), fRtn);
        TEST_AES_RUN(finishAes(), fRtn);
        printf("AES128-ECB Encrypt#%2ld: %s\n", tvi, \
            ((memcmp(test_AES_out, tv_AES128_NIST_Ex_cTxt_ref[tvi], AES_S_SIZE) == 0)?MES_PASS:MES_FAIL));
    }

    for(size_t tvi = 0UL; tvi < sizeof(tv_AES_NIST_Ex_pTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        TEST_AES_RUN(startAes(tv_AES192_key, sizeof(tv_AES192_key), AES_ENCRYPT), fRtn);
        TEST_AES_RUN(updateAes(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], sizeof(tv_AES_NIST_Ex_pTxt_ref[tvi])), fRtn);
        TEST_AES_RUN(finishAes(), fRtn);
        printf("AES192-ECB Encrypt#%2ld: %s\n", tvi, \
            ((memcmp(test_AES_out, tv_AES192_NIST_Ex_cTxt_ref[tvi], AES_S_SIZE) == 0)?MES_PASS:MES_FAIL));
    }

    for(size_t tvi = 0UL; tvi < sizeof(tv_AES_NIST_Ex_pTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        TEST_AES_RUN(startAes(tv_AES256_key, sizeof(tv_AES256_key), AES_ENCRYPT), fRtn);
        TEST_AES_RUN(updateAes(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], sizeof(tv_AES_NIST_Ex_pTxt_ref[tvi])), fRtn);
        TEST_AES_RUN(finishAes(), fRtn);
        printf("AES256-ECB Encrypt#%2ld: %s\n", tvi, \
            ((memcmp(test_AES_out, tv_AES256_NIST_Ex_cTxt_ref[tvi], AES_S_SIZE) == 0)?MES_PASS:MES_FAIL));
    }
}

void test_aesDecSUP(void)
{
    printf("%s:%d:%s\r\n", __FILE__, __LINE__, __func__);

    int fRtn;

    for(size_t tvi = 0UL; tvi < sizeof(tv_AES128_NIST_Ex_cTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        TEST_AES_RUN(startAes(tv_AES128_key, sizeof(tv_AES128_key), AES_DECRYPT), fRtn);
        TEST_AES_RUN(updateAes(test_AES_out, tv_AES128_NIST_Ex_cTxt_ref[tvi], sizeof(tv_AES128_NIST_Ex_cTxt_ref[tvi])), fRtn);
        TEST_AES_RUN(finishAes(), fRtn);
        printf("AES128-ECB Decrypt#%2ld: %s\n", tvi, \
            ((memcmp(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], AES_S_SIZE) == 0)?MES_PASS:MES_FAIL));
    }

    for(size_t tvi = 0UL; tvi < sizeof(tv_AES192_NIST_Ex_cTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        TEST_AES_RUN(startAes(tv_AES192_key, sizeof(tv_AES192_key), AES_DECRYPT), fRtn);
        TEST_AES_RUN(updateAes(test_AES_out, tv_AES192_NIST_Ex_cTxt_ref[tvi], sizeof(tv_AES192_NIST_Ex_cTxt_ref[tvi])), fRtn);
        TEST_AES_RUN(finishAes(), fRtn);
        printf("AES192-ECB Decrypt#%2ld: %s\n", tvi, \
            ((memcmp(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], AES_S_SIZE) == 0)?MES_PASS:MES_FAIL));
    }

    for(size_t tvi = 0UL; tvi < sizeof(tv_AES256_NIST_Ex_cTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        TEST_AES_RUN(startAes(tv_AES256_key, sizeof(tv_AES256_key), AES_DECRYPT), fRtn);
        TEST_AES_RUN(updateAes(test_AES_out, tv_AES256_NIST_Ex_cTxt_ref[tvi], sizeof(tv_AES256_NIST_Ex_cTxt_ref[tvi])), fRtn);
        TEST_AES_RUN(finishAes(), fRtn);
        printf("AES256-ECB Decrypt#%2ld: %s\n", tvi, \
            ((memcmp(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], AES_S_SIZE) == 0)?MES_PASS:MES_FAIL));
    }
}

void test_aes(void)
{
    test_aesEncV1();

    test_aesDecV1();
    test_aesDecV2();

    test_aes_blanks(); // calcaulates AES-GCM H

    test_aesEncSUP();
    test_aesDecSUP();
}

#undef TEST_AES_RUN
#undef TEST_AES_EXAM
#endif /* TEST_AES */

#ifdef TEST_ENDIAN
#include "endian/endian.h"
void test_endian(void)
{
    test_endian_environments();
}
#endif /* TEST_ENDIAN */

#ifdef TEST_SHA
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h> // exit()

#include "hash/sha2.h"

typedef union {
    uint32_t sha256DgSym[SHA2_DIGEST_NUM];
    uint64_t sha512DgSym[SHA2_DIGEST_NUM];
} sha2DgSym_t;
typedef union {
    uint8_t sha256DgStm[SHA256_DIGEST_SIZE];
    uint8_t sha512DgStm[SHA512_DIGEST_SIZE];
} sha2DgStm_t;

sha2DgSym_t g_sha2DgSym;
sha2DgStm_t g_sha2DgStm;

#define g_sha256Dg32bSym    g_sha2DgSym.sha256DgSym
#define g_sha256Dg_8bStm    g_sha2DgStm.sha256DgStm
#define g_sha512Dg64bSym    g_sha2DgSym.sha512DgSym
#define g_sha512Dg_8bStm    g_sha2DgStm.sha512DgStm

const char ref_test_CAVP[] = "[REFERENCES]\nCryptographic Algorithm Validation Program CAVP\n[Link] https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing\nSHA Test Vectors for Hashing Byte-Oriented Messages\n[Link] https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip";
void test_CAVP(void)
{
    printf("%s\n", ref_test_CAVP);

    /* All zero: updateSha256 */
    {
        printf("--------------------------------------------------------------------------------\n");

        uint8_t mes_all_0[SHA256_BLOCK_SIZE] = { 0 };
        const size_t mes_all_0_size = 0UL;

        printf("MESSAGE IS '0' VECTOR\n");

        startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

        updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)mes_all_0, mes_all_0_size);

        finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

        convSymbolToStreamSha256((uint32_t*)g_sha256Dg_8bStm, (const uint32_t*)g_sha256Dg32bSym, SHA256_DIGEST_SIZE);
        printf("[DIGEST]\n");
        printf("(32bit) 0x ");
        for(size_t si = 0UL; si < EDCSIZE2W32LEN(sizeof(g_sha256Dg32bSym)); si++)
        {
            printf("%08x", g_sha256Dg32bSym[si]);
        }
        printf("\n");
        printf("( 8bit) 0x ");
        for(size_t xi = 0UL; xi < sizeof(g_sha256Dg_8bStm); xi++)
        {
            printf("%02x", g_sha256Dg_8bStm[xi]);
        }
        printf("\n");

        printf("================================================================================\n");
    }
}

const char ref_test_FIPS_180_2_imVal[] = "[REFERENCES]\nCryptographic Standards and Guidelines\n[Link] https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values\nFIPS 180-2 - Secure Hash Standard, SHA256 Intermediate Value\n[Link] https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf";
void test_FIPS_180_2_imVal_sha256(void)
{
    printf("%s\n", ref_test_FIPS_180_2_imVal);

    {
        const uint32_t ref_mes_abc_pad[SHA2_BLOCK_NUM] = {
            0x61626380u, 0x00000000u, 0x00000000u, 0x00000000u, 
            0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 
            0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 
            0x00000000u, 0x00000000u, 0x00000000u, 0x00000018u
        };
        {
            printf("(ref_mes_abc_pad 32bit)\n0x ");
            for(size_t si = 0UL; si < EDCSIZE2W32LEN(sizeof(ref_mes_abc_pad)); si++)
            {
                printf("%08x ", ref_mes_abc_pad[si]);
                if((si&0x7U)==0x7U) printf("\n");
            }
            printf("\n");
        }

    }

    /* abc: updateSha256: 32bit_symbol */
    {
        printf("--------------------------------------------------------------------------------\n");

        uint32_t mes_abc_32b_symbol[SHA2_BLOCK_NUM] = {
            0x616263ffu, 0xffffffffu, 0xffffffffu, 0xffffffffu, 
            0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu, 
            0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu, 
            0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu
        };
        const size_t mes_abc_size = 3UL;
        {
            printf("(mes_abc_32b_symbol 32bit)\n0x ");
            for(size_t si = 0UL; si < EDCSIZE2W32LEN(sizeof(mes_abc_32b_symbol)); si++)
            {
                printf("%08x ", mes_abc_32b_symbol[si]);
                if((si&0x7U)==0x7U) printf("\n");
            }
            printf("\n");
        }

        printf("MESSAGE IS 32BIT SYMBOL\n");

        startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

        updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)mes_abc_32b_symbol, mes_abc_size);

        finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

        convSymbolToStreamSha256((uint32_t*)g_sha256Dg_8bStm, (const uint32_t*)g_sha256Dg32bSym, SHA256_DIGEST_SIZE);
        printf("[DIGEST]\n");
        printf("(32bit) 0x ");
        for(size_t si = 0UL; si < EDCSIZE2W32LEN(sizeof(g_sha256Dg32bSym)); si++)
        {
            printf("%08x", g_sha256Dg32bSym[si]);
        }
        printf("\n");
        printf("( 8bit) 0x ");
        for(size_t xi = 0UL; xi < sizeof(g_sha256Dg_8bStm); xi++)
        {
            printf("%02x", g_sha256Dg_8bStm[xi]);
        }
        printf("\n");

        printf("================================================================================\n");
    }

    /* abc: updateSha256: 8bit_stream */
    {
        printf("--------------------------------------------------------------------------------\n");

        uint8_t mes_abc_8b_stream[SHA256_BLOCK_SIZE] = {
            0x61u, 0x62u, 0x63u, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 
            0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 
            0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 
            0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu
        };
        const size_t mes_abc_size = 3UL;

        printf("MESSAGE IS 8BIT STREAM\n");

        convStreamToSymbolSha256((uint32_t*)mes_abc_8b_stream, (const uint32_t*)mes_abc_8b_stream, sizeof(mes_abc_8b_stream));

        startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

        updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)mes_abc_8b_stream, mes_abc_size);

        finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

        convSymbolToStreamSha256((uint32_t*)g_sha256Dg_8bStm, (const uint32_t*)g_sha256Dg32bSym, SHA256_DIGEST_SIZE);
        printf("[DIGEST]\n");
        printf("(32bit) 0x ");
        for(size_t si = 0UL; si < EDCSIZE2W32LEN(sizeof(g_sha256Dg32bSym)); si++)
        {
            printf("%08x", g_sha256Dg32bSym[si]);
        }
        printf("\n");
        printf("( 8bit) 0x ");
        for(size_t xi = 0UL; xi < sizeof(g_sha256Dg_8bStm); xi++)
        {
            printf("%02x", g_sha256Dg_8bStm[xi]);
        }
        printf("\n");

        printf("================================================================================\n");
    }

    /* abc: updateSha256: 8bit_string */
    {
        printf("--------------------------------------------------------------------------------\n");

        uint8_t mes_string_8b_stream[SHA256_BLOCK_SIZE] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        const size_t mes_string_size = strlen(mes_string_8b_stream);

        printf("MESSAGE IS 8BIT STRING\n");

        convStreamToSymbolSha256((uint32_t*)mes_string_8b_stream, (const uint32_t*)mes_string_8b_stream, sizeof(mes_string_8b_stream));

        startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

        updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)mes_string_8b_stream, mes_string_size);

        finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

        convSymbolToStreamSha256((uint32_t*)g_sha256Dg_8bStm, (const uint32_t*)g_sha256Dg32bSym, SHA256_DIGEST_SIZE);
        printf("[DIGEST]\n");
        printf("(32bit) 0x ");
        for(size_t si = 0UL; si < EDCSIZE2W32LEN(sizeof(g_sha256Dg32bSym)); si++)
        {
            printf("%08x", g_sha256Dg32bSym[si]);
        }
        printf("\n");
        printf("( 8bit) 0x ");
        for(size_t xi = 0UL; xi < sizeof(g_sha256Dg_8bStm); xi++)
        {
            printf("%02x", g_sha256Dg_8bStm[xi]);
        }
        printf("\n");

        printf("================================================================================\n");
    }
}

const char ref_test_FIPS_180_2_example_SHA2_Additional[] = "[REFERENCES]\nCryptographic Standards and Guidelines\n[Link] https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values\nFIPS 180-2 - Secure Hash Standard, data for SHA2 algorithms (without intermediate values)\n[Link] https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA2_Additional.pdf";
void test_FIPS_180_2_example_SHA2_Additional(void)
{
    printf("%s\n", ref_test_FIPS_180_2_example_SHA2_Additional);

    /* SHA-256 Test Data */
    {
        printf("--------------------------------------------------------------------------------\n");
        printf("[SHA-256 Test Data]\n");
        printf("================================================================================\n");
        /* #1) 1 byte 0xbd                                  */
        {
            printf("--------------------------------------------------------------------------------\n");

            size_t tv_num = 1UL;
            uint8_t tv_mesStm[SHA256_BLOCK_SIZE] = { 0xbdu, };
            const size_t tv_sz = 1UL;
            const uint32_t ref_dgSym[SHA2_DIGEST_NUM] = {
                0x68325720U, 0xaabd7c82U, 0xf30f554bU, 0x313d0570U, 0xc95accbbU, 0x7dc4b5aaU, 0xe11204c0U, 0x8ffe732bU,
            };

            convStreamToSymbolSha256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

            updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)tv_mesStm, tv_sz);

            finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

            printf("SHA-256 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

            printf("================================================================================\n");
        }
        /* #2) 4 bytes 0xc98c8e55                           */
        {
            printf("--------------------------------------------------------------------------------\n");

            size_t tv_num = 2UL;
            uint8_t tv_mesStm[SHA256_BLOCK_SIZE] = { 0xc9u, 0x8cu, 0x8eu, 0x55u, };
            const size_t tv_sz = 4UL;
            const uint32_t ref_dgSym[SHA2_DIGEST_NUM] = {
                0x7abc22c0U, 0xae5af26cU, 0xe93dbb94U, 0x433a0e0bU, 0x2e119d01U, 0x4f8e7f65U, 0xbd56c61cU, 0xcccd9504U,
            };

            convStreamToSymbolSha256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

            updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)tv_mesStm, tv_sz);

            finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

            printf("SHA-256 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

            printf("================================================================================\n");
        }
        /* #3) 55 bytes of zeros                            */
        {
            printf("--------------------------------------------------------------------------------\n");

            size_t tv_num = 3UL;
            uint8_t tv_mesStm[SHA256_BLOCK_SIZE] = { 0x0u, };
            const size_t tv_sz = 55UL;
            const uint32_t ref_dgSym[SHA2_DIGEST_NUM] = {
                0x02779466U, 0xcdec1638U, 0x11d07881U, 0x5c633f21U, 0x90141308U, 0x1449002fU, 0x24aa3e80U, 0xf0b88ef7U,
            };

            convStreamToSymbolSha256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

            updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)tv_mesStm, tv_sz);

            finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

            printf("SHA-256 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

            printf("================================================================================\n");
        }
        /* #4) 56 bytes of zeros                            */
        {
            printf("--------------------------------------------------------------------------------\n");

            size_t tv_num = 4UL;
            uint8_t tv_mesStm[SHA256_BLOCK_SIZE] = { 0x0u, };
            const size_t tv_sz = 56UL;
            const uint32_t ref_dgSym[SHA2_DIGEST_NUM] = {
                0xd4817aa5U, 0x497628e7U, 0xc77e6b60U, 0x6107042bU, 0xbba31308U, 0x88c5f47aU, 0x375e6179U, 0xbe789fbbU,
            };

            convStreamToSymbolSha256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

            updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)tv_mesStm, tv_sz);

            finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

            printf("SHA-256 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

            printf("================================================================================\n");
        }
        /* #5) 57 bytes of zeros                            */
        {
            printf("--------------------------------------------------------------------------------\n");

            size_t tv_num = 5UL;
            uint8_t tv_mesStm[SHA256_BLOCK_SIZE] = { 0x0u, };
            const size_t tv_sz = 57UL;
            const uint32_t ref_dgSym[SHA2_DIGEST_NUM] = {
                0x65a16cb7U, 0x861335d5U, 0xace3c607U, 0x18b5052eU, 0x44660726U, 0xda4cd13bU, 0xb745381bU, 0x235a1785U,
            };

            convStreamToSymbolSha256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

            updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)tv_mesStm, tv_sz);

            finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

            printf("SHA-256 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

            printf("================================================================================\n");
        }
        /* #6) 64 bytes of zeros                            */
        {
            printf("--------------------------------------------------------------------------------\n");

            size_t tv_num = 6UL;
            uint8_t tv_mesStm[SHA256_BLOCK_SIZE] = { 0x0u, };
            const size_t tv_sz = 64UL;
            const uint32_t ref_dgSym[SHA2_DIGEST_NUM] = {
                0xf5a5fd42U, 0xd16a2030U, 0x2798ef6eU, 0xd309979bU, 0x43003d23U, 0x20d9f0e8U, 0xea9831a9U, 0x2759fb4bU,
            };

            convStreamToSymbolSha256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

            updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)tv_mesStm, tv_sz);

            finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

            printf("SHA-256 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

            printf("================================================================================\n");
        }
        /* #7) 1000 bytes of zeros                          */
        {
            printf("--------------------------------------------------------------------------------\n");

            size_t tv_num = 7UL;
            uint8_t tv_mesStm[SHA256_BLOCK_SIZE];
            const size_t tv_sz = 1000UL;
            const uint32_t ref_dgSym[SHA2_DIGEST_NUM] = {
                0x541b3e9dU, 0xaa09b20bU, 0xf85fa273U, 0xe5cbd3e8U, 0x0185aa4eU, 0xc298e765U, 0xdb87742bU, 0x70138a53U,
            };
            size_t tv_chSz, tv_remSz, tv_prcSz;
            (void)memset(tv_mesStm, 0x0, SHA256_BLOCK_SIZE);

            convStreamToSymbolSha256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

            tv_remSz = tv_sz;
            for(tv_prcSz = 0UL; tv_prcSz < tv_sz; tv_prcSz += SHA256_BLOCK_SIZE)
            {
                tv_chSz = ((SHA256_BLOCK_SIZE<=tv_remSz)?(SHA256_BLOCK_SIZE):(tv_remSz));

                updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)tv_mesStm, tv_chSz);

                tv_remSz -= tv_chSz;
            }

            finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

            if(tv_remSz != 0UL)
            {
                printf("[ERROR!] Chunk Size Error] Remain Size: %lu\n", tv_remSz);
                exit(1);
            }

            printf("SHA-256 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

            printf("================================================================================\n");
        }
        /* #8) 1000 bytes of 0x41 ‘A’                       */
        {
            printf("--------------------------------------------------------------------------------\n");

            size_t tv_num = 8UL;
            uint8_t tv_mesStm[SHA256_BLOCK_SIZE];
            const size_t tv_sz = 1000UL;
            const uint32_t ref_dgSym[SHA2_DIGEST_NUM] = {
                0xc2e68682U, 0x3489ced2U, 0x017f6059U, 0xb8b23931U, 0x8b6364f6U, 0xdcd835d0U, 0xa519105aU, 0x1eadd6e4U,
            };
            size_t tv_chSz, tv_remSz, tv_prcSz;
            (void)memset(tv_mesStm, 0x41, SHA256_BLOCK_SIZE);

            convStreamToSymbolSha256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

            tv_remSz = tv_sz;
            for(tv_prcSz = 0UL; tv_prcSz < tv_sz; tv_prcSz += SHA256_BLOCK_SIZE)
            {
                tv_chSz = ((SHA256_BLOCK_SIZE<=tv_remSz)?(SHA256_BLOCK_SIZE):(tv_remSz));

                updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)tv_mesStm, tv_chSz);

                tv_remSz -= tv_chSz;
            }

            finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

            if(tv_remSz != 0UL)
            {
                printf("[ERROR!] Chunk Size Error] Remain Size: %lu\n", tv_remSz);
                exit(1);
            }

            printf("SHA-256 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

            printf("================================================================================\n");
        }
        /* #9) 1005 bytes of 0x55 ‘U’                       */
        {
            printf("--------------------------------------------------------------------------------\n");

            size_t tv_num = 9UL;
            uint8_t tv_mesStm[SHA256_BLOCK_SIZE];
            const size_t tv_sz = 1005UL;
            const uint32_t ref_dgSym[SHA2_DIGEST_NUM] = {
                0xf4d62ddeU, 0xc0f3dd90U, 0xea1380faU, 0x16a5ff8dU, 0xc4c54b21U, 0x740650f2U, 0x4afc4120U, 0x903552b0U,
            };
            size_t tv_chSz, tv_remSz, tv_prcSz;
            (void)memset(tv_mesStm, 0x55, SHA256_BLOCK_SIZE);

            convStreamToSymbolSha256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

            tv_remSz = tv_sz;
            for(tv_prcSz = 0UL; tv_prcSz < tv_sz; tv_prcSz += SHA256_BLOCK_SIZE)
            {
                tv_chSz = ((SHA256_BLOCK_SIZE<=tv_remSz)?(SHA256_BLOCK_SIZE):(tv_remSz));

                updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)tv_mesStm, tv_chSz);

                tv_remSz -= tv_chSz;
            }

            finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

            if(tv_remSz != 0UL)
            {
                printf("[ERROR!] Chunk Size Error] Remain Size: %lu\n", tv_remSz);
                exit(1);
            }

            printf("SHA-256 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

            printf("================================================================================\n");
        }
        /* #10) 1000000 bytes of zeros                      */
        {
            printf("--------------------------------------------------------------------------------\n");

            size_t tv_num = 10UL;
            uint8_t tv_mesStm[SHA256_BLOCK_SIZE];
            const size_t tv_sz = 1000000UL;
            const uint32_t ref_dgSym[SHA2_DIGEST_NUM] = {
                0xd29751f2U, 0x649b32ffU, 0x572b5e0aU, 0x9f541ea6U, 0x60a50f94U, 0xff0beedfU, 0xb0b692b9U, 0x24cc8025U,
            };
            size_t tv_chSz, tv_remSz, tv_prcSz;
            (void)memset(tv_mesStm, 0x0, SHA256_BLOCK_SIZE);

            convStreamToSymbolSha256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

            tv_remSz = tv_sz;
            for(tv_prcSz = 0UL; tv_prcSz < tv_sz; tv_prcSz += SHA256_BLOCK_SIZE)
            {
                tv_chSz = ((SHA256_BLOCK_SIZE<=tv_remSz)?(SHA256_BLOCK_SIZE):(tv_remSz));

                updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)tv_mesStm, tv_chSz);

                tv_remSz -= tv_chSz;
            }

            finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

            if(tv_remSz != 0UL)
            {
                printf("[ERROR!] Chunk Size Error] Remain Size: %lu\n", tv_remSz);
                exit(1);
            }

            printf("SHA-256 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

            printf("================================================================================\n");
        }
        /* #11) 0x20000000 (536870912) bytes of 0x5a ‘Z’    */
        {
            printf("--------------------------------------------------------------------------------\n");

            size_t tv_num = 11UL;
            uint8_t tv_mesStm[SHA256_BLOCK_SIZE];
            const size_t tv_sz = 536870912UL;
            const uint32_t ref_dgSym[SHA2_DIGEST_NUM] = {
                0x15a1868cU, 0x12cc5395U, 0x1e182344U, 0x277447cdU, 0x0979536bU, 0xadcc512aU, 0xd24c67e9U, 0xb2d4f3ddU,
            };
            size_t tv_chSz, tv_remSz, tv_prcSz;
            (void)memset(tv_mesStm, 0x5a, SHA256_BLOCK_SIZE);

            convStreamToSymbolSha256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

            tv_remSz = tv_sz;
            for(tv_prcSz = 0UL; tv_prcSz < tv_sz; tv_prcSz += SHA256_BLOCK_SIZE)
            {
                tv_chSz = ((SHA256_BLOCK_SIZE<=tv_remSz)?(SHA256_BLOCK_SIZE):(tv_remSz));

                updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)tv_mesStm, tv_chSz);

                tv_remSz -= tv_chSz;
            }

            finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

            if(tv_remSz != 0UL)
            {
                printf("[ERROR!] Chunk Size Error] Remain Size: %lu\n", tv_remSz);
                exit(1);
            }

            printf("SHA-256 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

            printf("================================================================================\n");
        }
        /* #12) 0x41000000 (1090519040) bytes of zeros      */
        {
            printf("--------------------------------------------------------------------------------\n");

            size_t tv_num = 12UL;
            uint8_t tv_mesStm[SHA256_BLOCK_SIZE];
            const size_t tv_sz = 1090519040UL;
            const uint32_t ref_dgSym[SHA2_DIGEST_NUM] = {
                0x461c19a9U, 0x3bd4344fU, 0x9215f5ecU, 0x64357090U, 0x342bc66bU, 0x15a14831U, 0x7d276e31U, 0xcbc20b53U,
            };
            size_t tv_chSz, tv_remSz, tv_prcSz;
            (void)memset(tv_mesStm, 0x0, SHA256_BLOCK_SIZE);

            convStreamToSymbolSha256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

            tv_remSz = tv_sz;
            for(tv_prcSz = 0UL; tv_prcSz < tv_sz; tv_prcSz += SHA256_BLOCK_SIZE)
            {
                tv_chSz = ((SHA256_BLOCK_SIZE<=tv_remSz)?(SHA256_BLOCK_SIZE):(tv_remSz));

                updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)tv_mesStm, tv_chSz);

                tv_remSz -= tv_chSz;
            }

            finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

            if(tv_remSz != 0UL)
            {
                printf("[ERROR!] Chunk Size Error] Remain Size: %lu\n", tv_remSz);
                exit(1);
            }

            printf("SHA-256 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

            printf("================================================================================\n");
        }
        /* #13) 0x6000003e (1610612798) bytes of 0x42 ‘B’   */
        {
            printf("--------------------------------------------------------------------------------\n");

            size_t tv_num = 13UL;
            uint8_t tv_mesStm[SHA256_BLOCK_SIZE];
            const size_t tv_sz = 1610612798UL;
            const uint32_t ref_dgSym[SHA2_DIGEST_NUM] = {
                0xc23ce8a7U, 0x895f4b21U, 0xec0daf37U, 0x920ac0a2U, 0x62a22004U, 0x5a03eb2dU, 0xfed48ef9U, 0xb05aabeaU,
            };
            size_t tv_chSz, tv_remSz, tv_prcSz;
            (void)memset(tv_mesStm, 0x42, SHA256_BLOCK_SIZE);

            convStreamToSymbolSha256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

            tv_remSz = tv_sz;
            for(tv_prcSz = 0UL; tv_prcSz < tv_sz; tv_prcSz += SHA256_BLOCK_SIZE)
            {
                tv_chSz = ((SHA256_BLOCK_SIZE<=tv_remSz)?(SHA256_BLOCK_SIZE):(tv_remSz));

                updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)tv_mesStm, tv_chSz);

                tv_remSz -= tv_chSz;
            }

            finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

            if(tv_remSz != 0UL)
            {
                printf("[ERROR!] Chunk Size Error] Remain Size: %lu\n", tv_remSz);
                exit(1);
            }

            printf("SHA-256 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

            printf("================================================================================\n");
        }
    }

    /* SHA-512 Test Data */
    {
        printf("--------------------------------------------------------------------------------\n");
        printf("[SHA-512 Test Data]\n");
        printf("================================================================================\n");
        /* #1) 0 byte (null message) */
        {
            printf("--------------------------------------------------------------------------------\n");

            size_t tv_num = 1UL;
            uint8_t tv_mesStm[SHA512_BLOCK_SIZE] = { };
            const size_t tv_sz = 0UL;
            const uint64_t ref_dgSym[SHA2_DIGEST_NUM] = {
                0xcf83e1357eefb8bdU, 0xf1542850d66d8007U, 0xd620e4050b5715dcU, 0x83f4a921d36ce9ce,
                0x47d0d13c5d85f2b0U, 0xff8318d2877eec2fU, 0x63b931bd47417a81U, 0xa538327af927da3e,
            };

            convStreamToSymbolSha512((uint64_t*)tv_mesStm, (const uint64_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha512(g_sha512Dg64bSym, (const uint64_t*)H0_512, sizeof(H0_512));

            updateSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym), (uint64_t*)tv_mesStm, tv_sz);

            finishSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym));

            printf("SHA-512 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha512Dg64bSym, SHA512_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

            printf("================================================================================\n");
        }
        /* #2) 111 bytes of zeros */
        {
            printf("--------------------------------------------------------------------------------\n");

            size_t tv_num = 2UL;
            uint8_t tv_mesStm[SHA512_BLOCK_SIZE];
            const size_t tv_sz = 111UL;
            const uint64_t ref_dgSym[SHA2_DIGEST_NUM] = {
                0x77ddd3a542e530fdU, 0x047b8977c657ba6cU, 0xe72f1492e360b2b2U, 0x212cd264e75ec038,
                0x82e4ff0525517ab4U, 0x207d14c70c2259baU, 0x88d4d335ee0e7e20U, 0x543d22102ab1788c,
            };
            (void)memset(tv_mesStm, 0x0, SHA512_BLOCK_SIZE);

            convStreamToSymbolSha512((uint64_t*)tv_mesStm, (const uint64_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha512(g_sha512Dg64bSym, (const uint64_t*)H0_512, sizeof(H0_512));

            updateSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym), (uint64_t*)tv_mesStm, tv_sz);

            finishSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym));

            printf("SHA-512 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha512Dg64bSym, SHA512_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

            printf("================================================================================\n");
        }
        /* #3) 112 bytes of zeros */
        {
            printf("--------------------------------------------------------------------------------\n");

            size_t tv_num = 3UL;
            uint8_t tv_mesStm[SHA512_BLOCK_SIZE];
            const size_t tv_sz = 112UL;
            const uint64_t ref_dgSym[SHA2_DIGEST_NUM] = {
                0x2be2e788c8a8adeaU, 0xa9c89a7f78904cacU, 0xea6e39297d75e057U, 0x3a73c756234534d6,
                0x627ab4156b48a665U, 0x7b29ab8beb733340U, 0x40ad39ead81446bbU, 0x09c70704ec707952,
            };
            (void)memset(tv_mesStm, 0x0, SHA512_BLOCK_SIZE);

            convStreamToSymbolSha512((uint64_t*)tv_mesStm, (const uint64_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha512(g_sha512Dg64bSym, (const uint64_t*)H0_512, sizeof(H0_512));

            updateSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym), (uint64_t*)tv_mesStm, tv_sz);

            finishSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym));

            printf("SHA-512 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha512Dg64bSym, SHA512_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

            printf("================================================================================\n");
        }
        /* #4) 113 bytes of zeros */
        {
            printf("--------------------------------------------------------------------------------\n");

            size_t tv_num = 4UL;
            uint8_t tv_mesStm[SHA512_BLOCK_SIZE];
            const size_t tv_sz = 113UL;
            const uint64_t ref_dgSym[SHA2_DIGEST_NUM] = {
                0x0e67910bcf0f9ccdU, 0xe5464c63b9c850a1U, 0x2a759227d16b040dU, 0x98986d54253f9f34,
                0x322318e56b8feb86U, 0xc5fb2270ed87f312U, 0x52f7f68493ee7597U, 0x43909bd75e4bb544,
            };
            (void)memset(tv_mesStm, 0x0, SHA512_BLOCK_SIZE);

            convStreamToSymbolSha512((uint64_t*)tv_mesStm, (const uint64_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha512(g_sha512Dg64bSym, (const uint64_t*)H0_512, sizeof(H0_512));

            updateSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym), (uint64_t*)tv_mesStm, tv_sz);

            finishSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym));

            printf("SHA-512 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha512Dg64bSym, SHA512_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

            printf("================================================================================\n");
        }
        /* #5) 122 bytes of zeros */
        {
            printf("--------------------------------------------------------------------------------\n");

            size_t tv_num = 5UL;
            uint8_t tv_mesStm[SHA512_BLOCK_SIZE];
            const size_t tv_sz = 122UL;
            const uint64_t ref_dgSym[SHA2_DIGEST_NUM] = {
                0x4f3f095d015be4a7U, 0xa7cc0b8c04da4aa0U, 0x9e74351e3a97651fU, 0x744c23716ebd9b3e,
                0x822e5077a01baa5cU, 0xc0ed45b9249e88abU, 0x343d4333539df21eU, 0xd229da6f4a514e0f,
            };
            (void)memset(tv_mesStm, 0x0, SHA512_BLOCK_SIZE);

            convStreamToSymbolSha512((uint64_t*)tv_mesStm, (const uint64_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha512(g_sha512Dg64bSym, (const uint64_t*)H0_512, sizeof(H0_512));

            updateSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym), (uint64_t*)tv_mesStm, tv_sz);

            finishSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym));

            printf("SHA-512 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha512Dg64bSym, SHA512_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

            printf("================================================================================\n");
        }
        /* #6) 1000 bytes of zeros */
        {
            printf("--------------------------------------------------------------------------------\n");

            size_t tv_num = 6UL;
            uint8_t tv_mesStm[SHA512_BLOCK_SIZE] = { 0x0u, };
            const size_t tv_sz = 1000UL;
            const uint64_t ref_dgSym[SHA2_DIGEST_NUM] = {
                0xca3dff61bb23477aU, 0xa6087b27508264a6U, 0xf9126ee3a004f53cU, 0xb8db942ed345f2f2,
                0xd229b4b59c859220U, 0xa1cf1913f34248e3U, 0x803bab650e849a3dU, 0x9a709edc09ae4a76,
            };
            size_t tv_chSz, tv_remSz, tv_prcSz;
            (void)memset(tv_mesStm, 0x0, SHA512_BLOCK_SIZE);

            convStreamToSymbolSha512((uint64_t*)tv_mesStm, (const uint64_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha512(g_sha512Dg64bSym, (const uint64_t*)H0_512, sizeof(H0_512));

            tv_remSz = tv_sz;
            for(tv_prcSz = 0UL; tv_prcSz < tv_sz; tv_prcSz += SHA512_BLOCK_SIZE)
            {
                tv_chSz = ((SHA512_BLOCK_SIZE<=tv_remSz)?(SHA512_BLOCK_SIZE):(tv_remSz));

                updateSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym), (uint64_t*)tv_mesStm, tv_chSz);

                tv_remSz -= tv_chSz;
            }

            finishSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym));

            printf("SHA-512 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha512Dg64bSym, SHA512_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

            printf("================================================================================\n");
        }
        /* #7) 1000 bytes of 0x41 ‘A’ */
        {
            printf("--------------------------------------------------------------------------------\n");

            size_t tv_num = 7UL;
            uint8_t tv_mesStm[SHA512_BLOCK_SIZE];
            const size_t tv_sz = 1000UL;
            const uint64_t ref_dgSym[SHA2_DIGEST_NUM] = {
                0x329c52ac62d1fe73U, 0x1151f2b895a00475U, 0x445ef74f50b979c6U, 0xf7bb7cae349328c1,
                0xd4cb4f7261a0ab43U, 0xf936a24b000651d4U, 0xa824fcdd577f211aU, 0xef8f806b16afe8af,
            };
            size_t tv_chSz, tv_remSz, tv_prcSz;
            (void)memset(tv_mesStm, 0x41, SHA512_BLOCK_SIZE);

            convStreamToSymbolSha512((uint64_t*)tv_mesStm, (const uint64_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha512(g_sha512Dg64bSym, (const uint64_t*)H0_512, sizeof(H0_512));

            tv_remSz = tv_sz;
            for(tv_prcSz = 0UL; tv_prcSz < tv_sz; tv_prcSz += SHA512_BLOCK_SIZE)
            {
                tv_chSz = ((SHA512_BLOCK_SIZE<=tv_remSz)?(SHA512_BLOCK_SIZE):(tv_remSz));

                updateSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym), (uint64_t*)tv_mesStm, tv_chSz);

                tv_remSz -= tv_chSz;
            }

            finishSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym));

            if(tv_remSz != 0UL)
            {
                printf("[ERROR!] Chunk Size Error] Remain Size: %lu\n", tv_remSz);
                exit(1);
            }

            printf("SHA-512 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha512Dg64bSym, SHA512_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

            printf("================================================================================\n");
        }
        /* #8) 1005 bytes of 0x55 ‘U’ */
        {
            printf("--------------------------------------------------------------------------------\n");

            size_t tv_num = 8UL;
            uint8_t tv_mesStm[SHA512_BLOCK_SIZE];
            const size_t tv_sz = 1005UL;
            const uint64_t ref_dgSym[SHA2_DIGEST_NUM] = {
                0x59f5e54fe299c6a8U, 0x764c6b199e44924aU, 0x37f59e2b56c3ebadU, 0x939b7289210dc8e4,
                0xc21b9720165b0f4dU, 0x4374c90f1bf4fb4aU, 0x5ace17a116179801U, 0x5052893a48c3d161,
            };
            size_t tv_chSz, tv_remSz, tv_prcSz;
            (void)memset(tv_mesStm, 0x55, SHA512_BLOCK_SIZE);

            convStreamToSymbolSha512((uint64_t*)tv_mesStm, (const uint64_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha512(g_sha512Dg64bSym, (const uint64_t*)H0_512, sizeof(H0_512));

            tv_remSz = tv_sz;
            for(tv_prcSz = 0UL; tv_prcSz < tv_sz; tv_prcSz += SHA512_BLOCK_SIZE)
            {
                tv_chSz = ((SHA512_BLOCK_SIZE<=tv_remSz)?(SHA512_BLOCK_SIZE):(tv_remSz));

                updateSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym), (uint64_t*)tv_mesStm, tv_chSz);

                tv_remSz -= tv_chSz;
            }

            finishSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym));

            if(tv_remSz != 0UL)
            {
                printf("[ERROR!] Chunk Size Error] Remain Size: %lu\n", tv_remSz);
                exit(1);
            }

            printf("SHA-512 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha512Dg64bSym, SHA512_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

            printf("================================================================================\n");
        }
        /* #9) 1000000 bytes of zeros */
        {
            printf("--------------------------------------------------------------------------------\n");

            size_t tv_num = 9UL;
            uint8_t tv_mesStm[SHA512_BLOCK_SIZE];
            const size_t tv_sz = 1000000UL;
            const uint64_t ref_dgSym[SHA2_DIGEST_NUM] = {
                0xce044bc9fd43269dU, 0x5bbc946cbebc3bb7U, 0x11341115cc4abdf2U, 0xedbc3ff2c57ad4b1,
                0x5deb699bda257feaU, 0x5aef9c6e55fcf4cfU, 0x9dc25a8c3ce25f2eU, 0xfe90908379bff7ed,
            };
            size_t tv_chSz, tv_remSz, tv_prcSz;
            (void)memset(tv_mesStm, 0x0, SHA512_BLOCK_SIZE);

            convStreamToSymbolSha512((uint64_t*)tv_mesStm, (const uint64_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha512(g_sha512Dg64bSym, (const uint64_t*)H0_512, sizeof(H0_512));

            tv_remSz = tv_sz;
            for(tv_prcSz = 0UL; tv_prcSz < tv_sz; tv_prcSz += SHA512_BLOCK_SIZE)
            {
                tv_chSz = ((SHA512_BLOCK_SIZE<=tv_remSz)?(SHA512_BLOCK_SIZE):(tv_remSz));

                updateSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym), (uint64_t*)tv_mesStm, tv_chSz);

                tv_remSz -= tv_chSz;
            }

            finishSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym));

            if(tv_remSz != 0UL)
            {
                printf("[ERROR!] Chunk Size Error] Remain Size: %lu\n", tv_remSz);
                exit(1);
            }

            printf("SHA-512 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha512Dg64bSym, SHA512_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

            printf("================================================================================\n");
        }
        /* #10) 0x20000000 (536870912) bytes of 0x5a ‘Z’ */
        {
            printf("--------------------------------------------------------------------------------\n");

            size_t tv_num = 10UL;
            uint8_t tv_mesStm[SHA512_BLOCK_SIZE];
            const size_t tv_sz = 536870912UL;
            const uint64_t ref_dgSym[SHA2_DIGEST_NUM] = {
                0xda172279f3ebbda9U, 0x5f6b6e1e5f0ebec6U, 0x82c25d3d93561a16U, 0x24c2fa9009d64c7e,
                0x9923f3b46bcaf11dU, 0x39a531f43297992bU, 0xa4155c7e827bd0f1U, 0xe194ae7ed6de4cac,
            };
            size_t tv_chSz, tv_remSz, tv_prcSz;
            (void)memset(tv_mesStm, 0x5a, SHA512_BLOCK_SIZE);

            convStreamToSymbolSha512((uint64_t*)tv_mesStm, (const uint64_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha512(g_sha512Dg64bSym, (const uint64_t*)H0_512, sizeof(H0_512));

            tv_remSz = tv_sz;
            for(tv_prcSz = 0UL; tv_prcSz < tv_sz; tv_prcSz += SHA512_BLOCK_SIZE)
            {
                tv_chSz = ((SHA512_BLOCK_SIZE<=tv_remSz)?(SHA512_BLOCK_SIZE):(tv_remSz));

                updateSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym), (uint64_t*)tv_mesStm, tv_chSz);

                tv_remSz -= tv_chSz;
            }

            finishSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym));

            if(tv_remSz != 0UL)
            {
                printf("[ERROR!] Chunk Size Error] Remain Size: %lu\n", tv_remSz);
                exit(1);
            }

            printf("SHA-512 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha512Dg64bSym, SHA512_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

            printf("================================================================================\n");
        }
        /* #11) 0x41000000 (1090519040) bytes of zeros */
        {
            printf("--------------------------------------------------------------------------------\n");

            size_t tv_num = 11UL;
            uint8_t tv_mesStm[SHA512_BLOCK_SIZE];
            const size_t tv_sz = 1090519040UL;
            const uint64_t ref_dgSym[SHA2_DIGEST_NUM] = {
                0x14b1be901cb43549U, 0xb4d831e61e5f9df1U, 0xc791c85b50e85f9dU, 0x6bc64135804ad43c,
                0xe8402750edbe4e5cU, 0x0fc170b99cf78b9fU, 0x4ecb9c7e02a15791U, 0x1d1bd1832d76784f,
            };
            size_t tv_chSz, tv_remSz, tv_prcSz;
            (void)memset(tv_mesStm, 0x0, SHA512_BLOCK_SIZE);

            convStreamToSymbolSha512((uint64_t*)tv_mesStm, (const uint64_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha512(g_sha512Dg64bSym, (const uint64_t*)H0_512, sizeof(H0_512));

            tv_remSz = tv_sz;
            for(tv_prcSz = 0UL; tv_prcSz < tv_sz; tv_prcSz += SHA512_BLOCK_SIZE)
            {
                tv_chSz = ((SHA512_BLOCK_SIZE<=tv_remSz)?(SHA512_BLOCK_SIZE):(tv_remSz));

                updateSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym), (uint64_t*)tv_mesStm, tv_chSz);

                tv_remSz -= tv_chSz;
            }

            finishSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym));

            if(tv_remSz != 0UL)
            {
                printf("[ERROR!] Chunk Size Error] Remain Size: %lu\n", tv_remSz);
                exit(1);
            }

            printf("SHA-512 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha512Dg64bSym, SHA512_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

            printf("================================================================================\n");
        }
        /* #12) 0x6000003e (1610612798) bytes of 0x42 ‘B’ */
        {
            printf("--------------------------------------------------------------------------------\n");

            size_t tv_num = 12UL;
            uint8_t tv_mesStm[SHA512_BLOCK_SIZE];
            const size_t tv_sz = 1610612798UL;
            const uint64_t ref_dgSym[SHA2_DIGEST_NUM] = {
                0xfd05e13eb771f051U, 0x90bd97d62647157eU, 0xa8f1f6949a52bb6dU, 0xaaedbad5f578ec59,
                0xb1b8d6c4a7ecb2feU, 0xca6892b4dc138771U, 0x670a0f3bd577eea3U, 0x26aed40ab7dd58b1,
            };
            size_t tv_chSz, tv_remSz, tv_prcSz;
            (void)memset(tv_mesStm, 0x42, SHA512_BLOCK_SIZE);

            convStreamToSymbolSha512((uint64_t*)tv_mesStm, (const uint64_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha512(g_sha512Dg64bSym, (const uint64_t*)H0_512, sizeof(H0_512));

            tv_remSz = tv_sz;
            for(tv_prcSz = 0UL; tv_prcSz < tv_sz; tv_prcSz += SHA512_BLOCK_SIZE)
            {
                tv_chSz = ((SHA512_BLOCK_SIZE<=tv_remSz)?(SHA512_BLOCK_SIZE):(tv_remSz));

                updateSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym), (uint64_t*)tv_mesStm, tv_chSz);

                tv_remSz -= tv_chSz;
            }

            finishSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym));

            if(tv_remSz != 0UL)
            {
                printf("[ERROR!] Chunk Size Error] Remain Size: %lu\n", tv_remSz);
                exit(1);
            }

            printf("SHA-512 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha512Dg64bSym, SHA512_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

            printf("================================================================================\n");
        }
    }
}

void test_sha2(void)
{
    const uint64_t ref_endian_64b = 0x0123456789abcdefUL;
    const uint8_t ref_mes_8b_stream_all_0_pad[SHA256_BLOCK_SIZE] = { 0x80u, 0x0, };

    /* uint64_t */
    {
        printf("--------------------------------------------------------------------------------\n");

        printf("(64b)0x%016lx\n", ref_endian_64b);
        printf("(mem)0x");
        for(size_t i = 0UL; i < sizeof(uint64_t); i++)
        {
            printf("%02x", ((uint8_t*)(&ref_endian_64b))[i]);
        }
        printf("\n");

        printf("================================================================================\n");
    }

    test_sha2_environments();

    test_CAVP();
    test_FIPS_180_2_imVal_sha256();
    test_FIPS_180_2_example_SHA2_Additional();
}

#undef g_sha256Dg32bSym
#undef g_sha256Dg_8bStm
#undef g_sha512Dg64bSym
#undef g_sha512Dg_8bStm

#endif /* TEST_SHA */

#ifdef TEST_HMAC
#include "hash/sha2.h"
#include "mac/hmac.h"

typedef union {
    uint32_t mac256[SHA2_DIGEST_NUM];
    uint64_t mac512[SHA2_DIGEST_NUM];
} hmacSym_t;
typedef union {
    uint8_t mac256[SHA256_DIGEST_SIZE];
    uint8_t mac512[SHA512_DIGEST_SIZE];
} hmacStm_t;

hmacSym_t g_hashSym;
hmacStm_t g_hashStm;

#define g_hmac256Sym    g_hashSym.mac256
#define g_hmac256Stm    g_hashStm.mac256
#define g_hmac512Sym    g_hashSym.mac512
#define g_hmac512Stm    g_hashStm.mac512

const char ref_test_FIPS_198_hamc256_imVal[] = "[REFERENCES]\nCryptographic Standards and Guidelines\n[Link] https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values\nFIPS 198 - The Keyed-Hash Message Authentication Code (HMAC)\n[Link] https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_SHA256.pdf";
void test_FIPS_198_hamc256_imVal(void)
{
    printf("%s\n", ref_test_FIPS_198_hamc256_imVal);

    /*
     * Key length = 64
     * Tag length = 32
     * Input Date: "Sample message for keylen=blocklen"
     */
    {
        printf("--------------------------------------------------------------------------------\n");
        const size_t testNum = 1UL;
        const uint32_t keySym[] = {
            0x00010203U,0x04050607U,0x08090A0BU,0x0C0D0E0FU,
            0x10111213U,0x14151617U,0x18191A1BU,0x1C1D1E1FU,
            0x20212223U,0x24252627U,0x28292A2BU,0x2C2D2E2FU,
            0x30313233U,0x34353637U,0x38393A3BU,0x3C3D3E3FU,
        };
        const size_t keySize = sizeof(keySym);

        uint8_t textStm[SHA256_BLOCK_SIZE] = "Sample message for keylen=blocklen";
        const size_t textLen = strlen(textStm);

        const uint32_t ref_mac[] = {
            0x8BB9A1DBU,0x9806F20DU,0xF7F77B82U,0x138C7914U,
            0xD174D59EU,0x13DC4D01U,0x69C9057BU,0x133E1D62U,
        };

        printf("Key length = %lu\n", keySize);
        printf("Key Value: 0x");
        for(size_t i = 0UL; i < keySize / sizeof(uint32_t); i++)
        {
            printf("%08x", keySym[i]);
        }
        printf("\n");

        printf("Text length = %lu\n", textLen);
        printf("Text: %s\n", textStm);
        printf("Text Val: 0x");
        for(size_t i = 0UL; i < textLen; i++)
        {
            printf("%02x", textStm[i]);
        }
        printf("\n");

        convStreamToSymbolSha256((uint32_t*)textStm, (const uint32_t*)textStm, sizeof(textStm));

        startHmac256(keySym, keySize, SHA256_DIGEST_SIZE);
        updateHmac256(SHA256_DIGEST_SIZE, (const uint32_t*)textStm, textLen);
        finishHmac256(g_hmac256Sym, SHA256_DIGEST_SIZE);

        printf("[HMAC256]\n");
        printf("(32bit) 0x ");
        for(size_t si = 0UL; si < EDCSIZE2W32LEN(sizeof(g_hmac256Sym)); si++)
        {
            printf("%08x", g_hmac256Sym[si]);
        }
        printf("\n");

        printf("[%2lu]HMAC-256: ", testNum);
        printf("%s\n",((memcmp(ref_mac, g_hmac256Sym, SHA256_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

        printf("--------------------------------------------------------------------------------\n");
    }
    /*
     * Key length = 32
     * Tag length = 32
     * Input Date: "Sample message for keylen<blocklen"
     */
    {
        printf("--------------------------------------------------------------------------------\n");
        const size_t testNum = 2UL;
        const uint32_t keySym[] = {
            0x00010203U,0x04050607U,0x08090A0BU,0x0C0D0E0FU,
            0x10111213U,0x14151617U,0x18191A1BU,0x1C1D1E1FU,
        };
        const size_t keySize = sizeof(keySym);

        uint8_t textStm[SHA256_BLOCK_SIZE] = "Sample message for keylen<blocklen";
        const size_t textLen = strlen(textStm);

        const uint32_t ref_mac[] = {
            0xA28CF431U, 0x30EE696AU, 0x98F14A37U, 0x678B56BCU, 
            0xFCBDD9E5U, 0xCF69717FU, 0xECF5480FU, 0x0EBDF790U, 
        };

        printf("Key length = %lu\n", keySize);
        printf("Key Value: 0x");
        for(size_t i = 0UL; i < keySize / sizeof(uint32_t); i++)
        {
            printf("%08x", keySym[i]);
        }
        printf("\n");

        printf("Text length = %lu\n", textLen);
        printf("Text: %s\n", textStm);
        printf("Text Val: 0x");
        for(size_t i = 0UL; i < textLen; i++)
        {
            printf("%02x", textStm[i]);
        }
        printf("\n");

        convStreamToSymbolSha256((uint32_t*)textStm, (const uint32_t*)textStm, sizeof(textStm));

        startHmac256(keySym, keySize, SHA256_DIGEST_SIZE);
        updateHmac256(SHA256_DIGEST_SIZE, (const uint32_t*)textStm, textLen);
        finishHmac256(g_hmac256Sym, SHA256_DIGEST_SIZE);

        printf("[HMAC256]\n");
        printf("(32bit) 0x ");
        for(size_t si = 0UL; si < EDCSIZE2W32LEN(sizeof(g_hmac256Sym)); si++)
        {
            printf("%08x", g_hmac256Sym[si]);
        }
        printf("\n");

        printf("[%2lu]HMAC-256: ", testNum);
        printf("%s\n",((memcmp(ref_mac, g_hmac256Sym, SHA256_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

        printf("--------------------------------------------------------------------------------\n");
    }
    /*
     * Key length = 100
     * Tag length = 32
     * Input Date: "Sample message for keylen=blocklen"
     */
    {
        printf("--------------------------------------------------------------------------------\n");
        const size_t testNum = 3UL;
        const uint32_t keySym[] = {
            0x00010203U, 0x04050607U, 0x08090A0BU, 0x0C0D0E0FU, 
            0x10111213U, 0x14151617U, 0x18191A1BU, 0x1C1D1E1FU, 
            0x20212223U, 0x24252627U, 0x28292A2BU, 0x2C2D2E2FU, 
            0x30313233U, 0x34353637U, 0x38393A3BU, 0x3C3D3E3FU, 
            0x40414243U, 0x44454647U, 0x48494A4BU, 0x4C4D4E4FU, 
            0x50515253U, 0x54555657U, 0x58595A5BU, 0x5C5D5E5FU, 
            0x60616263U, 
        };
        const size_t keySize = sizeof(keySym);

        uint8_t textStm[SHA256_BLOCK_SIZE] = "Sample message for keylen=blocklen";
        const size_t textLen = strlen(textStm);

        const uint32_t ref_mac[] = {
            0xBDCCB6C7U, 0x2DDEADB5U, 0x00AE7683U, 0x86CB38CCU, 
            0x41C63DBBU, 0x0878DDB9U, 0xC7A38A43U, 0x1B78378DU, 
        };

        printf("Key length = %lu\n", keySize);
        printf("Key Value: 0x");
        for(size_t i = 0UL; i < keySize / sizeof(uint32_t); i++)
        {
            printf("%08x", keySym[i]);
        }
        printf("\n");

        printf("Text length = %lu\n", textLen);
        printf("Text: %s\n", textStm);
        printf("Text Val: 0x");
        for(size_t i = 0UL; i < textLen; i++)
        {
            printf("%02x", textStm[i]);
        }
        printf("\n");

        convStreamToSymbolSha256((uint32_t*)textStm, (const uint32_t*)textStm, sizeof(textStm));

        startHmac256(keySym, keySize, SHA256_DIGEST_SIZE);
        updateHmac256(SHA256_DIGEST_SIZE, (const uint32_t*)textStm, textLen);
        finishHmac256(g_hmac256Sym, SHA256_DIGEST_SIZE);

        printf("[HMAC256]\n");
        printf("(32bit) 0x ");
        for(size_t si = 0UL; si < EDCSIZE2W32LEN(sizeof(g_hmac256Sym)); si++)
        {
            printf("%08x", g_hmac256Sym[si]);
        }
        printf("\n");

        printf("[%2lu]HMAC-256: ", testNum);
        printf("%s\n",((memcmp(ref_mac, g_hmac256Sym, SHA256_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

        printf("--------------------------------------------------------------------------------\n");
    }
    /*
     * Key length = 49
     * Tag length = 16
     * Input Date: "Sample message for keylen<blocklen, with truncated tag"
     */
    {
        printf("--------------------------------------------------------------------------------\n");
        const size_t testNum = 4UL;
        const uint32_t keySym[] = {
            0x00010203U, 0x04050607U, 0x08090A0BU, 0x0C0D0E0FU, 
            0x10111213U, 0x14151617U, 0x18191A1BU, 0x1C1D1E1FU, 
            0x20212223U, 0x24252627U, 0x28292A2BU, 0x2C2D2E2FU, 
            0x30000000U, 
        };
        const size_t keySize = 49U;

        uint8_t textStm[SHA256_BLOCK_SIZE] = "Sample message for keylen<blocklen, with truncated tag";
        const size_t textLen = strlen(textStm);

        const uint32_t ref_mac[] = {
            0x27A8B157U, 0x839EFEACU, 0x98DF070BU, 0x331D5936U, 
            0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 
        };
		const size_t ref_mac_truncated_size = 16UL;

        printf("Key length = %lu\n", keySize);
        printf("Key Value: 0x");
        for(size_t i = 0UL; i < keySize / sizeof(uint32_t); i++)
        {
            printf("%08x", keySym[i]);
        }
        printf("\n");

        printf("Text length = %lu\n", textLen);
        printf("Text: %s\n", textStm);
        printf("Text Val: 0x");
        for(size_t i = 0UL; i < textLen; i++)
        {
            printf("%02x", textStm[i]);
        }
        printf("\n");

        convStreamToSymbolSha256((uint32_t*)textStm, (const uint32_t*)textStm, sizeof(textStm));

        startHmac256(keySym, keySize, SHA256_DIGEST_SIZE);
        updateHmac256(SHA256_DIGEST_SIZE, (const uint32_t*)textStm, textLen);
        finishHmac256(g_hmac256Sym, SHA256_DIGEST_SIZE);

        printf("[HMAC256]\n");
        printf("(32bit) 0x ");
        for(size_t si = 0UL; si < EDCSIZE2W32LEN(ref_mac_truncated_size); si++)
        {
            printf("%08x", g_hmac256Sym[si]);
        }
        printf("\n");

        printf("[%2lu]HMAC-256(truncated to %lu Bytes): ", testNum, ref_mac_truncated_size);
        printf("%s\n",((memcmp(ref_mac, g_hmac256Sym, ref_mac_truncated_size) == 0)?MES_PASS:MES_FAIL));

        printf("--------------------------------------------------------------------------------\n");
    }
}

const char ref_test_FIPS_198_hamc512_imVal[] = "[REFERENCES]\nCryptographic Standards and Guidelines\n[Link] https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values\nFIPS 198 - The Keyed-Hash Message Authentication Code (HMAC)\n[Link] https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/hmac_sha512.pdf";
void test_FIPS_198_hamc512_imVal(void)
{
    printf("%s\n", ref_test_FIPS_198_hamc512_imVal);

    /*
     * Key length = 128
     * Tag length = 64
     * Input Date: "Sample message for keylen=blocklen"
     */
    {
        printf("--------------------------------------------------------------------------------\n");
        const size_t testNum = 1UL;
        const uint64_t keySym[] = {
            0x0001020304050607U, 0x08090A0B0C0D0E0FU, 0x1011121314151617U, 0x18191A1B1C1D1E1FU, 
            0x2021222324252627U, 0x28292A2B2C2D2E2FU, 0x3031323334353637U, 0x38393A3B3C3D3E3FU, 
            0x4041424344454647U, 0x48494A4B4C4D4E4FU, 0x5051525354555657U, 0x58595A5B5C5D5E5FU, 
            0x6061626364656667U, 0x68696A6B6C6D6E6FU, 0x7071727374757677U, 0x78797A7B7C7D7E7FU, 
        };
        const size_t keySize = sizeof(keySym);

        uint8_t textStm[SHA512_BLOCK_SIZE] = "Sample message for keylen=blocklen";
        const size_t textLen = strlen(textStm);

        const uint64_t ref_mac[] = {
            0xFC25E240658CA785U, 0xB7A811A8D3F7B4CAU, 0x48CFA26A8A366BF2U, 0xCD1F836B05FCB024U, 
            0xBD36853081811D6CU, 0xEA4216EBAD79DA1CU, 0xFCB95EA4586B8A0CU, 0xE356596A55FB1347U, 
        };

        printf("Key length = %lu\n", keySize);
        printf("Key Value: 0x");
        for(size_t i = 0UL; i < keySize / sizeof(uint64_t); i++)
        {
            printf("%016lx", keySym[i]);
        }
        printf("\n");

        printf("Text length = %lu\n", textLen);
        printf("Text: %s\n", textStm);
        printf("Text Val: 0x");
        for(size_t i = 0UL; i < textLen; i++)
        {
            printf("%02x", textStm[i]);
        }
        printf("\n");

        convStreamToSymbolSha512((uint64_t*)textStm, (const uint64_t*)textStm, sizeof(textStm));

        startHmac512(keySym, keySize, SHA512_DIGEST_SIZE);
        updateHmac512(SHA512_DIGEST_SIZE, (const uint64_t*)textStm, textLen);
        finishHmac512(g_hmac512Sym, SHA512_DIGEST_SIZE);

        printf("[HMAC512]\n");
        printf("(64bit) 0x ");
        for(size_t si = 0UL; si < EDCSIZE2W32LEN(sizeof(g_hmac512Sym)); si++)
        {
            printf("%016lx", g_hmac512Sym[si]);
        }
        printf("\n");

        printf("[%2lu]HMAC-512: ", testNum);
        printf("%s\n",((memcmp(ref_mac, g_hmac512Sym, SHA512_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

        printf("--------------------------------------------------------------------------------\n");
    }
    /*
     * Key length = 64
     * Tag length = 64
     * Input Date: "Sample message for keylen<blocklen"
     */
    {
        printf("--------------------------------------------------------------------------------\n");
        const size_t testNum = 2UL;
        const uint64_t keySym[] = {
            0x0001020304050607U, 0x08090A0B0C0D0E0FU, 0x1011121314151617U, 0x18191A1B1C1D1E1FU, 
            0x2021222324252627U, 0x28292A2B2C2D2E2FU, 0x3031323334353637U, 0x38393A3B3C3D3E3FU, 
        };
        const size_t keySize = sizeof(keySym);

        uint8_t textStm[SHA512_BLOCK_SIZE] = "Sample message for keylen<blocklen";
        const size_t textLen = strlen(textStm);

        const uint64_t ref_mac[] = {
            0xFD44C18BDA0BB0A6U, 0xCE0E82B031BF2818U, 0xF6539BD56EC00BDCU, 0x10A8A2D730B3634DU, 
            0xE2545D639B0F2CF7U, 0x10D0692C72A1896FU, 0x1F211C2B922D1A96U, 0xC392E07E7EA9FEDCU, 
        };

        printf("Key length = %lu\n", keySize);
        printf("Key Value: 0x");
        for(size_t i = 0UL; i < keySize / sizeof(uint64_t); i++)
        {
            printf("%016lx", keySym[i]);
        }
        printf("\n");

        printf("Text length = %lu\n", textLen);
        printf("Text: %s\n", textStm);
        printf("Text Val: 0x");
        for(size_t i = 0UL; i < textLen; i++)
        {
            printf("%02x", textStm[i]);
        }
        printf("\n");

        convStreamToSymbolSha512((uint64_t*)textStm, (const uint64_t*)textStm, sizeof(textStm));

        startHmac512(keySym, keySize, SHA512_DIGEST_SIZE);
        updateHmac512(SHA512_DIGEST_SIZE, (const uint64_t*)textStm, textLen);
        finishHmac512(g_hmac512Sym, SHA512_DIGEST_SIZE);

        printf("[HMAC512]\n");
        printf("(64bit) 0x ");
        for(size_t si = 0UL; si < EDCSIZE2W32LEN(sizeof(g_hmac512Sym)); si++)
        {
            printf("%016lx", g_hmac512Sym[si]);
        }
        printf("\n");

        printf("[%2lu]HMAC-512: ", testNum);
        printf("%s\n",((memcmp(ref_mac, g_hmac512Sym, SHA512_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

        printf("--------------------------------------------------------------------------------\n");
    }
    /*
     * Key length = 200
     * Tag length = 64
     * Input Date: "Sample message for keylen=blocklen"
     */
    {
        printf("--------------------------------------------------------------------------------\n");
        const size_t testNum = 3UL;
        const uint64_t keySym[] = {
            0x0001020304050607U, 0x08090A0B0C0D0E0FU, 0x1011121314151617U, 0x18191A1B1C1D1E1FU, 
            0x2021222324252627U, 0x28292A2B2C2D2E2FU, 0x3031323334353637U, 0x38393A3B3C3D3E3FU, 
            0x4041424344454647U, 0x48494A4B4C4D4E4FU, 0x5051525354555657U, 0x58595A5B5C5D5E5FU, 
            0x6061626364656667U, 0x68696A6B6C6D6E6FU, 0x7071727374757677U, 0x78797A7B7C7D7E7FU, 
            0x8081828384858687U, 0x88898A8B8C8D8E8FU, 0x9091929394959697U, 0x98999A9B9C9D9E9FU, 
            0xA0A1A2A3A4A5A6A7U, 0xA8A9AAABACADAEAFU, 0xB0B1B2B3B4B5B6B7U, 0xB8B9BABBBCBDBEBFU, 
            0xC0C1C2C3C4C5C6C7U, 
        };
        const size_t keySize = sizeof(keySym);

        uint8_t textStm[SHA512_BLOCK_SIZE] = "Sample message for keylen=blocklen";
        const size_t textLen = strlen(textStm);

        const uint64_t ref_mac[] = {
            0xD93EC8D2DE1AD2A9U, 0x957CB9B83F14E76AU, 0xD6B5E0CCE285079AU, 0x127D3B14BCCB7AA7U, 
            0x286D4AC0D4CE6421U, 0x5F2BC9E6870B33D9U, 0x7438BE4AAA20CDA5U, 0xC5A912B48B8E27F3U, 
        };

        printf("Key length = %lu\n", keySize);
        printf("Key Value: 0x");
        for(size_t i = 0UL; i < keySize / sizeof(uint64_t); i++)
        {
            printf("%016lx", keySym[i]);
        }
        printf("\n");

        printf("Text length = %lu\n", textLen);
        printf("Text: %s\n", textStm);
        printf("Text Val: 0x");
        for(size_t i = 0UL; i < textLen; i++)
        {
            printf("%02x", textStm[i]);
        }
        printf("\n");

        convStreamToSymbolSha512((uint64_t*)textStm, (const uint64_t*)textStm, sizeof(textStm));

        startHmac512(keySym, keySize, SHA512_DIGEST_SIZE);
        updateHmac512(SHA512_DIGEST_SIZE, (const uint64_t*)textStm, textLen);
        finishHmac512(g_hmac512Sym, SHA512_DIGEST_SIZE);

        printf("[HMAC512]\n");
        printf("(64bit) 0x ");
        for(size_t si = 0UL; si < EDCSIZE2W32LEN(sizeof(g_hmac512Sym)); si++)
        {
            printf("%016lx", g_hmac512Sym[si]);
        }
        printf("\n");

        printf("[%2lu]HMAC-512: ", testNum);
        printf("%s\n",((memcmp(ref_mac, g_hmac512Sym, SHA512_DIGEST_SIZE) == 0)?MES_PASS:MES_FAIL));

        printf("--------------------------------------------------------------------------------\n");
    }
    /*
     * Key length = 49
     * Tag length = 32
     * Input Date: "Sample message for keylen<blocklen, with truncated tag"
     */
    {
        printf("--------------------------------------------------------------------------------\n");
        const size_t testNum = 4UL;
        const uint64_t keySym[] = {
            0x0001020304050607U, 0x08090A0B0C0D0E0FU, 0x1011121314151617U, 0x18191A1B1C1D1E1FU, 
            0x2021222324252627U, 0x28292A2B2C2D2E2FU, 0x3000000000000000U, 0x0000000000000000U, 
            0x0000000000000000U, 0x0000000000000000U, 0x0000000000000000U, 0x0000000000000000U, 
            0x0000000000000000U, 0x0000000000000000U, 0x0000000000000000U, 0x0000000000000000U, 
        };
        const size_t keySize = 49U;

        uint8_t textStm[SHA512_BLOCK_SIZE] = "Sample message for keylen<blocklen, with truncated tag";
        const size_t textLen = strlen(textStm);

        const uint64_t ref_mac[] = {
            0x00F3E9A77BB0F06DU, 0xE15F160603E42B50U, 0x28758808596664C0U, 0x3E1AB8FB2B076778U, 
        };
		const size_t ref_mac_truncated_size = 32UL;

        printf("Key length = %lu\n", keySize);
        printf("Key Value: 0x");
        for(size_t i = 0UL; i < keySize / sizeof(uint64_t); i++)
        {
            printf("%016lx", keySym[i]);
        }
        printf("\n");

        printf("Text length = %lu\n", textLen);
        printf("Text: %s\n", textStm);
        printf("Text Val: 0x");
        for(size_t i = 0UL; i < textLen; i++)
        {
            printf("%02x", textStm[i]);
        }
        printf("\n");

        convStreamToSymbolSha512((uint64_t*)textStm, (const uint64_t*)textStm, sizeof(textStm));

        startHmac512(keySym, keySize, SHA512_DIGEST_SIZE);
        updateHmac512(SHA512_DIGEST_SIZE, (const uint64_t*)textStm, textLen);
        finishHmac512(g_hmac512Sym, SHA512_DIGEST_SIZE);

        printf("[HMAC512]\n");
        printf("(64bit) 0x ");
        for(size_t si = 0UL; si < EDCSIZE2W32LEN(ref_mac_truncated_size); si++)
        {
            printf("%016lx", g_hmac512Sym[si]);
        }
        printf("\n");

        printf("[%2lu]HMAC-512(truncated to %lu Bytes): ", testNum, ref_mac_truncated_size);
        printf("%s\n",((memcmp(ref_mac, g_hmac512Sym, ref_mac_truncated_size) == 0)?MES_PASS:MES_FAIL));

        printf("--------------------------------------------------------------------------------\n");
    }
}

#undef g_hmac256Sym
#undef g_hmac256Stm
#undef g_hmac512Sym
#undef g_hmac512Stm

#endif /* TEST_HMAC */

#ifdef TEST_CMAC
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "mac/cmac.h"

const char ref_test_RFC4493_aes128_cmac[] = "[REFERENCES]\nRFC4493, The AES-CMAC Algorithm, IETF, 2006. June\n[Link] https://datatracker.ietf.org/doc/html/rfc4493\n[Chapter] 4. Test Vectors\n[Link] https://datatracker.ietf.org/doc/html/rfc4493#section-4";
void test_RFC4493_aes128_cmac(void)
{
    printf("%s\n", ref_test_RFC4493_aes128_cmac);
    {
        /* Commonly used */
        /* Subkey Generation */
        const uint8_t tv_key[] = {
            0x2bU, 0x7eU, 0x15U, 0x16U, 0x28U, 0xaeU, 0xd2U, 0xa6U, 0xabU, 0xf7U, 0x15U, 0x88U, 0x09U, 0xcfU, 0x4fU, 0x3cU, 
        };
        const size_t tv_kSize = sizeof(tv_key);

        /* Example 1: len = 0 */
        {
            const size_t testNum = 1UL;
            const uint8_t tv_mes[] = "";
            const size_t tv_mSize = strlen(tv_mes);
            const uint8_t ref_tag[CMAC_TAG128b_SIZE] = {
                0xbbU, 0x1dU, 0x69U, 0x29U, 0xe9U, 0x59U, 0x37U, 0x28U, 0x7fU, 0xa3U, 0x7dU, 0x12U, 0x9bU, 0x75U, 0x67U, 0x46U, 
            };
            uint8_t tv_tag[CMAC_TAG128b_SIZE];
            size_t rSize, pSize;

            startCmac(tv_key, tv_kSize);

            for(pSize = 0UL, rSize = tv_mSize; CMAC_TAG128b_SIZE < rSize; pSize += CMAC_TAG128b_SIZE, rSize -= CMAC_TAG128b_SIZE)
            {
                updateCmac(&tv_mes[pSize], CMAC_TAG128b_SIZE);
            }
            finishCmac(tv_tag, &tv_mes[pSize], rSize);


            printf("AES128-CMAC#%2ld: %s\n", testNum, ((memcmp(tv_tag, ref_tag, CMAC_TAG128b_SIZE) == 0)?MES_PASS:MES_FAIL));
        }
        /* Example 2: len = 16 */
        {
            const size_t testNum = 2UL;
            const uint8_t tv_mes[] = {
                0x6bU, 0xc1U, 0xbeU, 0xe2U, 0x2eU, 0x40U, 0x9fU, 0x96U, 0xe9U, 0x3dU, 0x7eU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2aU,
            };
            const size_t tv_mSize = sizeof(tv_mes);
            const uint8_t ref_tag[CMAC_TAG128b_SIZE] = {
                0x07U, 0x0aU, 0x16U, 0xb4U, 0x6bU, 0x4dU, 0x41U, 0x44U, 0xf7U, 0x9bU, 0xddU, 0x9dU, 0xd0U, 0x4aU, 0x28U, 0x7cU,
            };
            uint8_t tv_tag[CMAC_TAG128b_SIZE];
            size_t rSize, pSize;

            startCmac(tv_key, tv_kSize);

            for(pSize = 0UL, rSize = tv_mSize; CMAC_TAG128b_SIZE < rSize; pSize += CMAC_TAG128b_SIZE, rSize -= CMAC_TAG128b_SIZE)
            {
                updateCmac(&tv_mes[pSize], CMAC_TAG128b_SIZE);
            }
            finishCmac(tv_tag, &tv_mes[pSize], rSize);


            printf("AES128-CMAC#%2ld: %s\n", testNum, ((memcmp(tv_tag, ref_tag, CMAC_TAG128b_SIZE) == 0)?MES_PASS:MES_FAIL));
        }
        /* Example 3: len = 40 */
        {
            const size_t testNum = 3UL;
            const uint8_t tv_mes[] = {
                0x6bU, 0xc1U, 0xbeU, 0xe2U, 0x2eU, 0x40U, 0x9fU, 0x96U, 0xe9U, 0x3dU, 0x7eU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2aU, 
                0xaeU, 0x2dU, 0x8aU, 0x57U, 0x1eU, 0x03U, 0xacU, 0x9cU, 0x9eU, 0xb7U, 0x6fU, 0xacU, 0x45U, 0xafU, 0x8eU, 0x51U, 
                0x30U, 0xc8U, 0x1cU, 0x46U, 0xa3U, 0x5cU, 0xe4U, 0x11U, 
            };
            const size_t tv_mSize = sizeof(tv_mes);
            const uint8_t ref_tag[CMAC_TAG128b_SIZE] = {
                0xdfU, 0xa6U, 0x67U, 0x47U, 0xdeU, 0x9aU, 0xe6U, 0x30U, 0x30U, 0xcaU, 0x32U, 0x61U, 0x14U, 0x97U, 0xc8U, 0x27U, 
            };
            uint8_t tv_tag[CMAC_TAG128b_SIZE];
            size_t rSize, pSize;

            startCmac(tv_key, tv_kSize);

            for(pSize = 0UL, rSize = tv_mSize; CMAC_TAG128b_SIZE < rSize; pSize += CMAC_TAG128b_SIZE, rSize -= CMAC_TAG128b_SIZE)
            {
                updateCmac(&tv_mes[pSize], CMAC_TAG128b_SIZE);
            }
            finishCmac(tv_tag, &tv_mes[pSize], rSize);

            printf("AES128-CMAC#%2ld: %s\n", testNum, ((memcmp(tv_tag, ref_tag, CMAC_TAG128b_SIZE) == 0)?MES_PASS:MES_FAIL));
        }
        /* Example 4: len = 64 */
        {
            const size_t testNum = 4UL;
            const uint8_t tv_mes[] = {
                0x6bU, 0xc1U, 0xbeU, 0xe2U, 0x2eU, 0x40U, 0x9fU, 0x96U, 0xe9U, 0x3dU, 0x7eU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2aU, 
                0xaeU, 0x2dU, 0x8aU, 0x57U, 0x1eU, 0x03U, 0xacU, 0x9cU, 0x9eU, 0xb7U, 0x6fU, 0xacU, 0x45U, 0xafU, 0x8eU, 0x51U, 
                0x30U, 0xc8U, 0x1cU, 0x46U, 0xa3U, 0x5cU, 0xe4U, 0x11U, 0xe5U, 0xfbU, 0xc1U, 0x19U, 0x1aU, 0x0aU, 0x52U, 0xefU, 
                0xf6U, 0x9fU, 0x24U, 0x45U, 0xdfU, 0x4fU, 0x9bU, 0x17U, 0xadU, 0x2bU, 0x41U, 0x7bU, 0xe6U, 0x6cU, 0x37U, 0x10U, 
            };
            const size_t tv_mSize = sizeof(tv_mes);
            const uint8_t ref_tag[CMAC_TAG128b_SIZE] = {
                0x51U, 0xf0U, 0xbeU, 0xbfU, 0x7eU, 0x3bU, 0x9dU, 0x92U, 0xfcU, 0x49U, 0x74U, 0x17U, 0x79U, 0x36U, 0x3cU, 0xfeU, 
            };
            uint8_t tv_tag[CMAC_TAG128b_SIZE];
            size_t rSize, pSize;

            startCmac(tv_key, tv_kSize);

            for(pSize = 0UL, rSize = tv_mSize; CMAC_TAG128b_SIZE < rSize; pSize += CMAC_TAG128b_SIZE, rSize -= CMAC_TAG128b_SIZE)
            {
                updateCmac(&tv_mes[pSize], CMAC_TAG128b_SIZE);
            }
            finishCmac(tv_tag, &tv_mes[pSize], rSize);

            printf("AES128-CMAC#%2ld: %s\n", testNum, ((memcmp(tv_tag, ref_tag, CMAC_TAG128b_SIZE) == 0)?MES_PASS:MES_FAIL));
        }
    }
}

const char ref_test_SP800_38B_cmac_aes_imVal[] = "[REFERENCES]\nCryptographic Standards and Guidelines\n[Link] https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values\nSP 800-38B - Recommendation for Block Cipher Modes of Operation: The CMAC Mode for Authentication (CMAC-AES)\n[Link] https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf";
void test_SP800_38B_cmac_aes_imVal(void)
{
    printf("%s\n", ref_test_SP800_38B_cmac_aes_imVal);
    {
        /* CMAC-AES128 */
        {
            /* Commonly used CMAC-AES128 */
            const uint8_t tv_key[] = {
                0x2BU, 0x7EU, 0x15U, 0x16U, 0x28U, 0xAEU, 0xD2U, 0xA6U, 0xABU, 0xF7U, 0x15U, 0x88U, 0x09U, 0xCFU, 0x4FU, 0x3CU,
            };
            const size_t tv_kSize = sizeof(tv_key);

            /* CMAC-AES128, Example #1 */
            {
                const size_t testNum = 1UL;
                const uint8_t tv_mes[] = "";
                const size_t tv_mSize = strlen(tv_mes);
                const uint8_t ref_tag[CMAC_TAG128b_SIZE] = {
                    /* INSERT REFERENCE TAG VALUES */
                    0xBBU, 0x1DU, 0x69U, 0x29U, 0xE9U, 0x59U, 0x37U, 0x28U, 0x7FU, 0xA3U, 0x7DU, 0x12U, 0x9BU, 0x75U, 0x67U, 0x46U,
                };
                uint8_t tv_tag[CMAC_TAG128b_SIZE];
                size_t rSize, pSize;

                startCmac(tv_key, tv_kSize);

                for(pSize = 0UL, rSize = tv_mSize; CMAC_TAG128b_SIZE < rSize; pSize += CMAC_TAG128b_SIZE, rSize -= CMAC_TAG128b_SIZE)
                {
                    updateCmac(&tv_mes[pSize], CMAC_TAG128b_SIZE);
                }
                finishCmac(tv_tag, &tv_mes[pSize], rSize);

                printf("AES128-CMAC#%2ld: %s\n", testNum, ((memcmp(tv_tag, ref_tag, CMAC_TAG128b_SIZE) == 0)?MES_PASS:MES_FAIL));
            }
            /* CMAC-AES128, Example #2 */
            {
                const size_t testNum = 2UL;
                const uint8_t tv_mes[] = {
                    /* INSERT INPUT MESSAGE VALUES */
                    0x6BU, 0xC1U, 0xBEU, 0xE2U, 0x2EU, 0x40U, 0x9FU, 0x96U, 0xE9U, 0x3DU, 0x7EU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2AU,
                };
                const size_t tv_mSize = sizeof(tv_mes);
                const uint8_t ref_tag[CMAC_TAG128b_SIZE] = {
                    /* INSERT REFERENCE TAG VALUES */
                    0x07U, 0x0AU, 0x16U, 0xB4U, 0x6BU, 0x4DU, 0x41U, 0x44U, 0xF7U, 0x9BU, 0xDDU, 0x9DU, 0xD0U, 0x4AU, 0x28U, 0x7CU,
                };
                uint8_t tv_tag[CMAC_TAG128b_SIZE];
                size_t rSize, pSize;

                startCmac(tv_key, tv_kSize);

                for(pSize = 0UL, rSize = tv_mSize; CMAC_TAG128b_SIZE < rSize; pSize += CMAC_TAG128b_SIZE, rSize -= CMAC_TAG128b_SIZE)
                {
                    updateCmac(&tv_mes[pSize], CMAC_TAG128b_SIZE);
                }
                finishCmac(tv_tag, &tv_mes[pSize], rSize);

                printf("AES128-CMAC#%2ld: %s\n", testNum, ((memcmp(tv_tag, ref_tag, CMAC_TAG128b_SIZE) == 0)?MES_PASS:MES_FAIL));
            }
            /* CMAC-AES128, Example #3 */
            {
                const size_t testNum = 3UL;
                const uint8_t tv_mes[] = {
                    /* INSERT INPUT MESSAGE VALUES */
                    0x6BU, 0xC1U, 0xBEU, 0xE2U, 0x2EU, 0x40U, 0x9FU, 0x96U, 0xE9U, 0x3DU, 0x7EU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2AU,
                    0xAEU, 0x2DU, 0x8AU, 0x57U,
                };
                const size_t tv_mSize = sizeof(tv_mes);
                const uint8_t ref_tag[CMAC_TAG128b_SIZE] = {
                    /* INSERT REFERENCE TAG VALUES */
                    0x7DU, 0x85U, 0x44U, 0x9EU, 0xA6U, 0xEAU, 0x19U, 0xC8U, 0x23U, 0xA7U, 0xBFU, 0x78U, 0x83U, 0x7DU, 0xFAU, 0xDEU,
                };
                uint8_t tv_tag[CMAC_TAG128b_SIZE];
                size_t rSize, pSize;

                startCmac(tv_key, tv_kSize);

                for(pSize = 0UL, rSize = tv_mSize; CMAC_TAG128b_SIZE < rSize; pSize += CMAC_TAG128b_SIZE, rSize -= CMAC_TAG128b_SIZE)
                {
                    updateCmac(&tv_mes[pSize], CMAC_TAG128b_SIZE);
                }
                finishCmac(tv_tag, &tv_mes[pSize], rSize);

                printf("AES128-CMAC#%2ld: %s\n", testNum, ((memcmp(tv_tag, ref_tag, CMAC_TAG128b_SIZE) == 0)?MES_PASS:MES_FAIL));
            }
            /* CMAC-AES128, Example #4 */
            {
                const size_t testNum = 4UL;
                const uint8_t tv_mes[] = {
                    /* INSERT INPUT MESSAGE VALUES */
                    0x6BU, 0xC1U, 0xBEU, 0xE2U, 0x2EU, 0x40U, 0x9FU, 0x96U, 0xE9U, 0x3DU, 0x7EU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2AU,
                    0xAEU, 0x2DU, 0x8AU, 0x57U, 0x1EU, 0x03U, 0xACU, 0x9CU, 0x9EU, 0xB7U, 0x6FU, 0xACU, 0x45U, 0xAFU, 0x8EU, 0x51U,
                    0x30U, 0xC8U, 0x1CU, 0x46U, 0xA3U, 0x5CU, 0xE4U, 0x11U, 0xE5U, 0xFBU, 0xC1U, 0x19U, 0x1AU, 0x0AU, 0x52U, 0xEFU,
                    0xF6U, 0x9FU, 0x24U, 0x45U, 0xDFU, 0x4FU, 0x9BU, 0x17U, 0xADU, 0x2BU, 0x41U, 0x7BU, 0xE6U, 0x6CU, 0x37U, 0x10U,
                };
                const size_t tv_mSize = sizeof(tv_mes);
                const uint8_t ref_tag[CMAC_TAG128b_SIZE] = {
                    /* INSERT REFERENCE TAG VALUES */
                    0x51U, 0xF0U, 0xBEU, 0xBFU, 0x7EU, 0x3BU, 0x9DU, 0x92U, 0xFCU, 0x49U, 0x74U, 0x17U, 0x79U, 0x36U, 0x3CU, 0xFEU,
                };
                uint8_t tv_tag[CMAC_TAG128b_SIZE];
                size_t rSize, pSize;

                startCmac(tv_key, tv_kSize);

                for(pSize = 0UL, rSize = tv_mSize; CMAC_TAG128b_SIZE < rSize; pSize += CMAC_TAG128b_SIZE, rSize -= CMAC_TAG128b_SIZE)
                {
                    updateCmac(&tv_mes[pSize], CMAC_TAG128b_SIZE);
                }
                finishCmac(tv_tag, &tv_mes[pSize], rSize);

                printf("AES128-CMAC#%2ld: %s\n", testNum, ((memcmp(tv_tag, ref_tag, CMAC_TAG128b_SIZE) == 0)?MES_PASS:MES_FAIL));
            }
        }
        /* CMAC-AES192 */
        {
            /* Commonly used CMAC-AES192 */
            const uint8_t tv_key[] = {
                0x8EU, 0x73U, 0xB0U, 0xF7U, 0xDAU, 0x0EU, 0x64U, 0x52U, 0xC8U, 0x10U, 0xF3U, 0x2BU, 0x80U, 0x90U, 0x79U, 0xE5U,
                0x62U, 0xF8U, 0xEAU, 0xD2U, 0x52U, 0x2CU, 0x6BU, 0x7BU,
            };
            const size_t tv_kSize = sizeof(tv_key);

            /* CMAC-AES192, Example #1 */
            {
                const size_t testNum = 1UL;
                const uint8_t tv_mes[] = "";
                const size_t tv_mSize = strlen(tv_mes);
                const uint8_t ref_tag[CMAC_TAG128b_SIZE] = {
                    /* INSERT REFERENCE TAG VALUES */
                    0xD1U, 0x7DU, 0xDFU, 0x46U, 0xADU, 0xAAU, 0xCDU, 0xE5U, 0x31U, 0xCAU, 0xC4U, 0x83U, 0xDEU, 0x7AU, 0x93U, 0x67U,
                };
                uint8_t tv_tag[CMAC_TAG128b_SIZE];
                size_t rSize, pSize;

                startCmac(tv_key, tv_kSize);

                for(pSize = 0UL, rSize = tv_mSize; CMAC_TAG128b_SIZE < rSize; pSize += CMAC_TAG128b_SIZE, rSize -= CMAC_TAG128b_SIZE)
                {
                    updateCmac(&tv_mes[pSize], CMAC_TAG128b_SIZE);
                }
                finishCmac(tv_tag, &tv_mes[pSize], rSize);

                printf("AES192-CMAC#%2ld: %s\n", testNum, ((memcmp(tv_tag, ref_tag, CMAC_TAG128b_SIZE) == 0)?MES_PASS:MES_FAIL));
            }
            /* CMAC-AES192, Example #2 */
            {
                const size_t testNum = 2UL;
                const uint8_t tv_mes[] = {
                    /* INSERT INPUT MESSAGE VALUES */
                    0x6BU, 0xC1U, 0xBEU, 0xE2U, 0x2EU, 0x40U, 0x9FU, 0x96U, 0xE9U, 0x3DU, 0x7EU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2AU,
                };
                const size_t tv_mSize = sizeof(tv_mes);
                const uint8_t ref_tag[CMAC_TAG128b_SIZE] = {
                    /* INSERT REFERENCE TAG VALUES */
                    0x9EU, 0x99U, 0xA7U, 0xBFU, 0x31U, 0xE7U, 0x10U, 0x90U, 0x06U, 0x62U, 0xF6U, 0x5EU, 0x61U, 0x7CU, 0x51U, 0x84U,
                };
                uint8_t tv_tag[CMAC_TAG128b_SIZE];
                size_t rSize, pSize;

                startCmac(tv_key, tv_kSize);

                for(pSize = 0UL, rSize = tv_mSize; CMAC_TAG128b_SIZE < rSize; pSize += CMAC_TAG128b_SIZE, rSize -= CMAC_TAG128b_SIZE)
                {
                    updateCmac(&tv_mes[pSize], CMAC_TAG128b_SIZE);
                }
                finishCmac(tv_tag, &tv_mes[pSize], rSize);

                printf("AES192-CMAC#%2ld: %s\n", testNum, ((memcmp(tv_tag, ref_tag, CMAC_TAG128b_SIZE) == 0)?MES_PASS:MES_FAIL));
            }
            /* CMAC-AES192, Example #3 */
            {
                const size_t testNum = 3UL;
                const uint8_t tv_mes[] = {
                    /* INSERT INPUT MESSAGE VALUES */
                    0x6BU, 0xC1U, 0xBEU, 0xE2U, 0x2EU, 0x40U, 0x9FU, 0x96U, 0xE9U, 0x3DU, 0x7EU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2AU,
                    0xAEU, 0x2DU, 0x8AU, 0x57U,
                };
                const size_t tv_mSize = sizeof(tv_mes);
                const uint8_t ref_tag[CMAC_TAG128b_SIZE] = {
                    /* INSERT REFERENCE TAG VALUES */
                    0x3DU, 0x75U, 0xC1U, 0x94U, 0xEDU, 0x96U, 0x07U, 0x04U, 0x44U, 0xA9U, 0xFAU, 0x7EU, 0xC7U, 0x40U, 0xECU, 0xF8U,
                };
                uint8_t tv_tag[CMAC_TAG128b_SIZE];
                size_t rSize, pSize;

                startCmac(tv_key, tv_kSize);

                for(pSize = 0UL, rSize = tv_mSize; CMAC_TAG128b_SIZE < rSize; pSize += CMAC_TAG128b_SIZE, rSize -= CMAC_TAG128b_SIZE)
                {
                    updateCmac(&tv_mes[pSize], CMAC_TAG128b_SIZE);
                }
                finishCmac(tv_tag, &tv_mes[pSize], rSize);

                printf("AES192-CMAC#%2ld: %s\n", testNum, ((memcmp(tv_tag, ref_tag, CMAC_TAG128b_SIZE) == 0)?MES_PASS:MES_FAIL));
            }
            /* CMAC-AES192, Example #4 */
            {
                const size_t testNum = 4UL;
                const uint8_t tv_mes[] = {
                    /* INSERT INPUT MESSAGE VALUES */
                    0x6BU, 0xC1U, 0xBEU, 0xE2U, 0x2EU, 0x40U, 0x9FU, 0x96U, 0xE9U, 0x3DU, 0x7EU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2AU,
                    0xAEU, 0x2DU, 0x8AU, 0x57U, 0x1EU, 0x03U, 0xACU, 0x9CU, 0x9EU, 0xB7U, 0x6FU, 0xACU, 0x45U, 0xAFU, 0x8EU, 0x51U,
                    0x30U, 0xC8U, 0x1CU, 0x46U, 0xA3U, 0x5CU, 0xE4U, 0x11U, 0xE5U, 0xFBU, 0xC1U, 0x19U, 0x1AU, 0x0AU, 0x52U, 0xEFU,
                    0xF6U, 0x9FU, 0x24U, 0x45U, 0xDFU, 0x4FU, 0x9BU, 0x17U, 0xADU, 0x2BU, 0x41U, 0x7BU, 0xE6U, 0x6CU, 0x37U, 0x10U,
                };
                const size_t tv_mSize = sizeof(tv_mes);
                const uint8_t ref_tag[CMAC_TAG128b_SIZE] = {
                    /* INSERT REFERENCE TAG VALUES */
                    0xA1U, 0xD5U, 0xDFU, 0x0EU, 0xEDU, 0x79U, 0x0FU, 0x79U, 0x4DU, 0x77U, 0x58U, 0x96U, 0x59U, 0xF3U, 0x9AU, 0x11U,
                };
                uint8_t tv_tag[CMAC_TAG128b_SIZE];
                size_t rSize, pSize;

                startCmac(tv_key, tv_kSize);

                for(pSize = 0UL, rSize = tv_mSize; CMAC_TAG128b_SIZE < rSize; pSize += CMAC_TAG128b_SIZE, rSize -= CMAC_TAG128b_SIZE)
                {
                    updateCmac(&tv_mes[pSize], CMAC_TAG128b_SIZE);
                }
                finishCmac(tv_tag, &tv_mes[pSize], rSize);

                printf("AES192-CMAC#%2ld: %s\n", testNum, ((memcmp(tv_tag, ref_tag, CMAC_TAG128b_SIZE) == 0)?MES_PASS:MES_FAIL));
            }
        }
        /* CMAC-AES256 */
        {
            /* Commonly used CMAC-AES256 */
            const uint8_t tv_key[] = {
                0x60U, 0x3DU, 0xEBU, 0x10U, 0x15U, 0xCAU, 0x71U, 0xBEU, 0x2BU, 0x73U, 0xAEU, 0xF0U, 0x85U, 0x7DU, 0x77U, 0x81U,
                0x1FU, 0x35U, 0x2CU, 0x07U, 0x3BU, 0x61U, 0x08U, 0xD7U, 0x2DU, 0x98U, 0x10U, 0xA3U, 0x09U, 0x14U, 0xDFU, 0xF4U,
            };
            const size_t tv_kSize = sizeof(tv_key);

            /* CMAC-AES256, Example #1 */
            {
                const size_t testNum = 1UL;
                const uint8_t tv_mes[] = "";
                const size_t tv_mSize = strlen(tv_mes);
                const uint8_t ref_tag[CMAC_TAG128b_SIZE] = {
                    /* INSERT REFERENCE TAG VALUES */
                    0x02U, 0x89U, 0x62U, 0xF6U, 0x1BU, 0x7BU, 0xF8U, 0x9EU, 0xFCU, 0x6BU, 0x55U, 0x1FU, 0x46U, 0x67U, 0xD9U, 0x83U,
                };
                uint8_t tv_tag[CMAC_TAG128b_SIZE];
                size_t rSize, pSize;

                startCmac(tv_key, tv_kSize);

                for(pSize = 0UL, rSize = tv_mSize; CMAC_TAG128b_SIZE < rSize; pSize += CMAC_TAG128b_SIZE, rSize -= CMAC_TAG128b_SIZE)
                {
                    updateCmac(&tv_mes[pSize], CMAC_TAG128b_SIZE);
                }
                finishCmac(tv_tag, &tv_mes[pSize], rSize);

                printf("AES256-CMAC#%2ld: %s\n", testNum, ((memcmp(tv_tag, ref_tag, CMAC_TAG128b_SIZE) == 0)?MES_PASS:MES_FAIL));
            }
            /* CMAC-AES256, Example #2 */
            {
                const size_t testNum = 2UL;
                const uint8_t tv_mes[] = {
                    /* INSERT INPUT MESSAGE VALUES */
                    0x6BU, 0xC1U, 0xBEU, 0xE2U, 0x2EU, 0x40U, 0x9FU, 0x96U, 0xE9U, 0x3DU, 0x7EU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2AU,
                };
                const size_t tv_mSize = sizeof(tv_mes);
                const uint8_t ref_tag[CMAC_TAG128b_SIZE] = {
                    /* INSERT REFERENCE TAG VALUES */
                    0x28U, 0xA7U, 0x02U, 0x3FU, 0x45U, 0x2EU, 0x8FU, 0x82U, 0xBDU, 0x4BU, 0xF2U, 0x8DU, 0x8CU, 0x37U, 0xC3U, 0x5CU,
                };
                uint8_t tv_tag[CMAC_TAG128b_SIZE];
                size_t rSize, pSize;

                startCmac(tv_key, tv_kSize);

                for(pSize = 0UL, rSize = tv_mSize; CMAC_TAG128b_SIZE < rSize; pSize += CMAC_TAG128b_SIZE, rSize -= CMAC_TAG128b_SIZE)
                {
                    updateCmac(&tv_mes[pSize], CMAC_TAG128b_SIZE);
                }
                finishCmac(tv_tag, &tv_mes[pSize], rSize);

                printf("AES256-CMAC#%2ld: %s\n", testNum, ((memcmp(tv_tag, ref_tag, CMAC_TAG128b_SIZE) == 0)?MES_PASS:MES_FAIL));
            }
            /* CMAC-AES256, Example #3 */
            {
                const size_t testNum = 3UL;
                const uint8_t tv_mes[] = {
                    /* INSERT INPUT MESSAGE VALUES */
                    0x6BU, 0xC1U, 0xBEU, 0xE2U, 0x2EU, 0x40U, 0x9FU, 0x96U, 0xE9U, 0x3DU, 0x7EU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2AU,
                    0xAEU, 0x2DU, 0x8AU, 0x57U,
                };
                const size_t tv_mSize = sizeof(tv_mes);
                const uint8_t ref_tag[CMAC_TAG128b_SIZE] = {
                    /* INSERT REFERENCE TAG VALUES */
                    0x15U, 0x67U, 0x27U, 0xDCU, 0x08U, 0x78U, 0x94U, 0x4AU, 0x02U, 0x3CU, 0x1FU, 0xE0U, 0x3BU, 0xADU, 0x6DU, 0x93U,
                };
                uint8_t tv_tag[CMAC_TAG128b_SIZE];
                size_t rSize, pSize;

                startCmac(tv_key, tv_kSize);

                for(pSize = 0UL, rSize = tv_mSize; CMAC_TAG128b_SIZE < rSize; pSize += CMAC_TAG128b_SIZE, rSize -= CMAC_TAG128b_SIZE)
                {
                    updateCmac(&tv_mes[pSize], CMAC_TAG128b_SIZE);
                }
                finishCmac(tv_tag, &tv_mes[pSize], rSize);

                printf("AES256-CMAC#%2ld: %s\n", testNum, ((memcmp(tv_tag, ref_tag, CMAC_TAG128b_SIZE) == 0)?MES_PASS:MES_FAIL));
            }
            /* CMAC-AES256, Example #4 */
            {
                const size_t testNum = 4UL;
                const uint8_t tv_mes[] = {
                    /* INSERT INPUT MESSAGE VALUES */
                    0x6BU, 0xC1U, 0xBEU, 0xE2U, 0x2EU, 0x40U, 0x9FU, 0x96U, 0xE9U, 0x3DU, 0x7EU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2AU,
                    0xAEU, 0x2DU, 0x8AU, 0x57U, 0x1EU, 0x03U, 0xACU, 0x9CU, 0x9EU, 0xB7U, 0x6FU, 0xACU, 0x45U, 0xAFU, 0x8EU, 0x51U,
                    0x30U, 0xC8U, 0x1CU, 0x46U, 0xA3U, 0x5CU, 0xE4U, 0x11U, 0xE5U, 0xFBU, 0xC1U, 0x19U, 0x1AU, 0x0AU, 0x52U, 0xEFU,
                    0xF6U, 0x9FU, 0x24U, 0x45U, 0xDFU, 0x4FU, 0x9BU, 0x17U, 0xADU, 0x2BU, 0x41U, 0x7BU, 0xE6U, 0x6CU, 0x37U, 0x10U,
                };
                const size_t tv_mSize = sizeof(tv_mes);
                const uint8_t ref_tag[CMAC_TAG128b_SIZE] = {
                    /* INSERT REFERENCE TAG VALUES */
                    0xE1U, 0x99U, 0x21U, 0x90U, 0x54U, 0x9FU, 0x6EU, 0xD5U, 0x69U, 0x6AU, 0x2CU, 0x05U, 0x6CU, 0x31U, 0x54U, 0x10U,
                };
                uint8_t tv_tag[CMAC_TAG128b_SIZE];
                size_t rSize, pSize;

                startCmac(tv_key, tv_kSize);

                for(pSize = 0UL, rSize = tv_mSize; CMAC_TAG128b_SIZE < rSize; pSize += CMAC_TAG128b_SIZE, rSize -= CMAC_TAG128b_SIZE)
                {
                    updateCmac(&tv_mes[pSize], CMAC_TAG128b_SIZE);
                }
                finishCmac(tv_tag, &tv_mes[pSize], rSize);

                printf("AES256-CMAC#%2ld: %s\n", testNum, ((memcmp(tv_tag, ref_tag, CMAC_TAG128b_SIZE) == 0)?MES_PASS:MES_FAIL));
            }
        }
    }
}
#endif /* TEST_CMAC */

#define _KEYIN_DO_TEST_(c, TEST_FUNC_NAME) { \
    (c) = '\0'; \
    do { \
        printf("run %s()(y/n)?: ", (TEST_FUNC_NAME)); \
        (c) = getchar(); \
        getchar(); \
    } while(((c) != 'y' ) && ((c) != 'Y' ) && ((c) != 'n' ) && ((c) != 'N' )); \
    if('A' <= (c) && (c) <= 'Z')    (c) += 0x20; \
}
#define _COND_DO_TEST_(c)   if((c) == 'y')

void test_sequence(void) {
    char keyin = '\0';
    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_macro()]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_macro");
    _COND_DO_TEST_(keyin)
    test_macro();
    printf("[test   end: test_macro()]\r\n");
    printf("================================================================================\n");

#if 0   /* CONFIG_DO_TEST_BIGNUM */
    printf("[test start: test_bignum()]\r\n");
    test_bignum();
    printf("[test   end: test_bignum()]\r\n");
#endif  /* CONFIG_DO_TEST_BIGNUM */

    /******************************/
    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_cpy_bignum_math_signed()]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_cpy_bignum_math_signed");
    _COND_DO_TEST_(keyin)
    test_cpy_bignum_math_signed();
    printf("[test   end: test_cpy_bignum_math_signed()]\r\n");
    printf("================================================================================\n");

    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_cpy_bignum_math_unsigned()]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_cpy_bignum_math_unsigned");
    _COND_DO_TEST_(keyin)
    test_cpy_bignum_math_unsigned();
    printf("[test   end: test_cpy_bignum_math_unsigned()]\r\n");
    printf("================================================================================\n");

    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_twos_bignum_256b()]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_twos_bignum_256b");
    _COND_DO_TEST_(keyin)
    test_twos_bignum_256b();
    printf("[test   end: test_twos_bignum_256b()]\r\n");
    printf("================================================================================\n");

    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_abs_bignum_signed_256b()]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_abs_bignum_signed_256b");
    _COND_DO_TEST_(keyin)
    test_abs_bignum_signed_256b();
    printf("[test   end: test_abs_bignum_signed_256b()]\r\n");
    printf("================================================================================\n");

    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_sign_bignum_256b()]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_sign_bignum_256b");
    _COND_DO_TEST_(keyin)
    test_sign_bignum_256b();
    printf("[test   end: test_sign_bignum_256b()]\r\n");
    printf("================================================================================\n");

    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_cmp0_bignum_256b()]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_cmp0_bignum_256b");
    _COND_DO_TEST_(keyin)
    test_cmp0_bignum_256b();
    printf("[test   end: test_cmp0_bignum_256b()]\r\n");
    printf("================================================================================\n");

#if 1 /* cmp_bignum_with_sub_add_twos */
    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_cmp_bignum_signed_256b(cmp_bignum_with_sub_add_twos)]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_cmp_bignum_signed_256b");
    _COND_DO_TEST_(keyin)
    test_cmp_bignum_signed_256b("cmp_bignum_with_sub_add_twos", cmp_bignum_with_sub_add_twos);
    printf("[test   end: test_cmp_bignum_signed_256b(cmp_bignum_with_sub_add_twos)]\r\n");
    printf("================================================================================\n");
#endif/* cmp_bignum_with_sub_add_twos */

    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_cmp_bignum_signed_256b(cmp_bignum_logical)]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_cmp_bignum_signed_256b");
    _COND_DO_TEST_(keyin)
    test_cmp_bignum_signed_256b("cmp_bignum_logical", cmp_bignum_logical);
    printf("[test   end: test_cmp_bignum_signed_256b(cmp_bignum_logical)]\r\n");
    printf("================================================================================\n");

    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_sub_bignum_unsigned_127b()]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_sub_bignum_unsigned_127b");
    _COND_DO_TEST_(keyin)
    test_sub_bignum_unsigned_127b();
    printf("[test   end: test_sub_bignum_unsigned_127b()]\r\n");
    printf("================================================================================\n");

    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_add_bignum_unsigned_256b()]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_add_bignum_unsigned_256b");
    _COND_DO_TEST_(keyin)
    test_add_bignum_unsigned_256b();
    printf("[test   end: test_add_bignum_unsigned_256b()]\r\n");
    printf("================================================================================\n");

    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_sub_bignum_unsigned_256b(sub_bignum)]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_sub_bignum_unsigned_256b");
    _COND_DO_TEST_(keyin)
    test_sub_bignum_unsigned_256b("sub_bignum", sub_bignum);
    printf("[test   end: test_sub_bignum_unsigned_256b(sub_bignum)]\r\n");
    printf("================================================================================\n");

    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_sub_bignum_unsigned_256b(sub_bignum_with_add_twos)]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_sub_bignum_unsigned_256b");
    _COND_DO_TEST_(keyin)
    test_sub_bignum_unsigned_256b("sub_bignum_with_add_twos", sub_bignum_with_add_twos);
    printf("[test   end: test_sub_bignum_unsigned_256b(sub_bignum_with_add_twos)]\r\n");
    printf("================================================================================\n");

    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_add_bignum_carry_loc()]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_add_bignum_carry_loc");
    _COND_DO_TEST_(keyin)
    test_add_bignum_carry_loc();
    printf("[test   end: test_add_bignum_carry_loc()]\r\n");
    printf("================================================================================\n");

    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_mul_bignum_1024b(mul_bignum_1bs)]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_mul_bignum_1024b");
    _COND_DO_TEST_(keyin)
    test_mul_bignum_1024b("mul_bignum_1bs", mul_bignum_1bs);
    printf("[test   end: test_mul_bignum_1024b(mul_bignum_1bs)]\r\n");
    printf("================================================================================\n");

    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_mul_bignum_1024b(mul_bignum)]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_mul_bignum_1024b");
    _COND_DO_TEST_(keyin)
    test_mul_bignum_1024b("mul_bignum", mul_bignum);
    printf("[test   end: test_mul_bignum_1024b(mul_bignum)]\r\n");
    printf("================================================================================\n");

    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_mul_bignum_1024b(mul_bignum_unsafe)]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_mul_bignum_1024b");
    _COND_DO_TEST_(keyin)
    test_mul_bignum_1024b("mul_bignum", mul_bignum_unsafe);
    printf("[test   end: test_mul_bignum_1024b(mul_bignum_unsafe)]\r\n");
    printf("================================================================================\n");

    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_mul_bignum_1024b_sameBignumLength(mul_bignum)]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_mul_bignum_1024b_sameBignumLength");
    _COND_DO_TEST_(keyin)
    test_mul_bignum_1024b_sameBignumLength("mul_bignum", mul_bignum);
    printf("[test   end: test_mul_bignum_1024b_sameBignumLength(mul_bignum)]\r\n");
    printf("================================================================================\n");

    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_mul_bignum_1024b_sameBignumLength(mul_bignum_unsafe)]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_mul_bignum_1024b_sameBignumLength");
    _COND_DO_TEST_(keyin)
    test_mul_bignum_1024b_sameBignumLength("mul_bignum", mul_bignum_unsafe);
    printf("[test   end: test_mul_bignum_1024b_sameBignumLength(mul_bignum_unsafe)]\r\n");
    printf("================================================================================\n");

    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_mul_bignum_bs_nn()]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_mul_bignum_bs_nn");
    _COND_DO_TEST_(keyin)
    test_mul_bignum_bs_nn();
    printf("[test   end: test_mul_bignum_bs_nn()]\r\n");
    printf("================================================================================\n");

    /******************************/
    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_bignum_bit_contol()]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_bignum_bit_contol");
    _COND_DO_TEST_(keyin)
    test_bignum_bit_contol();
    printf("[test   end: test_bignum_bit_contol()]\r\n");
    printf("================================================================================\n");

    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_find_bignum_MSBL_LSBL()]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_find_bignum_MSBL_LSBL");
    _COND_DO_TEST_(keyin)
    test_find_bignum_MSBL_LSBL();
    printf("[test   end: test_find_bignum_MSBL_LSBL()]\r\n");
    printf("================================================================================\n");

    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_lslb_bignum()]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_lslb_bignum");
    _COND_DO_TEST_(keyin)
    test_lslb_bignum();
    printf("[test   end: test_lslb_bignum()]\r\n");
    printf("================================================================================\n");

    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_lsrb_bignum()]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_lsrb_bignum");
    _COND_DO_TEST_(keyin)
    test_lsrb_bignum();
    printf("[test   end: test_lsrb_bignum()]\r\n");
    printf("================================================================================\n");

    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_lslnb_bignum_self()]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_lslnb_bignum_self");
    _COND_DO_TEST_(keyin)
    test_lslnb_bignum_self();
    printf("[test   end: test_lslnb_bignum_self()]\r\n");
    printf("================================================================================\n");

    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_lsrnb_bignum_self()]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_lsrnb_bignum_self");
    _COND_DO_TEST_(keyin)
    test_lsrnb_bignum_self();
    printf("[test   end: test_lsrnb_bignum_self()]\r\n");
    printf("================================================================================\n");

    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_lsl1b_bignum_self()]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_lsl1b_bignum_self");
    _COND_DO_TEST_(keyin)
    test_lsl1b_bignum_self();
    printf("[test   end: test_lsl1b_bignum_self()]\r\n");
    printf("================================================================================\n");

    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_mul_bignum_sameBignumLength_with_mod_value(mul_bignum)]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_mul_bignum_sameBignumLength_with_mod_value");
    _COND_DO_TEST_(keyin)
    test_mul_bignum_sameBignumLength_with_mod_value("mul_bignum", mul_bignum);
    printf("[test   end: test_mul_bignum_sameBignumLength_with_mod_value(mul_bignum)]\r\n");
    printf("================================================================================\n");

    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_mul_bignum_sameBignumLength_with_mod_value(mul_bignum_unsafe)]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_mul_bignum_sameBignumLength_with_mod_value");
    _COND_DO_TEST_(keyin)
    test_mul_bignum_sameBignumLength_with_mod_value("mul_bignum_unsafe", mul_bignum_unsafe);
    printf("[test   end: test_mul_bignum_sameBignumLength_with_mod_value(mul_bignum_unsafe)]\r\n");
    printf("================================================================================\n");

    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_div_bignum_with_mod()]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_div_bignum_with_mod");
    _COND_DO_TEST_(keyin)
    test_div_bignum_with_mod();
    printf("[test   end: test_div_bignum_with_mod()]\r\n");
    printf("================================================================================\n");

    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_gcd_bignum()]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_gcd_bignum");
    _COND_DO_TEST_(keyin)
    test_gcd_bignum();
    printf("[test   end: test_gcd_bignum()]\r\n");
    printf("================================================================================\n");

    printf("--------------------------------------------------------------------------------\n");
    printf("[test start: test_mmi_bignum()]\r\n");
    _KEYIN_DO_TEST_(keyin, "test_mmi_bignum");
    _COND_DO_TEST_(keyin)
    test_mmi_bignum();
    printf("[test   end: test_mmi_bignum()]\r\n");
    printf("================================================================================\n");

    printf("--------------------------------------------------------------------------------\n");
    _KEYIN_DO_TEST_(keyin, "test_ghash");
    _COND_DO_TEST_(keyin)
    test_ghash();
    printf("================================================================================\n");
#ifdef TEST_AES
    printf("--------------------------------------------------------------------------------\n");
    _KEYIN_DO_TEST_(keyin, "test_aes");
    _COND_DO_TEST_(keyin)
    test_aes();
    printf("================================================================================\n");
#endif /* TEST_AES */

#ifdef TEST_ENDIAN
    printf("--------------------------------------------------------------------------------\n");
    _KEYIN_DO_TEST_(keyin, "test_endian");
    _COND_DO_TEST_(keyin)
    test_endian();
    printf("================================================================================\n");
#endif /* TEST_ENDIAN */

#ifdef TEST_SHA
    printf("--------------------------------------------------------------------------------\n");
    _KEYIN_DO_TEST_(keyin, "test_sha2");
    _COND_DO_TEST_(keyin)
    test_sha2();
    printf("================================================================================\n");
#endif /* TEST_SHA */

#ifdef TEST_HMAC
    printf("--------------------------------------------------------------------------------\n");
    _KEYIN_DO_TEST_(keyin, "test_FIPS_198_hamc256_imVal");
    _COND_DO_TEST_(keyin)
    test_FIPS_198_hamc256_imVal();
    printf("================================================================================\n");
    printf("--------------------------------------------------------------------------------\n");
    _KEYIN_DO_TEST_(keyin, "test_FIPS_198_hamc512_imVal");
    _COND_DO_TEST_(keyin)
    test_FIPS_198_hamc512_imVal();
    printf("================================================================================\n");
#endif /* TEST_HMAC */

#ifdef TEST_CMAC
    printf("--------------------------------------------------------------------------------\n");
    _KEYIN_DO_TEST_(keyin, "test_FIPS_198_hamc512_imVal");
    _COND_DO_TEST_(keyin)
    test_RFC4493_aes128_cmac();
    printf("================================================================================\n");
    printf("--------------------------------------------------------------------------------\n");
    _KEYIN_DO_TEST_(keyin, "test_SP800_38B_cmac_aes_imVal");
    _COND_DO_TEST_(keyin)
    test_SP800_38B_cmac_aes_imVal();
    printf("================================================================================\n");
#endif /* TEST_CMAC */
}

void test_u32_u64_mul_time(void) {
#define TEST_MUL_COUNT_TIME_LOOPS   102400000UL
    uint32_t x32, a32, b32;
    uint64_t x64, a64, b64;
    size_t loopCnt;

    a32 = 0x1111ffffU;
    b32 = 0x0000ffffU;
    TICK_TIME_START("uint32_t mul time test");
    for(loopCnt = 0UL; loopCnt < TEST_MUL_COUNT_TIME_LOOPS; loopCnt++) {
        x32 = a32 * b32;
    }
    TICK_TIME_END;

    a64 = 0x11111111ffffffffU;
    b64 = 0x00000000ffffffffU;
    TICK_TIME_START("uint64_t mul time test");
    for(loopCnt = 0UL; loopCnt < TEST_MUL_COUNT_TIME_LOOPS; loopCnt++) {
        x64 = a64 * b64;
    }
    TICK_TIME_END;
#undef TEST_MUL_COUNT_TIME_LOOPS
}

int main(int argc, char** argv) {
    char keyin = '\0';
    printf("arg:%d, ",argc);
    for(unsigned int i=0; i<argc; i++) {
        printf("arg[%d]:%s, ", i, argv[i]);
    }
    printf("\r\n");

    _KEYIN_DO_TEST_(keyin, "test_sequence");
    _COND_DO_TEST_(keyin)
    test_sequence();

    _KEYIN_DO_TEST_(keyin, "test_u32_u64_mul_time");
    _COND_DO_TEST_(keyin)
    test_u32_u64_mul_time();
}
