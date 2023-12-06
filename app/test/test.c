#include <time.h>

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <unistd.h>

#include <sys/sysinfo.h>

#include "common/util.h"
#include "common/ntype.h"
#include "common/returnType.h"

#include "arith/arith_core.h"
#include "logic/logic_core.h"

#include "test/vector.h"

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

static char* g_tTimeTitle;
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

void test_print_ntype(ntype_s* p, const char* title) {
    printf("[%s]\r\n", title);
    printf("addr:0x%p, NTYPE size:%lu\r\n", p, sizeof(NTYPE));
    printf("p->data:0x%p, p->lastMask:0x%x\r\np->bits=%ld, p->length=%ld, p->size=%ld\r\n", \
            p->data, p->lastMask, p->bits, p->length, p->size);
    for(size_t i = p->length- 1u; i != ((size_t)-1); i--) {
        printf("0x%08x", p->data[i]);
        if(i != 0u) printf(":");
        else        printf("\r\n");
    }
}

void test_macro(void) {
    bool cmp_result;
    // test: UIN_CEIL(n, x)
    {
        uint32_t ref, r, n, m;
        printf("[TEST] UIN_CEIL\r\n");

        // test 1
        n = 6u; m = 14u;
        ref = 1u;
        r = UIN_CEIL(n, m);
        printf("n=%u, m=%u, r=%u\r\n", n, m, r);
        printf("UIN_CEIL(%u, %u), result: %s\r\n", n, m, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        // test 2
        n = 14u; m = 14u;
        ref = 1u;
        r = UIN_CEIL(n, m);
        printf("n=%u, m=%u, r=%u\r\n", n, m, r);
        printf("UIN_CEIL(%u, %u), result: %s\r\n", n, m, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        // test 3
        n = 1024u; m = 1023u;
        ref = 2u;
        r = UIN_CEIL(n, m);
        printf("n=%u, m=%u, r=%u\r\n", n, m, r);
        printf("UIN_CEIL(%u, %u), result: %s\r\n", n, m, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        // test 4
        n = 34u + 7u; m = 17u;
        ref = 3u;
        r = UIN_CEIL(n, m);
        printf("n=%u, m=%u, r=%u\r\n", n, m, r);
        printf("UIN_CEIL(%u, %u), result: %s\r\n", n, m, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        // test 5
        n = 60u + 14u; m = 37u;
        ref = 2u;
        r = UIN_CEIL(n, m);
        printf("n=%u, m=%u, r=%u\r\n", n, m, r);
        printf("UIN_CEIL(%u, %u), result: %s\r\n", n, m, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        // test 6
        n = 35u + 6u; m = 7u;
        ref = 6u;
        r = UIN_CEIL(n, m);
        printf("n=%u, m=%u, r=%u\r\n", n, m, r);
        printf("UIN_CEIL(%u, %u), result: %s\r\n", n, m, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

    }

    // test: INT_CEIL(n, x)
    {
        int32_t ref, r, n, m;
        printf("[TEST] INT_CEIL\r\n");

        // test 1
        n = 6; m = 14;
        ref = 1;
        r = INT_CEIL(n, m);
        printf("n=%u, m=%u, r=%u\r\n", n, m, r);
        printf("INT_CEIL(%u, %u), result: %s\r\n", n, m, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        // test 2
        n = 14; m = 14;
        ref = 1;
        r = INT_CEIL(n, m);
        printf("n=%u, m=%u, r=%u\r\n", n, m, r);
        printf("INT_CEIL(%u, %u), result: %s\r\n", n, m, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        // test 3
        n = 1024; m = 1023;
        ref = 2;
        r = INT_CEIL(n, m);
        printf("n=%u, m=%u, r=%u\r\n", n, m, r);
        printf("INT_CEIL(%u, %u), result: %s\r\n", n, m, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        // test 4
        n = 34u + 7; m = 17;
        ref = 3;
        r = INT_CEIL(n, m);
        printf("n=%u, m=%u, r=%u\r\n", n, m, r);
        printf("INT_CEIL(%u, %u), result: %s\r\n", n, m, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        // test 5
        n = 60u + 14; m = 37;
        ref = 2;
        r = INT_CEIL(n, m);
        printf("n=%u, m=%u, r=%u\r\n", n, m, r);
        printf("INT_CEIL(%u, %u), result: %s\r\n", n, m, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        // test 6
        n = 35u + 6; m = 7;
        ref = 6;
        r = INT_CEIL(n, m);
        printf("n=%u, m=%u, r=%u\r\n", n, m, r);
        printf("INT_CEIL(%u, %u), result: %s\r\n", n, m, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

    }

    // test: BIT_U8_SIZE(bits)
    {
        uint32_t ref, r, n;
        printf("[TEST] BIT_U8_SIZE\r\n");

        // test 1
        n = 6u;
        ref = 1u;
        r = BIT_U8_SIZE(n);
        printf("n=%u, r=%u\r\n", n, r);
        printf("BIT_U8_SIZE(%u), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        // test 2
        n = 14u;
        ref = 2u;
        r = BIT_U8_SIZE(n);
        printf("n=%u, r=%u\r\n", n, r);
        printf("BIT_U8_SIZE(%u), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        // test 3
        n = 1024u;
        ref = 128u;
        r = BIT_U8_SIZE(n);
        printf("n=%u, r=%u\r\n", n, r);
        printf("BIT_U8_SIZE(%u), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        // test 4
        n = 10240u;
        ref = 1280u;
        r = BIT_U8_SIZE(n);
        printf("n=%u, r=%u\r\n", n, r);
        printf("BIT_U8_SIZE(%u), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        // test 5
        n = 10241u;
        ref = 1281u;
        r = BIT_U8_SIZE(n);
        printf("n=%u, r=%u\r\n", n, r);
        printf("BIT_U8_SIZE(%u), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        // test 6
        n = 727u;
        ref = 91u;
        r = BIT_U8_SIZE(n);
        printf("n=%u, r=%u\r\n", n, r);
        printf("BIT_U8_SIZE(%u), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

    }

    // test: BIT_U16_SIZE(bits)
    {
        uint32_t ref, r, n;
        printf("[TEST] BIT_U16_SIZE\r\n");

        // test 1
        n = 6u;
        ref = 1u;
        r = BIT_U16_SIZE(n);
        printf("n=%u, r=%u\r\n", n, r);
        printf("BIT_U16_SIZE(%u), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        // test 2
        n = 14u;
        ref = 1u;
        r = BIT_U16_SIZE(n);
        printf("n=%u, r=%u\r\n", n, r);
        printf("BIT_U16_SIZE(%u), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        // test 3
        n = 1024u;
        ref = 64u;
        r = BIT_U16_SIZE(n);
        printf("n=%u, r=%u\r\n", n, r);
        printf("BIT_U16_SIZE(%u), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        // test 4
        n = 10240u;
        ref = 640u;
        r = BIT_U16_SIZE(n);
        printf("n=%u, r=%u\r\n", n, r);
        printf("BIT_U16_SIZE(%u), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        // test 5
        n = 10241u;
        ref = 641u;
        r = BIT_U16_SIZE(n);
        printf("n=%u, r=%u\r\n", n, r);
        printf("BIT_U16_SIZE(%u), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        // test 6
        n = 727u;
        ref = 46u;
        r = BIT_U16_SIZE(n);
        printf("n=%u, r=%u\r\n", n, r);
        printf("BIT_U16_SIZE(%u), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

    }

    // test: BIT_U32_SIZE(bits)
    {
        uint32_t ref, r, n;
        printf("[TEST] BIT_U32_SIZE\r\n");

        // test 1
        n = 6u;
        ref = 1u;
        r = BIT_U32_SIZE(n);
        printf("n=%u, r=%u\r\n", n, r);
        printf("BIT_U32_SIZE(%u), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        // test 2
        n = 14u;
        ref = 1u;
        r = BIT_U32_SIZE(n);
        printf("n=%u, r=%u\r\n", n, r);
        printf("BIT_U32_SIZE(%u), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        // test 3
        n = 1024u;
        ref = 32u;
        r = BIT_U32_SIZE(n);
        printf("n=%u, r=%u\r\n", n, r);
        printf("BIT_U32_SIZE(%u), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        // test 4
        n = 10240u;
        ref = 320u;
        r = BIT_U32_SIZE(n);
        printf("n=%u, r=%u\r\n", n, r);
        printf("BIT_U32_SIZE(%u), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        // test 5
        n = 10241u;
        ref = 321u;
        r = BIT_U32_SIZE(n);
        printf("n=%u, r=%u\r\n", n, r);
        printf("BIT_U32_SIZE(%u), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        // test 6
        n = 727u;
        ref = 23u;
        r = BIT_U32_SIZE(n);
        printf("n=%u, r=%u\r\n", n, r);
        printf("BIT_U32_SIZE(%u), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

    }

    // test: BIT_U64_SIZE(bits)
    {
        uint32_t ref, r, n;
        printf("[TEST] BIT_U64_SIZE\r\n");

        // test 1
        n = 6u;
        ref = 1u;
        r = BIT_U64_SIZE(n);
        printf("n=%u, r=%u\r\n", n, r);
        printf("BIT_U64_SIZE(%u), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        // test 2
        n = 14u;
        ref = 1u;
        r = BIT_U64_SIZE(n);
        printf("n=%u, r=%u\r\n", n, r);
        printf("BIT_U64_SIZE(%u), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        // test 3
        n = 1024u;
        ref = 16u;
        r = BIT_U64_SIZE(n);
        printf("n=%u, r=%u\r\n", n, r);
        printf("BIT_U64_SIZE(%u), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        // test 4
        n = 10240u;
        ref = 160u;
        r = BIT_U64_SIZE(n);
        printf("n=%u, r=%u\r\n", n, r);
        printf("BIT_U64_SIZE(%u), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        // test 5
        n = 10241u;
        ref = 161u;
        r = BIT_U64_SIZE(n);
        printf("n=%u, r=%u\r\n", n, r);
        printf("BIT_U64_SIZE(%u), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        // test 6
        n = 727u;
        ref = 12u;
        r = BIT_U64_SIZE(n);
        printf("n=%u, r=%u\r\n", n, r);
        printf("BIT_U64_SIZE(%u), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

    }

    // test: LASTBITMASK(bits, TYPE)
    {
        // uint32_t
        uint32_t test_tmp_u32_bits;
        uint32_t test_tmp_u32_mask;
        uint32_t test_tmp_u32_ref;

        test_tmp_u32_bits = 127UL;
        test_tmp_u32_ref = 0x7FFFFFFFUL;
        test_tmp_u32_mask = LASTBITMASK(test_tmp_u32_bits, uint32_t);
        cmp_result = (test_tmp_u32_ref == test_tmp_u32_mask);
        printf("LASTBITMASK(%u, uint32_t)=0x%08x, result: %s\r\n", test_tmp_u32_bits, test_tmp_u32_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);

        test_tmp_u32_bits = 126UL;
        test_tmp_u32_ref = 0x3FFFFFFFUL;
        test_tmp_u32_mask = LASTBITMASK(test_tmp_u32_bits, uint32_t);
        cmp_result = (test_tmp_u32_ref == test_tmp_u32_mask);
        printf("LASTBITMASK(%u, uint32_t)=0x%08x, result: %s\r\n", test_tmp_u32_bits, test_tmp_u32_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);

        test_tmp_u32_bits = 125UL;
        test_tmp_u32_ref = 0x1FFFFFFFUL;
        test_tmp_u32_mask = LASTBITMASK(test_tmp_u32_bits, uint32_t);
        cmp_result = (test_tmp_u32_ref == test_tmp_u32_mask);
        printf("LASTBITMASK(%u, uint32_t)=0x%08x, result: %s\r\n", test_tmp_u32_bits, test_tmp_u32_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);

        test_tmp_u32_bits = 124UL;
        test_tmp_u32_ref = 0x0FFFFFFFUL;
        test_tmp_u32_mask = LASTBITMASK(test_tmp_u32_bits, uint32_t);
        cmp_result = (test_tmp_u32_ref == test_tmp_u32_mask);
        printf("LASTBITMASK(%u, uint32_t)=0x%08x, result: %s\r\n", test_tmp_u32_bits, test_tmp_u32_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);

        test_tmp_u32_bits = 105UL;
        test_tmp_u32_ref = 0x000001FFUL;
        test_tmp_u32_mask = LASTBITMASK(test_tmp_u32_bits, uint32_t);
        cmp_result = (test_tmp_u32_ref == test_tmp_u32_mask);
        printf("LASTBITMASK(%u, uint32_t)=0x%08x, result: %s\r\n", test_tmp_u32_bits, test_tmp_u32_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);

        test_tmp_u32_bits = 104UL;
        test_tmp_u32_ref = 0x000000FFUL;
        test_tmp_u32_mask = LASTBITMASK(test_tmp_u32_bits, uint32_t);
        cmp_result = (test_tmp_u32_ref == test_tmp_u32_mask);
        printf("LASTBITMASK(%u, uint32_t)=0x%08x, result: %s\r\n", test_tmp_u32_bits, test_tmp_u32_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);

        test_tmp_u32_bits = 103UL;
        test_tmp_u32_ref = 0x0000007FUL;
        test_tmp_u32_mask = LASTBITMASK(test_tmp_u32_bits, uint32_t);
        cmp_result = (test_tmp_u32_ref == test_tmp_u32_mask);
        printf("LASTBITMASK(%u, uint32_t)=0x%08x, result: %s\r\n", test_tmp_u32_bits, test_tmp_u32_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);

        test_tmp_u32_bits = 102UL;
        test_tmp_u32_ref = 0x0000003FUL;
        test_tmp_u32_mask = LASTBITMASK(test_tmp_u32_bits, uint32_t);
        cmp_result = (test_tmp_u32_ref == test_tmp_u32_mask);
        printf("LASTBITMASK(%u, uint32_t)=0x%08x, result: %s\r\n", test_tmp_u32_bits, test_tmp_u32_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);

        test_tmp_u32_bits = 101UL;
        test_tmp_u32_ref = 0x0000001FUL;
        test_tmp_u32_mask = LASTBITMASK(test_tmp_u32_bits, uint32_t);
        cmp_result = (test_tmp_u32_ref == test_tmp_u32_mask);
        printf("LASTBITMASK(%u, uint32_t)=0x%08x, result: %s\r\n", test_tmp_u32_bits, test_tmp_u32_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);

        test_tmp_u32_bits = 100UL;
        test_tmp_u32_ref = 0x0000000FUL;
        test_tmp_u32_mask = LASTBITMASK(test_tmp_u32_bits, uint32_t);
        cmp_result = (test_tmp_u32_ref == test_tmp_u32_mask);
        printf("LASTBITMASK(%u, uint32_t)=0x%08x, result: %s\r\n", test_tmp_u32_bits, test_tmp_u32_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);

        test_tmp_u32_bits = 99UL;
        test_tmp_u32_ref = 0x00000007UL;
        test_tmp_u32_mask = LASTBITMASK(test_tmp_u32_bits, uint32_t);
        cmp_result = (test_tmp_u32_ref == test_tmp_u32_mask);
        printf("LASTBITMASK(%u, uint32_t)=0x%08x, result: %s\r\n", test_tmp_u32_bits, test_tmp_u32_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);

        test_tmp_u32_bits = 98UL;
        test_tmp_u32_ref = 0x00000003UL;
        test_tmp_u32_mask = LASTBITMASK(test_tmp_u32_bits, uint32_t);
        cmp_result = (test_tmp_u32_ref == test_tmp_u32_mask);
        printf("LASTBITMASK(%u, uint32_t)=0x%08x, result: %s\r\n", test_tmp_u32_bits, test_tmp_u32_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);

        test_tmp_u32_bits = 97UL;
        test_tmp_u32_ref = 0x00000001UL;
        test_tmp_u32_mask = LASTBITMASK(test_tmp_u32_bits, uint32_t);
        cmp_result = (test_tmp_u32_ref == test_tmp_u32_mask);
        printf("LASTBITMASK(%u, uint32_t)=0x%08x, result: %s\r\n", test_tmp_u32_bits, test_tmp_u32_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);

        // uint64_t
        uint64_t test_tmp_u64_bits;
        uint64_t test_tmp_u64_mask;
        uint64_t test_tmp_u64_ref;

        test_tmp_u64_bits = 127UL;
        test_tmp_u64_ref = 0x7FFFFFFFFFFFFFFFUL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);

        test_tmp_u64_bits = 126UL;
        test_tmp_u64_ref = 0x3FFFFFFFFFFFFFFFUL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);

        test_tmp_u64_bits = 125UL;
        test_tmp_u64_ref = 0x1FFFFFFFFFFFFFFFUL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);

        test_tmp_u64_bits = 124UL;
        test_tmp_u64_ref = 0x0FFFFFFFFFFFFFFFUL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);

        test_tmp_u64_bits = 105UL;
        test_tmp_u64_ref = 0x000001FFFFFFFFFFUL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);

        test_tmp_u64_bits = 104UL;
        test_tmp_u64_ref = 0x000000FFFFFFFFFFUL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);

        test_tmp_u64_bits = 103UL;
        test_tmp_u64_ref = 0x0000007FFFFFFFFFUL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);

        test_tmp_u64_bits = 102UL;
        test_tmp_u64_ref = 0x0000003FFFFFFFFFUL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);

        test_tmp_u64_bits = 101UL;
        test_tmp_u64_ref = 0x0000001FFFFFFFFFUL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);

        test_tmp_u64_bits = 100UL;
        test_tmp_u64_ref = 0x0000000FFFFFFFFFUL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);

        test_tmp_u64_bits = 99UL;
        test_tmp_u64_ref = 0x00000007FFFFFFFFUL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);

        test_tmp_u64_bits = 98UL;
        test_tmp_u64_ref = 0x00000003FFFFFFFFUL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);

        test_tmp_u64_bits = 97UL;
        test_tmp_u64_ref = 0x00000001FFFFFFFFUL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);

        test_tmp_u64_bits = 69UL;
        test_tmp_u64_ref = 0x000000000000001FUL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);

        test_tmp_u64_bits = 68UL;
        test_tmp_u64_ref = 0x000000000000000FUL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);

        test_tmp_u64_bits = 67UL;
        test_tmp_u64_ref = 0x0000000000000007UL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);

        test_tmp_u64_bits = 66UL;
        test_tmp_u64_ref = 0x0000000000000003UL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);

        test_tmp_u64_bits = 65UL;
        test_tmp_u64_ref = 0x0000000000000001UL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));
        TEST_ASSERT(cmp_result);
    }

    // test: U16_SIZE(size)
    {
        size_t ref, r, n;
        size_t fail = 0u;
        printf("[TEST] U16_SIZE\r\n");

        for(n = 1u; n < 1024u; n++) {
            if(n % sizeof(uint16_t) != 0u) {
                ref = ((n - (n % sizeof(uint16_t))) + sizeof(uint16_t));
                r = U16_SIZE(n);
                if(ref != r) {
                    fail++;
                    printf("U16_SIZE(%lu), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));
                    break;
                }
            }
        }
        printf("U16_SIZE(%lu), fail count=%lu, result: %s\r\n", n, fail, (fail==0u)?("PASS"):("FAIL"));

        n = 4u;
        ref = 4u;
        r = U16_SIZE(n);
        printf("U16_SIZE(%lu)=%lu, result: %s\r\n", n, r, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        n = 5u;
        ref = 6u;
        r = U16_SIZE(n);
        printf("U16_SIZE(%lu)=%lu, result: %s\r\n", n, r, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        n = 6u;
        ref = 6u;
        r = U16_SIZE(n);
        printf("U16_SIZE(%lu)=%lu, result: %s\r\n", n, r, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        n = 7u;
        ref = 8u;
        r = U16_SIZE(n);
        printf("U16_SIZE(%lu)=%lu, result: %s\r\n", n, r, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        n = 8u;
        ref = 8u;
        r = U16_SIZE(n);
        printf("U16_SIZE(%lu)=%lu, result: %s\r\n", n, r, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);
    }

    // test: U32_SIZE(size)
    {
        size_t ref, r, n;
        size_t fail = 0u;
        printf("[TEST] U32_SIZE\r\n");

        for(n = 1u; n < 1024u; n++) {
            if(n % sizeof(uint32_t) != 0u) {
                ref = ((n - (n % sizeof(uint32_t))) + sizeof(uint32_t));
                r = U32_SIZE(n);
                if(ref != r) {
                    fail++;
                    printf("U32_SIZE(%lu), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));
                    break;
                }
            }
        }
        printf("U32_SIZE(%lu), fail count=%lu, result: %s\r\n", n, fail, (fail==0u)?("PASS"):("FAIL"));

        n = 15u;
        ref = 16u;
        r = U32_SIZE(n);
        printf("U32_SIZE(%lu)=%lu, result: %s\r\n", n, r, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        n = 16u;
        ref = 16u;
        r = U32_SIZE(n);
        printf("U32_SIZE(%lu)=%lu, result: %s\r\n", n, r, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        n = 17u;
        ref = 20u;
        r = U32_SIZE(n);
        printf("U32_SIZE(%lu)=%lu, result: %s\r\n", n, r, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);
    }

    // test: U64_SIZE(size)
    {
        size_t ref, r, n;
        size_t fail = 0u;
        printf("[TEST] U64_SIZE\r\n");

        for(n = 1u; n < 1024u; n++) {
            if(n % sizeof(uint64_t) != 0u) {
                ref = ((n - (n % sizeof(uint64_t))) + sizeof(uint64_t));
                r = U64_SIZE(n);
                if(ref != r) {
                    fail++;
                    printf("U64_SIZE(%lu), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));
                    break;
                }
            }
        }
        printf("U64_SIZE(%lu), fail count=%lu, result: %s\r\n", n, fail, (fail==0u)?("PASS"):("FAIL"));

        n = 15u;
        ref = 16u;
        r = U64_SIZE(n);
        printf("U64_SIZE(%lu)=%lu, result: %s\r\n", n, r, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        n = 16u;
        ref = 16u;
        r = U64_SIZE(n);
        printf("U64_SIZE(%lu)=%lu, result: %s\r\n", n, r, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);

        n = 17u;
        ref = 24u;
        r = U64_SIZE(n);
        printf("U64_SIZE(%lu)=%lu, result: %s\r\n", n, r, (ref==r)?("PASS"):("FAIL"));
        TEST_ASSERT(ref==r);
    }
}

void test_ntype(void) {
    ntype_s* p = (ntype_s*)NULL;

    size_t test_bits, test_size;
    int test_cmp_bits, test_cmp_size;

    {
        test_bits = 1ul;
        test_size = UIN_CEIL(test_bits, 8u);
        p = mkNum(test_bits);
        if(test_bits == p->bits)    test_cmp_bits = 0;
        else                        test_cmp_bits = -1;
        if(test_size == p->size)    test_cmp_size = 0;
        else                        test_cmp_size = -1;
        printf("(ntype_s*):0x%p, bitLen:%lu[bit]:%s, size:%lu[Bytes]:%s\r\n", p,
            p->bits, (test_cmp_bits == 0)?"PASS":"FAIL", \
            p->size, (test_cmp_size == 0)?"PASS":"FAIL");
        rmNum(&p);
        TEST_ASSERT(test_cmp_bits == 0);
        TEST_ASSERT(test_cmp_size == 0);

        test_bits = 8ul - 1ul;
        test_size = UIN_CEIL(test_bits, 8u);
        p = mkNum(test_bits);
        if(test_bits == p->bits)    test_cmp_bits = 0;
        else                        test_cmp_bits = -1;
        if(test_size == p->size)    test_cmp_size = 0;
        else                        test_cmp_size = -1;
        printf("(ntype_s*):0x%p, bitLen:%lu[bit]:%s, size:%lu[Bytes]:%s\r\n", p,
            p->bits, (test_cmp_bits == 0)?"PASS":"FAIL", \
            p->size, (test_cmp_size == 0)?"PASS":"FAIL");
        rmNum(&p);
        TEST_ASSERT(test_cmp_bits == 0);
        TEST_ASSERT(test_cmp_size == 0);

        test_bits = 8ul;
        test_size = UIN_CEIL(test_bits, 8u);
        p = mkNum(test_bits);
        if(test_bits == p->bits)    test_cmp_bits = 0;
        else                        test_cmp_bits = -1;
        if(test_size == p->size)    test_cmp_size = 0;
        else                        test_cmp_size = -1;
        printf("(ntype_s*):0x%p, bitLen:%lu[bit]:%s, size:%lu[Bytes]:%s\r\n", p,
            p->bits, (test_cmp_bits == 0)?"PASS":"FAIL", \
            p->size, (test_cmp_size == 0)?"PASS":"FAIL");
        rmNum(&p);
        TEST_ASSERT(test_cmp_bits == 0);
        TEST_ASSERT(test_cmp_size == 0);

        test_bits = 8ul + 1ul;
        test_size = UIN_CEIL(test_bits, 8u);
        p = mkNum(test_bits);
        if(test_bits == p->bits)    test_cmp_bits = 0;
        else                        test_cmp_bits = -1;
        if(test_size == p->size)    test_cmp_size = 0;
        else                        test_cmp_size = -1;
        printf("(ntype_s*):0x%p, bitLen:%lu[bit]:%s, size:%lu[Bytes]:%s\r\n", p,
            p->bits, (test_cmp_bits == 0)?"PASS":"FAIL", \
            p->size, (test_cmp_size == 0)?"PASS":"FAIL");
        rmNum(&p);
        TEST_ASSERT(test_cmp_bits == 0);
        TEST_ASSERT(test_cmp_size == 0);

        test_bits = 16ul - 1ul;
        test_size = UIN_CEIL(test_bits, 8u);
        p = mkNum(test_bits);
        if(test_bits == p->bits)    test_cmp_bits = 0;
        else                        test_cmp_bits = -1;
        if(test_size == p->size)    test_cmp_size = 0;
        else                        test_cmp_size = -1;
        printf("(ntype_s*):0x%p, bitLen:%lu[bit]:%s, size:%lu[Bytes]:%s\r\n", p,
            p->bits, (test_cmp_bits == 0)?"PASS":"FAIL", \
            p->size, (test_cmp_size == 0)?"PASS":"FAIL");
        rmNum(&p);
        TEST_ASSERT(test_cmp_bits == 0);
        TEST_ASSERT(test_cmp_size == 0);

        test_bits = 16ul;
        test_size = UIN_CEIL(test_bits, 8u);
        p = mkNum(test_bits);
        if(test_bits == p->bits)    test_cmp_bits = 0;
        else                        test_cmp_bits = -1;
        if(test_size == p->size)    test_cmp_size = 0;
        else                        test_cmp_size = -1;
        printf("(ntype_s*):0x%p, bitLen:%lu[bit]:%s, size:%lu[Bytes]:%s\r\n", p,
            p->bits, (test_cmp_bits == 0)?"PASS":"FAIL", \
            p->size, (test_cmp_size == 0)?"PASS":"FAIL");
        rmNum(&p);
        TEST_ASSERT(test_cmp_bits == 0);
        TEST_ASSERT(test_cmp_size == 0);

        test_bits = 16ul + 1ul;
        test_size = UIN_CEIL(test_bits, 8u);
        p = mkNum(test_bits);
        if(test_bits == p->bits)    test_cmp_bits = 0;
        else                        test_cmp_bits = -1;
        if(test_size == p->size)    test_cmp_size = 0;
        else                        test_cmp_size = -1;
        printf("(ntype_s*):0x%p, bitLen:%lu[bit]:%s, size:%lu[Bytes]:%s\r\n", p,
            p->bits, (test_cmp_bits == 0)?"PASS":"FAIL", \
            p->size, (test_cmp_size == 0)?"PASS":"FAIL");
        rmNum(&p);
        TEST_ASSERT(test_cmp_bits == 0);
        TEST_ASSERT(test_cmp_size == 0);

        test_bits = 512ul - 1ul;
        test_size = UIN_CEIL(test_bits, 8u);
        p = mkNum(test_bits);
        if(test_bits == p->bits)    test_cmp_bits = 0;
        else                        test_cmp_bits = -1;
        if(test_size == p->size)    test_cmp_size = 0;
        else                        test_cmp_size = -1;
        printf("(ntype_s*):0x%p, bitLen:%lu[bit]:%s, size:%lu[Bytes]:%s\r\n", p,
            p->bits, (test_cmp_bits == 0)?"PASS":"FAIL", \
            p->size, (test_cmp_size == 0)?"PASS":"FAIL");
        rmNum(&p);
        TEST_ASSERT(test_cmp_bits == 0);
        TEST_ASSERT(test_cmp_size == 0);

        test_bits = 512ul;
        test_size = UIN_CEIL(test_bits, 8u);
        p = mkNum(test_bits);
        if(test_bits == p->bits)    test_cmp_bits = 0;
        else                        test_cmp_bits = -1;
        if(test_size == p->size)    test_cmp_size = 0;
        else                        test_cmp_size = -1;
        printf("(ntype_s*):0x%p, bitLen:%lu[bit]:%s, size:%lu[Bytes]:%s\r\n", p,
            p->bits, (test_cmp_bits == 0)?"PASS":"FAIL", \
            p->size, (test_cmp_size == 0)?"PASS":"FAIL");
        rmNum(&p);
        TEST_ASSERT(test_cmp_bits == 0);
        TEST_ASSERT(test_cmp_size == 0);

        test_bits = 512ul + 1ul;
        test_size = UIN_CEIL(test_bits, 8u);
        p = mkNum(test_bits);
        if(test_bits == p->bits)    test_cmp_bits = 0;
        else                        test_cmp_bits = -1;
        if(test_size == p->size)    test_cmp_size = 0;
        else                        test_cmp_size = -1;
        printf("(ntype_s*):0x%p, bitLen:%lu[bit]:%s, size:%lu[Bytes]:%s\r\n", p,
            p->bits, (test_cmp_bits == 0)?"PASS":"FAIL", \
            p->size, (test_cmp_size == 0)?"PASS":"FAIL");
        rmNum(&p);
        TEST_ASSERT(test_cmp_bits == 0);
        TEST_ASSERT(test_cmp_size == 0);

        test_bits = 1023ul;
        test_size = UIN_CEIL(test_bits, 8u);
        p = mkNum(test_bits);
        if(test_bits == p->bits)    test_cmp_bits = 0;
        else                        test_cmp_bits = -1;
        if(test_size == p->size)    test_cmp_size = 0;
        else                        test_cmp_size = -1;
        printf("(ntype_s*):0x%p, bitLen:%lu[bit]:%s, size:%lu[Bytes]:%s\r\n", p,
            p->bits, (test_cmp_bits == 0)?"PASS":"FAIL", \
            p->size, (test_cmp_size == 0)?"PASS":"FAIL");
        rmNum(&p);
        TEST_ASSERT(test_cmp_bits == 0);
        TEST_ASSERT(test_cmp_size == 0);
    }

    for(uint32_t tmp_bitLen = 1ul; tmp_bitLen < 20480ul; tmp_bitLen++) {
        test_bits = tmp_bitLen;
        test_size = UIN_CEIL(test_bits, 8u);
        p = mkNum(test_bits);
        if(test_bits == p->bits)    test_cmp_bits = 0;
        else                        test_cmp_bits = -1;
        if(test_size == p->size)    test_cmp_size = 0;
        else                        test_cmp_size = -1;
        printf("(ntype_s*):0x%p, bitLen:%lu[bit]:%s, size:%lu[Bytes]:%s\r\n", p,
            p->bits, (test_cmp_bits == 0)?"PASS":"FAIL", \
            p->size, (test_cmp_size == 0)?"PASS":"FAIL");
        rmNum(&p);
        TEST_ASSERT(test_cmp_bits == 0);
        TEST_ASSERT(test_cmp_size == 0);

        if((test_cmp_bits != 0) || (test_cmp_size != 0)) {
            printf("config:bitLength=%lu,arrayLength=%lu\r\n", test_bits, test_size);
            break;
        } else {}
    }
}

#define TEST_ARITH_BITS 127u    //16Bytes
void test_arith_add(void) {
    int test_cmp;

    ntype_s* test_ref;
    ntype_s* test_dst;
    ntype_s* test_opA;
    ntype_s* test_opB;

    test_ref = mkNum(TEST_ARITH_BITS);
    test_dst = mkNum(TEST_ARITH_BITS);
    test_opA = mkNum(TEST_ARITH_BITS);
    test_opB = mkNum(TEST_ARITH_BITS);

    /* Sum test */
    for(unsigned int i = 0u; i < TV_U32_ADD_NUM; i++) {
        memset(test_ref->data, 0x0u, (test_ref->size));
        memset(test_opA->data, 0x0u, (test_opA->size));
        memset(test_opB->data, 0x0u, (test_opB->size));

        memcpy(test_ref->data, TV_u32_add_refList[i], TV_u32_add_lenList[i]);
        memcpy(test_opA->data, TV_u32_add_opAList[i], TV_u32_add_lenList[i]);
        memcpy(test_opB->data, TV_u32_add_opBList[i], TV_u32_add_lenList[i]);

        TICK_TIME_START("add_NTYPE");
        add_NTYPE(test_dst, test_opA, test_opB, TV_u32_add_carryList[i]);
        TICK_TIME_END;
        test_print_ntype(test_opA, "opA");
        test_print_ntype(test_opB, "opB");
        test_print_ntype(test_dst, "dst");
        test_print_ntype(test_ref, "ref");
        printf("[carry]\r\nc=0x%08x\r\n", TV_u32_add_carryList[i]);

        test_cmp = memcmp(test_ref->data, test_dst->data, (test_ref->size));
        printf("add_NTYPE() is %s\r\n", ((test_cmp == 0)?"PASS":"FAIL"));
        TEST_ASSERT(test_cmp == 0);
    }

    rmNum(&test_ref);
    rmNum(&test_dst);
    rmNum(&test_opA);
    rmNum(&test_opB);
}

void test_arith_sub(void) {
    int test_cmp;

    ntype_s* test_ref;
    ntype_s* test_dst;
    ntype_s* test_opA;
    ntype_s* test_opB;

    test_ref = mkNum(TEST_ARITH_BITS);
    test_dst = mkNum(TEST_ARITH_BITS);
    test_opA = mkNum(TEST_ARITH_BITS);
    test_opB = mkNum(TEST_ARITH_BITS);

    /* Sum test */
    for(unsigned int i = 0u; i < TV_U32_SUB_NUM; i++) {
        memset(test_ref->data, 0x0u, (test_ref->size));
        memset(test_opA->data, 0x0u, (test_opA->size));
        memset(test_opB->data, 0x0u, (test_opB->size));

        memcpy(test_ref->data, TV_u32_sub_refList[i], TV_u32_sub_lenList[i]);
        memcpy(test_opA->data, TV_u32_sub_opAList[i], TV_u32_sub_lenList[i]);
        memcpy(test_opB->data, TV_u32_sub_opBList[i], TV_u32_sub_lenList[i]);

        TICK_TIME_START("sub_NTYPE");
        sub_NTYPE(test_dst, test_opA, test_opB, TV_u32_sub_carryList[i]);
        TICK_TIME_END;
        test_print_ntype(test_opA, "opA");
        test_print_ntype(test_opB, "opB");
        test_print_ntype(test_dst, "dst");
        test_print_ntype(test_ref, "ref");
        printf("[carry]\r\nc=0x%08x\r\n", TV_u32_sub_carryList[i]);

        test_cmp = memcmp(test_ref->data, test_dst->data, (test_ref->size));
        printf("sub_NTYPE() is %s\r\n", ((test_cmp == 0)?"PASS":"FAIL"));
        TEST_ASSERT(test_cmp == 0);
    }

    rmNum(&test_ref);
    rmNum(&test_dst);
    rmNum(&test_opA);
    rmNum(&test_opB);
}

#define TEST_ARITH_MUL_U32_BS_BIT  1024U
void test_arith_mul_u32_bs(void) {
    int test_cmp;

    ntype_s* test_ref = mkNum(TEST_ARITH_MUL_U32_BS_BIT<<1U);
    ntype_s* test_opA = mkNum(TEST_ARITH_MUL_U32_BS_BIT<<0U);
    ntype_s* test_opB = mkNum(TEST_ARITH_MUL_U32_BS_BIT<<0U);
    ntype_s* test_dst = mkNum(TEST_ARITH_MUL_U32_BS_BIT<<1U);

    /****************/
    /* TestVector 1 */
    (void)memset(test_ref->data, 0U, test_ref->size);
    (void)memset(test_opA->data, 0U, test_opA->size);
    (void)memset(test_opB->data, 0U, test_opB->size);
    (void)memset(test_dst->data, 0U, test_dst->size);

    // set operand A
    test_opA->data[0] = 0xffffffffU;
    test_opA->data[1] = 0xffffffffU;

    // set operand B
    test_opB->data[0] = 0xffffffffU;
    test_opB->data[1] = 0xffffffffU;

    // set reference
    test_ref->data[0] = 0x00000001U;
    test_ref->data[1] = 0x00000000U;
    test_ref->data[2] = 0xfffffffeU;
    test_ref->data[3] = 0xffffffffU;

    TICK_TIME_START("mul_NTYPE_bs");
    mul_NTYPE_bs(test_dst, test_opA, test_opB);
    TICK_TIME_END;
    test_print_ntype(test_opA, "opA");
    test_print_ntype(test_opB, "opB");
    test_print_ntype(test_dst, "dst");
    test_print_ntype(test_ref, "ref");

    test_cmp = memcmp(test_ref->data, test_dst->data, (test_ref->size));
    printf("mul_NTYPE_bs() is %s\r\n", ((test_cmp == 0)?"PASS":"FAIL"));
    TEST_ASSERT(test_cmp == 0);

    /****************/
    /* TestVector 2 */
    (void)memset(test_ref->data, 0U, test_ref->size);
    (void)memset(test_opA->data, 0U, test_opA->size);
    (void)memset(test_opB->data, 0U, test_opB->size);
    (void)memset(test_dst->data, 0U, test_dst->size);

    // set operand A
    test_opA->data[0] = 0xffffffffU;
    test_opA->data[1] = 0xffffffffU;
    test_opA->data[2] = 0xffffffffU;
    test_opA->data[3] = 0xffffffffU;

    // set operand B
    test_opB->data[0] = 0xffffffffU;
    test_opB->data[1] = 0xffffffffU;
    test_opB->data[2] = 0xffffffffU;
    test_opB->data[3] = 0xffffffffU;

    // set reference
    test_ref->data[0] = 0x00000001U;
    test_ref->data[1] = 0x00000000U;
    test_ref->data[2] = 0x00000000U;
    test_ref->data[3] = 0x00000000U;
    test_ref->data[4] = 0xfffffffeU;
    test_ref->data[5] = 0xffffffffU;
    test_ref->data[6] = 0xffffffffU;
    test_ref->data[7] = 0xffffffffU;

    TICK_TIME_START("mul_NTYPE_bs");
    mul_NTYPE_bs(test_dst, test_opA, test_opB);
    TICK_TIME_END;
    test_print_ntype(test_opA, "opA");
    test_print_ntype(test_opB, "opB");
    test_print_ntype(test_dst, "dst");
    test_print_ntype(test_ref, "ref");

    test_cmp = memcmp(test_ref->data, test_dst->data, (test_ref->size));
    printf("mul_NTYPE_bs() is %s\r\n", ((test_cmp == 0)?"PASS":"FAIL"));
    TEST_ASSERT(test_cmp == 0);

    /****************/
    /* TestVector 3 */
    (void)memset(test_ref->data, 0U, test_ref->size);
    (void)memset(test_opA->data, 0U, test_opA->size);
    (void)memset(test_opB->data, 0U, test_opB->size);
    (void)memset(test_dst->data, 0U, test_dst->size);

    // set operand A
    test_opA->data[0]  = 0xffffffffU;
    test_opA->data[1]  = 0xffffffffU;
    test_opA->data[2]  = 0xffffffffU;
    test_opA->data[3]  = 0xffffffffU;
    test_opA->data[4]  = 0xffffffffU;

    // set operand B
    test_opB->data[0]  = 0xffffffffU;
    test_opB->data[1]  = 0xffffffffU;
    test_opB->data[2]  = 0xffffffffU;
    test_opB->data[3]  = 0xffffffffU;
    test_opB->data[4]  = 0xffffffffU;
    test_opB->data[5]  = 0xffffffffU;

    // set reference
    test_ref->data[0]  = 0x00000001U;
    test_ref->data[1]  = 0x00000000U;
    test_ref->data[2]  = 0x00000000U;
    test_ref->data[3]  = 0x00000000U;
    test_ref->data[4]  = 0x00000000U;
    test_ref->data[5]  = 0xffffffffU;
    test_ref->data[6]  = 0xfffffffeU;
    test_ref->data[7]  = 0xffffffffU;
    test_ref->data[8]  = 0xffffffffU;
    test_ref->data[9]  = 0xffffffffU;
    test_ref->data[10] = 0xffffffffU;

    TICK_TIME_START("mul_NTYPE_bs");
    mul_NTYPE_bs(test_dst, test_opA, test_opB);
    TICK_TIME_END;
    test_print_ntype(test_opA, "opA");
    test_print_ntype(test_opB, "opB");
    test_print_ntype(test_dst, "dst");
    test_print_ntype(test_ref, "ref");

    test_cmp = memcmp(test_ref->data, test_dst->data, (test_ref->size));
    printf("mul_NTYPE_bs() is %s\r\n", ((test_cmp == 0)?"PASS":"FAIL"));
    TEST_ASSERT(test_cmp == 0);

    /****************/
    /* TestVector 4 */
    (void)memset(test_ref->data, 0U, test_ref->size);
    (void)memset(test_opA->data, 0U, test_opA->size);
    (void)memset(test_opB->data, 0U, test_opB->size);
    (void)memset(test_dst->data, 0U, test_dst->size);

    // set operand A
    test_opA->data[0]  = 0xffffffffU;
    test_opA->data[1]  = 0xffffffffU;
    test_opA->data[2]  = 0xffffffffU;
    test_opA->data[3]  = 0xffffffffU;
    test_opA->data[4]  = 0xffffffffU;
    test_opA->data[5]  = 0x0fffffffU;

    // set operand B
    test_opB->data[0]  = 0xffffffffU;
    test_opB->data[1]  = 0xffffffffU;
    test_opB->data[2]  = 0xffffffffU;
    test_opB->data[3]  = 0xffffffffU;
    test_opB->data[4]  = 0xffffffffU;
    test_opB->data[5]  = 0xffffffffU;
    test_opB->data[6]  = 0xffffffffU;

    // set reference
    test_ref->data[0]  = 0x00000001U;
    test_ref->data[1]  = 0x00000000U;
    test_ref->data[2]  = 0x00000000U;
    test_ref->data[3]  = 0x00000000U;
    test_ref->data[4]  = 0x00000000U;
    test_ref->data[5]  = 0xf0000000U;
    test_ref->data[6]  = 0xffffffffU;
    test_ref->data[7]  = 0xfffffffeU;
    test_ref->data[8]  = 0xffffffffU;
    test_ref->data[9]  = 0xffffffffU;
    test_ref->data[10] = 0xffffffffU;
    test_ref->data[11] = 0xffffffffU;
    test_ref->data[12] = 0x0fffffffU;

    TICK_TIME_START("mul_NTYPE_bs");
    mul_NTYPE_bs(test_dst, test_opA, test_opB);
    TICK_TIME_END;
    test_print_ntype(test_opA, "opA");
    test_print_ntype(test_opB, "opB");
    test_print_ntype(test_dst, "dst");
    test_print_ntype(test_ref, "ref");

    test_cmp = memcmp(test_ref->data, test_dst->data, (test_ref->size));
    printf("mul_NTYPE_bs() is %s\r\n", ((test_cmp == 0)?"PASS":"FAIL"));
    TEST_ASSERT(test_cmp == 0);

    rmNum(&test_ref);
    rmNum(&test_opA);
    rmNum(&test_opB);
    rmNum(&test_dst);
}

#define TEST_ARITH_MUL_u32_bs_NN_BIT       512U
void test_arith_mul_u32_bs_nn(void) {
    int test_cmp;
    ReturnType fr;

    ntype_s* test_ref = mkNum(TEST_ARITH_MUL_u32_bs_NN_BIT);
    ntype_s* test_opA = mkNum(TEST_ARITH_MUL_u32_bs_NN_BIT);
    ntype_s* test_opB = mkNum(TEST_ARITH_MUL_u32_bs_NN_BIT);
    ntype_s* test_dst = mkNum(TEST_ARITH_MUL_u32_bs_NN_BIT);

    /****************/
    /* TestVector 1, Negative x Negative */
    (void)memset(test_ref->data, 0U,    test_ref->size);
    (void)memset(test_opA->data, 0xffU, test_opA->size);
    (void)memset(test_opB->data, 0xffU, test_opB->size);
    (void)memset(test_dst->data, 0U,    test_dst->size);

    // set operand A -> -1
    //test_opA->data[0];

    // set operand B
    //test_opB->data[0];

    // set reference
    test_ref->data[0]  = 0x00000001U;

    if(fr = mul_NTYPE_bs_ext(test_dst, test_opA, test_opB, false)) {
        printReturnType(fr);
    } else { /* Do nothing */ }
    test_print_ntype(test_opA, "opA");
    test_print_ntype(test_opB, "opB");
    test_print_ntype(test_dst, "dst");
    test_print_ntype(test_ref, "ref");

    test_cmp = memcmp(test_ref->data, test_dst->data, (test_ref->size));
    printf("mul_NTYPE_bs() is %s\r\n", ((test_cmp == 0)?"PASS":"FAIL"));
    TEST_ASSERT(test_cmp == 0);

    rmNum(&test_ref);
    rmNum(&test_opA);
    rmNum(&test_opB);
    rmNum(&test_dst);
}

#define TEST_LOGIC_SHIFT_ONE_BIT    1024U
#define TEST_LOGIC_SHIFT_REF        0x08108051U
#define TEST_LOGIC_SHIFT_VAL        0x84084028U

void test_logic_shft(void) {
    int test_cmp;
    ReturnType fr;

    ntype_s* test_refer;
    ntype_s* test_sft1b;
    NTYPE test_ovf;

    test_refer = mkNum(TEST_LOGIC_SHIFT_ONE_BIT);
    test_sft1b = mkNum(TEST_LOGIC_SHIFT_ONE_BIT);

    /* Shift sequence 1 */
    (void)memset(test_refer->data, 0x0U, test_refer->size);
    (void)memset(test_sft1b->data, 0x0U, test_sft1b->size);

    // set reference
    test_refer->data[0] = 0x2U;

    // set init vector
    test_sft1b->data[0] = 0x1U;

    test_print_ntype(test_sft1b, "sft1b(before)");
    // run test function
    TICK_TIME_START("sftL1b");
    if(fr = sftL1b(test_sft1b, &test_ovf, 0U)) {
        TICK_TIME_END;
        printf("sftL1b(test_sft1b, &test_ovf) = %d\r\n", fr);
    } else {
        TICK_TIME_END;
    }

    test_cmp = memcmp(test_refer->data, test_sft1b->data, (test_refer->size));
    test_print_ntype(test_refer, "refer");
    test_print_ntype(test_sft1b, "sft1b(after)");
    printf("sftL1b() is %s\r\n", ((test_cmp == 0)?"PASS":"FAIL"));
    TEST_ASSERT(test_cmp == 0);

    /* Shift sequence 2 */
    (void)memset(test_refer->data, 0x0U, test_refer->size);
    (void)memset(test_sft1b->data, 0x0U, test_sft1b->size);

    // set reference
    for(size_t i = 0U; i < test_refer->length; i++) {
        test_refer->data[i] = TEST_LOGIC_SHIFT_REF;
    }

    // set init vector
    for(size_t i = 0U; i < test_sft1b->length; i++) {
        test_sft1b->data[i] = TEST_LOGIC_SHIFT_VAL;
    }

    test_print_ntype(test_sft1b, "sft1b(before)");
    // run test function
    TICK_TIME_START("sftL1b");
    if(fr = sftL1b(test_sft1b, &test_ovf, 1U)) {
        TICK_TIME_END;
        printf("sftL1b(test_sft1b, &test_ovf) = %d\r\n", fr);
    } else {
        TICK_TIME_END;
    }

    test_cmp = memcmp(test_refer->data, test_sft1b->data, (test_refer->size));
    test_print_ntype(test_refer, "refer");
    test_print_ntype(test_sft1b, "sft1b(after)");
    printf("sftL1b() is %s\r\n", ((test_cmp == 0)?"PASS":"FAIL"));

}

void test_sequence(void) {
    printf("[test start: test_macro()]\r\n");
    test_macro();
    printf("[test   end: test_macro()]\r\n");

#if 0   /* CONFIG_DO_TEST_NTYPE */
    printf("[test start: test_ntype()]\r\n");
    test_ntype();
    printf("[test   end: test_ntype()]\r\n");
#endif  /* CONFIG_DO_TEST_NTYPE */

    /******************************/
    printf("[test start: test_arith_add()]\r\n");
    test_arith_add();
    printf("[test   end: test_arith_add()]\r\n");

    printf("[test start: test_arith_sub()]\r\n");
    test_arith_sub();
    printf("[test   end: test_arith_sub()]\r\n");

    printf("[test start: test_arith_mul_u32_bs()]\r\n");
    test_arith_mul_u32_bs();
    printf("[test   end: test_arith_mul_u32_bs()]\r\n");

    printf("[test start: test_arith_mul_u32_bs_nn()]\r\n");
    test_arith_mul_u32_bs_nn();
    printf("[test   end: test_arith_mul_u32_bs_nn()]\r\n");

    /******************************/
    printf("[test start: test_logic_shft()]\r\n");
    printf("[test   end: test_logic_shft()]\r\n");
    test_logic_shft();
}

#define TEST_MUL_COUNT_TIME_LOOPS   102400000UL
void test_u32_u64_mul_time(void) {
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
}

int main(int argc, char** argv) {
    printf("arg:%d, ",argc);
    for(unsigned int i=0; i<argc; i++) {
        printf("arg[%d]:%s, ", i, argv[i]);
    }
    printf("\r\n");

    test_sequence();

    test_u32_u64_mul_time();
}
