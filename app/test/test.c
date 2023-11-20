#include <time.h>

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <sys/sysinfo.h>

#include "common/util.h"
#include "common/ntype.h"
#include "common/returnType.h"

#include "arith/arith_core.h"
#include "logic/logic_core.h"

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

        // test 2
        n = 14u; m = 14u;
        ref = 1u;
        r = UIN_CEIL(n, m);
        printf("n=%u, m=%u, r=%u\r\n", n, m, r);
        printf("UIN_CEIL(%u, %u), result: %s\r\n", n, m, (ref==r)?("PASS"):("FAIL"));

        // test 3
        n = 1024u; m = 1023u;
        ref = 2u;
        r = UIN_CEIL(n, m);
        printf("n=%u, m=%u, r=%u\r\n", n, m, r);
        printf("UIN_CEIL(%u, %u), result: %s\r\n", n, m, (ref==r)?("PASS"):("FAIL"));

        // test 4
        n = 34u + 7u; m = 17u;
        ref = 3u;
        r = UIN_CEIL(n, m);
        printf("n=%u, m=%u, r=%u\r\n", n, m, r);
        printf("UIN_CEIL(%u, %u), result: %s\r\n", n, m, (ref==r)?("PASS"):("FAIL"));

        // test 5
        n = 60u + 14u; m = 37u;
        ref = 2u;
        r = UIN_CEIL(n, m);
        printf("n=%u, m=%u, r=%u\r\n", n, m, r);
        printf("UIN_CEIL(%u, %u), result: %s\r\n", n, m, (ref==r)?("PASS"):("FAIL"));

        // test 6
        n = 35u + 6u; m = 7u;
        ref = 6u;
        r = UIN_CEIL(n, m);
        printf("n=%u, m=%u, r=%u\r\n", n, m, r);
        printf("UIN_CEIL(%u, %u), result: %s\r\n", n, m, (ref==r)?("PASS"):("FAIL"));

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

        // test 2
        n = 14; m = 14;
        ref = 1;
        r = INT_CEIL(n, m);
        printf("n=%u, m=%u, r=%u\r\n", n, m, r);
        printf("INT_CEIL(%u, %u), result: %s\r\n", n, m, (ref==r)?("PASS"):("FAIL"));

        // test 3
        n = 1024; m = 1023;
        ref = 2;
        r = INT_CEIL(n, m);
        printf("n=%u, m=%u, r=%u\r\n", n, m, r);
        printf("INT_CEIL(%u, %u), result: %s\r\n", n, m, (ref==r)?("PASS"):("FAIL"));

        // test 4
        n = 34u + 7; m = 17;
        ref = 3;
        r = INT_CEIL(n, m);
        printf("n=%u, m=%u, r=%u\r\n", n, m, r);
        printf("INT_CEIL(%u, %u), result: %s\r\n", n, m, (ref==r)?("PASS"):("FAIL"));

        // test 5
        n = 60u + 14; m = 37;
        ref = 2;
        r = INT_CEIL(n, m);
        printf("n=%u, m=%u, r=%u\r\n", n, m, r);
        printf("INT_CEIL(%u, %u), result: %s\r\n", n, m, (ref==r)?("PASS"):("FAIL"));

        // test 6
        n = 35u + 6; m = 7;
        ref = 6;
        r = INT_CEIL(n, m);
        printf("n=%u, m=%u, r=%u\r\n", n, m, r);
        printf("INT_CEIL(%u, %u), result: %s\r\n", n, m, (ref==r)?("PASS"):("FAIL"));

    }

    // test: BIT2SIZE(bits)
    {
        uint32_t ref, r, n;
        printf("[TEST] BIT2SIZE\r\n");

        // test 1
        n = 6u;
        ref = 1u;
        r = BIT2SIZE(n);
        printf("n=%u, r=%u\r\n", n, r);
        printf("BIT2SIZE(%u), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));

        // test 2
        n = 14u;
        ref = 2u;
        r = BIT2SIZE(n);
        printf("n=%u, r=%u\r\n", n, r);
        printf("BIT2SIZE(%u), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));

        // test 3
        n = 1024u;
        ref = 128u;
        r = BIT2SIZE(n);
        printf("n=%u, r=%u\r\n", n, r);
        printf("BIT2SIZE(%u), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));

        // test 4
        n = 10240u;
        ref = 1280u;
        r = BIT2SIZE(n);
        printf("n=%u, r=%u\r\n", n, r);
        printf("BIT2SIZE(%u), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));

        // test 5
        n = 10241u;
        ref = 1281u;
        r = BIT2SIZE(n);
        printf("n=%u, r=%u\r\n", n, r);
        printf("BIT2SIZE(%u), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));

        // test 6
        n = 727u;
        ref = 91u;
        r = BIT2SIZE(n);
        printf("n=%u, r=%u\r\n", n, r);
        printf("BIT2SIZE(%u), result: %s\r\n", n, (ref==r)?("PASS"):("FAIL"));

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

        test_tmp_u32_bits = 126UL;
        test_tmp_u32_ref = 0x3FFFFFFFUL;
        test_tmp_u32_mask = LASTBITMASK(test_tmp_u32_bits, uint32_t);
        cmp_result = (test_tmp_u32_ref == test_tmp_u32_mask);
        printf("LASTBITMASK(%u, uint32_t)=0x%08x, result: %s\r\n", test_tmp_u32_bits, test_tmp_u32_mask, (cmp_result)?("PASS"):("FAIL"));

        test_tmp_u32_bits = 125UL;
        test_tmp_u32_ref = 0x1FFFFFFFUL;
        test_tmp_u32_mask = LASTBITMASK(test_tmp_u32_bits, uint32_t);
        cmp_result = (test_tmp_u32_ref == test_tmp_u32_mask);
        printf("LASTBITMASK(%u, uint32_t)=0x%08x, result: %s\r\n", test_tmp_u32_bits, test_tmp_u32_mask, (cmp_result)?("PASS"):("FAIL"));

        test_tmp_u32_bits = 124UL;
        test_tmp_u32_ref = 0x0FFFFFFFUL;
        test_tmp_u32_mask = LASTBITMASK(test_tmp_u32_bits, uint32_t);
        cmp_result = (test_tmp_u32_ref == test_tmp_u32_mask);
        printf("LASTBITMASK(%u, uint32_t)=0x%08x, result: %s\r\n", test_tmp_u32_bits, test_tmp_u32_mask, (cmp_result)?("PASS"):("FAIL"));

        test_tmp_u32_bits = 105UL;
        test_tmp_u32_ref = 0x000001FFUL;
        test_tmp_u32_mask = LASTBITMASK(test_tmp_u32_bits, uint32_t);
        cmp_result = (test_tmp_u32_ref == test_tmp_u32_mask);
        printf("LASTBITMASK(%u, uint32_t)=0x%08x, result: %s\r\n", test_tmp_u32_bits, test_tmp_u32_mask, (cmp_result)?("PASS"):("FAIL"));

        test_tmp_u32_bits = 104UL;
        test_tmp_u32_ref = 0x000000FFUL;
        test_tmp_u32_mask = LASTBITMASK(test_tmp_u32_bits, uint32_t);
        cmp_result = (test_tmp_u32_ref == test_tmp_u32_mask);
        printf("LASTBITMASK(%u, uint32_t)=0x%08x, result: %s\r\n", test_tmp_u32_bits, test_tmp_u32_mask, (cmp_result)?("PASS"):("FAIL"));

        test_tmp_u32_bits = 103UL;
        test_tmp_u32_ref = 0x0000007FUL;
        test_tmp_u32_mask = LASTBITMASK(test_tmp_u32_bits, uint32_t);
        cmp_result = (test_tmp_u32_ref == test_tmp_u32_mask);
        printf("LASTBITMASK(%u, uint32_t)=0x%08x, result: %s\r\n", test_tmp_u32_bits, test_tmp_u32_mask, (cmp_result)?("PASS"):("FAIL"));

        test_tmp_u32_bits = 102UL;
        test_tmp_u32_ref = 0x0000003FUL;
        test_tmp_u32_mask = LASTBITMASK(test_tmp_u32_bits, uint32_t);
        cmp_result = (test_tmp_u32_ref == test_tmp_u32_mask);
        printf("LASTBITMASK(%u, uint32_t)=0x%08x, result: %s\r\n", test_tmp_u32_bits, test_tmp_u32_mask, (cmp_result)?("PASS"):("FAIL"));

        test_tmp_u32_bits = 101UL;
        test_tmp_u32_ref = 0x0000001FUL;
        test_tmp_u32_mask = LASTBITMASK(test_tmp_u32_bits, uint32_t);
        cmp_result = (test_tmp_u32_ref == test_tmp_u32_mask);
        printf("LASTBITMASK(%u, uint32_t)=0x%08x, result: %s\r\n", test_tmp_u32_bits, test_tmp_u32_mask, (cmp_result)?("PASS"):("FAIL"));

        test_tmp_u32_bits = 100UL;
        test_tmp_u32_ref = 0x0000000FUL;
        test_tmp_u32_mask = LASTBITMASK(test_tmp_u32_bits, uint32_t);
        cmp_result = (test_tmp_u32_ref == test_tmp_u32_mask);
        printf("LASTBITMASK(%u, uint32_t)=0x%08x, result: %s\r\n", test_tmp_u32_bits, test_tmp_u32_mask, (cmp_result)?("PASS"):("FAIL"));

        test_tmp_u32_bits = 99UL;
        test_tmp_u32_ref = 0x00000007UL;
        test_tmp_u32_mask = LASTBITMASK(test_tmp_u32_bits, uint32_t);
        cmp_result = (test_tmp_u32_ref == test_tmp_u32_mask);
        printf("LASTBITMASK(%u, uint32_t)=0x%08x, result: %s\r\n", test_tmp_u32_bits, test_tmp_u32_mask, (cmp_result)?("PASS"):("FAIL"));

        test_tmp_u32_bits = 98UL;
        test_tmp_u32_ref = 0x00000003UL;
        test_tmp_u32_mask = LASTBITMASK(test_tmp_u32_bits, uint32_t);
        cmp_result = (test_tmp_u32_ref == test_tmp_u32_mask);
        printf("LASTBITMASK(%u, uint32_t)=0x%08x, result: %s\r\n", test_tmp_u32_bits, test_tmp_u32_mask, (cmp_result)?("PASS"):("FAIL"));

        test_tmp_u32_bits = 97UL;
        test_tmp_u32_ref = 0x00000001UL;
        test_tmp_u32_mask = LASTBITMASK(test_tmp_u32_bits, uint32_t);
        cmp_result = (test_tmp_u32_ref == test_tmp_u32_mask);
        printf("LASTBITMASK(%u, uint32_t)=0x%08x, result: %s\r\n", test_tmp_u32_bits, test_tmp_u32_mask, (cmp_result)?("PASS"):("FAIL"));

        // uint64_t
        uint64_t test_tmp_u64_bits;
        uint64_t test_tmp_u64_mask;
        uint64_t test_tmp_u64_ref;

        test_tmp_u64_bits = 127UL;
        test_tmp_u64_ref = 0x7FFFFFFFFFFFFFFFUL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));

        test_tmp_u64_bits = 126UL;
        test_tmp_u64_ref = 0x3FFFFFFFFFFFFFFFUL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));

        test_tmp_u64_bits = 125UL;
        test_tmp_u64_ref = 0x1FFFFFFFFFFFFFFFUL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));

        test_tmp_u64_bits = 124UL;
        test_tmp_u64_ref = 0x0FFFFFFFFFFFFFFFUL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));

        test_tmp_u64_bits = 105UL;
        test_tmp_u64_ref = 0x000001FFFFFFFFFFUL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));

        test_tmp_u64_bits = 104UL;
        test_tmp_u64_ref = 0x000000FFFFFFFFFFUL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));

        test_tmp_u64_bits = 103UL;
        test_tmp_u64_ref = 0x0000007FFFFFFFFFUL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));

        test_tmp_u64_bits = 102UL;
        test_tmp_u64_ref = 0x0000003FFFFFFFFFUL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));

        test_tmp_u64_bits = 101UL;
        test_tmp_u64_ref = 0x0000001FFFFFFFFFUL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));

        test_tmp_u64_bits = 100UL;
        test_tmp_u64_ref = 0x0000000FFFFFFFFFUL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));

        test_tmp_u64_bits = 99UL;
        test_tmp_u64_ref = 0x00000007FFFFFFFFUL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));

        test_tmp_u64_bits = 98UL;
        test_tmp_u64_ref = 0x00000003FFFFFFFFUL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));

        test_tmp_u64_bits = 97UL;
        test_tmp_u64_ref = 0x00000001FFFFFFFFUL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));

        test_tmp_u64_bits = 69UL;
        test_tmp_u64_ref = 0x000000000000001FUL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));

        test_tmp_u64_bits = 68UL;
        test_tmp_u64_ref = 0x000000000000000FUL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));

        test_tmp_u64_bits = 67UL;
        test_tmp_u64_ref = 0x0000000000000007UL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));

        test_tmp_u64_bits = 66UL;
        test_tmp_u64_ref = 0x0000000000000003UL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));

        test_tmp_u64_bits = 65UL;
        test_tmp_u64_ref = 0x0000000000000001UL;
        test_tmp_u64_mask = LASTBITMASK(test_tmp_u64_bits, uint64_t);
        cmp_result = (test_tmp_u64_ref == test_tmp_u64_mask);
        printf("LASTBITMASK(%lu, uint64_t)=0x%016lx, result: %s\r\n", test_tmp_u64_bits, test_tmp_u64_mask, (cmp_result)?("PASS"):("FAIL"));
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
    memset(&test_ref->data[0], 0x0u, (test_opA->size));
    memset(&test_opA->data[0], 0x0u, (test_opA->size));
    memset(&test_opB->data[0], 0x0u, (test_opB->size));

    test_ref->data[0] = 0x00000000ul;
    test_ref->data[1] = 0x00000000ul;
    test_ref->data[2] = 0x00000000ul;
    test_ref->data[3] = 0x00000001ul;

    test_opA->data[0] = 0xFFFFFFFFul;
    test_opB->data[0] = 0x00000001ul;
    test_opA->data[1] = 0xFFFFFFFFul;
    test_opB->data[1] = 0x00000000ul;
    test_opA->data[2] = 0xFFFFFFFEul;
    test_opB->data[2] = 0x00000001ul;

    TICK_TIME_START("add_u32");
    add_u32(test_dst, test_opA, test_opB, 0ul);
    TICK_TIME_END;
    test_print_ntype(test_opA, "opA");
    test_print_ntype(test_opB, "opB");
    test_print_ntype(test_dst, "dst");
    test_print_ntype(test_ref, "ref");

    test_cmp = memcmp(test_ref->data, test_dst->data, (test_ref->size));
    printf("add_u32() is %s\r\n", ((test_cmp == 0)?"PASS":"FAIL"));

    /* Sum test */
    memset(&test_ref->data[0], 0x0u, (test_opA->size));
    memset(&test_opA->data[0], 0x0u, (test_opA->size));
    memset(&test_opB->data[0], 0x0u, (test_opB->size));

    test_ref->data[0] = 0xFFFFFFFEul;
    test_ref->data[1] = 0xFFFFFFFFul;
    test_ref->data[2] = 0xFFFFFFFFul;
    test_ref->data[3] = 0x00000001ul;

    test_opA->data[0] = 0xFFFFFFFFul;
    test_opB->data[0] = 0xFFFFFFFFul;
    test_opA->data[1] = 0xFFFFFFFFul;
    test_opB->data[1] = 0xFFFFFFFFul;
    test_opA->data[2] = 0xFFFFFFFFul;
    test_opB->data[2] = 0xFFFFFFFFul;
    test_opA->data[3] = 0x0ul;
    test_opB->data[3] = 0x0ul;

    TICK_TIME_START("add_u32");
    add_u32(test_dst, test_opA, test_opB, 0ul);
    TICK_TIME_END;
    test_print_ntype(test_opA, "opA");
    test_print_ntype(test_opB, "opB");
    test_print_ntype(test_dst, "dst");
    test_print_ntype(test_ref, "ref");

    test_cmp = memcmp(test_ref->data, test_dst->data, (test_ref->size));
    printf("add_u32() is %s\r\n", ((test_cmp == 0)?"PASS":"FAIL"));

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
    memset(&test_ref->data[0], 0x0u, (test_opA->size));
    memset(&test_opA->data[0], 0x0u, (test_opA->size));
    memset(&test_opB->data[0], 0x0u, (test_opB->size));

#if 1
    memset(&test_ref->data[0], 0xffffffffUL, (test_opA->size));

    test_opA->data[0] = 0x1UL;
#endif

    TICK_TIME_START("sub_u32");
    sub_u32(test_dst, test_opA, test_opB, 0ul);
    TICK_TIME_END;
    test_print_ntype(test_opA, "opA");
    test_print_ntype(test_opB, "opB");
    test_print_ntype(test_dst, "dst");
    test_print_ntype(test_ref, "ref");

    test_cmp = memcmp(test_ref->data, test_dst->data, (test_ref->size));
    printf("sub_u32() is %s\r\n", ((test_cmp == 0)?"PASS":"FAIL"));

    /* Sum test */
    memset(&test_ref->data[0], 0x0u, (test_opA->size));
    memset(&test_opA->data[0], 0x0u, (test_opA->size));
    memset(&test_opB->data[0], 0x0u, (test_opB->size));

#if 1
    memset(&test_ref->data[0], 0xffffffffUL, (test_opA->size));
    test_ref->data[0] = 0xfffffffeUL;

    test_opA->data[0] = 0x1;
#endif

    TICK_TIME_START("sub_u32");
    sub_u32(test_dst, test_opA, test_opB, 1ul);
    TICK_TIME_END;
    test_print_ntype(test_opA, "opA");
    test_print_ntype(test_opB, "opB");
    test_print_ntype(test_dst, "dst");
    test_print_ntype(test_ref, "ref");

    test_cmp = memcmp(test_ref->data, test_dst->data, (test_ref->size));
    printf("sub_u32() is %s\r\n", ((test_cmp == 0)?"PASS":"FAIL"));

    rmNum(&test_ref);
    rmNum(&test_dst);
    rmNum(&test_opA);
    rmNum(&test_opB);
}

#define TEST_ARITH_MUL_BIT  1024U
void test_arith_mul_u32_bs(void) {
    int test_cmp;

    ntype_s* test_ref = mkNum(TEST_ARITH_MUL_BIT<<1U);
    ntype_s* test_opA = mkNum(TEST_ARITH_MUL_BIT<<0U);
    ntype_s* test_opB = mkNum(TEST_ARITH_MUL_BIT<<0U);
    ntype_s* test_dst = mkNum(TEST_ARITH_MUL_BIT<<1U);

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

    TICK_TIME_START("mul_u32_bs");
    mul_u32_bs(test_dst, test_opA, test_opB);
    TICK_TIME_END;
    test_print_ntype(test_opA, "opA");
    test_print_ntype(test_opB, "opB");
    test_print_ntype(test_dst, "dst");
    test_print_ntype(test_ref, "ref");

    test_cmp = memcmp(test_ref->data, test_dst->data, (test_ref->size));
    printf("mul_u32_bs() is %s\r\n", ((test_cmp == 0)?"PASS":"FAIL"));

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

    TICK_TIME_START("mul_u32_bs");
    mul_u32_bs(test_dst, test_opA, test_opB);
    TICK_TIME_END;
    test_print_ntype(test_opA, "opA");
    test_print_ntype(test_opB, "opB");
    test_print_ntype(test_dst, "dst");
    test_print_ntype(test_ref, "ref");

    test_cmp = memcmp(test_ref->data, test_dst->data, (test_ref->size));
    printf("mul_u32_bs() is %s\r\n", ((test_cmp == 0)?"PASS":"FAIL"));

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

    TICK_TIME_START("mul_u32_bs");
    mul_u32_bs(test_dst, test_opA, test_opB);
    TICK_TIME_END;
    test_print_ntype(test_opA, "opA");
    test_print_ntype(test_opB, "opB");
    test_print_ntype(test_dst, "dst");
    test_print_ntype(test_ref, "ref");

    test_cmp = memcmp(test_ref->data, test_dst->data, (test_ref->size));
    printf("mul_u32_bs() is %s\r\n", ((test_cmp == 0)?"PASS":"FAIL"));

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

    TICK_TIME_START("mul_u32_bs");
    mul_u32_bs(test_dst, test_opA, test_opB);
    TICK_TIME_END;
    test_print_ntype(test_opA, "opA");
    test_print_ntype(test_opB, "opB");
    test_print_ntype(test_dst, "dst");
    test_print_ntype(test_ref, "ref");

    test_cmp = memcmp(test_ref->data, test_dst->data, (test_ref->size));
    printf("mul_u32_bs() is %s\r\n", ((test_cmp == 0)?"PASS":"FAIL"));

    rmNum(&test_ref);
    rmNum(&test_opA);
    rmNum(&test_opB);
    rmNum(&test_dst);
}

#define TEST_ARITH_MUL_NN_BIT       512U
void test_arith_mul_u32_bs_nn(void) {
    int test_cmp;
    ReturnType fr;

    ntype_s* test_ref = mkNum(TEST_ARITH_MUL_NN_BIT);
    ntype_s* test_opA = mkNum(TEST_ARITH_MUL_NN_BIT);
    ntype_s* test_opB = mkNum(TEST_ARITH_MUL_NN_BIT);
    ntype_s* test_dst = mkNum(TEST_ARITH_MUL_NN_BIT);

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

    if(fr = mul_u32_bs_ext(test_dst, test_opA, test_opB, false)) {
        printReturnType(fr);
    } else { /* Do nothing */ }
    test_print_ntype(test_opA, "opA");
    test_print_ntype(test_opB, "opB");
    test_print_ntype(test_dst, "dst");
    test_print_ntype(test_ref, "ref");

    test_cmp = memcmp(test_ref->data, test_dst->data, (test_ref->size));
    printf("mul_u32_bs() is %s\r\n", ((test_cmp == 0)?"PASS":"FAIL"));

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

    printf("[test start: test_ntype()]\r\n");
    test_ntype();
    printf("[test   end: test_ntype()]\r\n");

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

int main(int argc, char** argv) {
    printf("arg:%d, ",argc);
    for(unsigned int i=0; i<argc; i++) {
        printf("arg[%d]:%s, ", i, argv[i]);
    }
    printf("\r\n");

    test_sequence();
}
