#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <sys/sysinfo.h>

#include "common/util.h"
#include "common/ntype.h"
#include "arith/arith_core.h"

void _memChk(void) {
    struct sysinfo info;

    sysinfo(&info);

    printf("load: %ld %ld %ld\n", info.loads[0], info.loads[1], info.loads[2]);
    printf("mem : %ld %ld %ld\n", info.totalram, info.totalram-info.freeram, info.freeram);
}

void test_print_ntype(ntype_s* p, const char* title) {
    printf("ntype addr:0x%p, NTYPE size:%lu\r\n", p, sizeof(NTYPE));
    printf("[%s]\r\n", title);
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
    ntype_s* test_ref;
    ntype_s* test_dst;
    ntype_s* test_opA;
    ntype_s* test_opB;
    int test_cmp;

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

    add_u32(test_dst, test_opA, test_opB, 0ul);
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

    add_u32(test_dst, test_opA, test_opB, 0ul);
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
    ntype_s* test_ref;
    ntype_s* test_dst;
    ntype_s* test_opA;
    ntype_s* test_opB;
    int test_cmp;

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

    sub_u32(test_dst, test_opA, test_opB, 0ul);
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

    sub_u32(test_dst, test_opA, test_opB, 1ul);
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

void test_sequence(void) {
    test_macro();
    test_ntype();
    test_arith_add();
    test_arith_sub();
}

int main(int argc, char** argv) {
    printf("arg:%d, ",argc);
    for(unsigned int i=0; i<argc; i++) {
        printf("arg[%d]:%s, ", i, argv[i]);
    }
    printf("\r\n");

    test_sequence();
}
