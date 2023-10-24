#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <sys/sysinfo.h>

#include "common/util.h"
#include "common/ntype.h"
#include "arith/core.h"

void _memChk(void) {
    struct sysinfo info;

    sysinfo(&info);

    printf("load: %ld %ld %ld\n", info.loads[0], info.loads[1], info.loads[2]);
    printf("mem : %ld %ld %ld\n", info.totalram, info.totalram-info.freeram, info.freeram);
}

void test_print_ntype(ntype_s* p, const char* title) {
    printf("ntype addr:0x%p, NTYPE size:%lu\r\n", p, sizeof(NTYPE));
    printf("[%s]\r\n", title);
    for(size_t i = p->size - 1u; i != ((size_t)-1); i--) {
        printf("0x%08x", p->array[i]);
        if(i != 0u) printf(":");
        else        printf("\r\n");
    }
}

void test_macro(void) {
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
}

void test_ntype(void) {
    ntype_s* p = (ntype_s*)NULL;

    size_t test_bitLen, test_size;
    int test_cmp_bitLen, test_cmp_size;

    {
        test_bitLen = 1ul;
        test_size = UIN_CEIL(test_bitLen, 8u);
        p = mkNum(test_bitLen);
        if(test_bitLen == p->bitLen)    test_cmp_bitLen = 0;
        else                        test_cmp_bitLen = -1;
        if(test_size == p->size)    test_cmp_size = 0;
        else                        test_cmp_size = -1;
        printf("(ntype_s*):0x%p, bitLen:%lu[bit]:%s, size:%lu[Bytes]:%s\r\n", p,
            p->bitLen, (test_cmp_bitLen == 0)?"PASS":"FAIL", \
            p->size, (test_cmp_size == 0)?"PASS":"FAIL");
        rmNum(&p);

        test_bitLen = 8ul - 1ul;
        test_size = UIN_CEIL(test_bitLen, 8u);
        p = mkNum(test_bitLen);
        if(test_bitLen == p->bitLen)    test_cmp_bitLen = 0;
        else                        test_cmp_bitLen = -1;
        if(test_size == p->size)    test_cmp_size = 0;
        else                        test_cmp_size = -1;
        printf("(ntype_s*):0x%p, bitLen:%lu[bit]:%s, size:%lu[Bytes]:%s\r\n", p,
            p->bitLen, (test_cmp_bitLen == 0)?"PASS":"FAIL", \
            p->size, (test_cmp_size == 0)?"PASS":"FAIL");
        rmNum(&p);

        test_bitLen = 8ul;
        test_size = UIN_CEIL(test_bitLen, 8u);
        p = mkNum(test_bitLen);
        if(test_bitLen == p->bitLen)    test_cmp_bitLen = 0;
        else                        test_cmp_bitLen = -1;
        if(test_size == p->size)    test_cmp_size = 0;
        else                        test_cmp_size = -1;
        printf("(ntype_s*):0x%p, bitLen:%lu[bit]:%s, size:%lu[Bytes]:%s\r\n", p,
            p->bitLen, (test_cmp_bitLen == 0)?"PASS":"FAIL", \
            p->size, (test_cmp_size == 0)?"PASS":"FAIL");
        rmNum(&p);

        test_bitLen = 8ul + 1ul;
        test_size = UIN_CEIL(test_bitLen, 8u);
        p = mkNum(test_bitLen);
        if(test_bitLen == p->bitLen)    test_cmp_bitLen = 0;
        else                        test_cmp_bitLen = -1;
        if(test_size == p->size)    test_cmp_size = 0;
        else                        test_cmp_size = -1;
        printf("(ntype_s*):0x%p, bitLen:%lu[bit]:%s, size:%lu[Bytes]:%s\r\n", p,
            p->bitLen, (test_cmp_bitLen == 0)?"PASS":"FAIL", \
            p->size, (test_cmp_size == 0)?"PASS":"FAIL");
        rmNum(&p);

        test_bitLen = 16ul - 1ul;
        test_size = UIN_CEIL(test_bitLen, 8u);
        p = mkNum(test_bitLen);
        if(test_bitLen == p->bitLen)    test_cmp_bitLen = 0;
        else                        test_cmp_bitLen = -1;
        if(test_size == p->size)    test_cmp_size = 0;
        else                        test_cmp_size = -1;
        printf("(ntype_s*):0x%p, bitLen:%lu[bit]:%s, size:%lu[Bytes]:%s\r\n", p,
            p->bitLen, (test_cmp_bitLen == 0)?"PASS":"FAIL", \
            p->size, (test_cmp_size == 0)?"PASS":"FAIL");
        rmNum(&p);

        test_bitLen = 16ul;
        test_size = UIN_CEIL(test_bitLen, 8u);
        p = mkNum(test_bitLen);
        if(test_bitLen == p->bitLen)    test_cmp_bitLen = 0;
        else                        test_cmp_bitLen = -1;
        if(test_size == p->size)    test_cmp_size = 0;
        else                        test_cmp_size = -1;
        printf("(ntype_s*):0x%p, bitLen:%lu[bit]:%s, size:%lu[Bytes]:%s\r\n", p,
            p->bitLen, (test_cmp_bitLen == 0)?"PASS":"FAIL", \
            p->size, (test_cmp_size == 0)?"PASS":"FAIL");
        rmNum(&p);

        test_bitLen = 16ul + 1ul;
        test_size = UIN_CEIL(test_bitLen, 8u);
        p = mkNum(test_bitLen);
        if(test_bitLen == p->bitLen)    test_cmp_bitLen = 0;
        else                        test_cmp_bitLen = -1;
        if(test_size == p->size)    test_cmp_size = 0;
        else                        test_cmp_size = -1;
        printf("(ntype_s*):0x%p, bitLen:%lu[bit]:%s, size:%lu[Bytes]:%s\r\n", p,
            p->bitLen, (test_cmp_bitLen == 0)?"PASS":"FAIL", \
            p->size, (test_cmp_size == 0)?"PASS":"FAIL");
        rmNum(&p);

        test_bitLen = 512ul - 1ul;
        test_size = UIN_CEIL(test_bitLen, 8u);
        p = mkNum(test_bitLen);
        if(test_bitLen == p->bitLen)    test_cmp_bitLen = 0;
        else                        test_cmp_bitLen = -1;
        if(test_size == p->size)    test_cmp_size = 0;
        else                        test_cmp_size = -1;
        printf("(ntype_s*):0x%p, bitLen:%lu[bit]:%s, size:%lu[Bytes]:%s\r\n", p,
            p->bitLen, (test_cmp_bitLen == 0)?"PASS":"FAIL", \
            p->size, (test_cmp_size == 0)?"PASS":"FAIL");
        rmNum(&p);

        test_bitLen = 512ul;
        test_size = UIN_CEIL(test_bitLen, 8u);
        p = mkNum(test_bitLen);
        if(test_bitLen == p->bitLen)    test_cmp_bitLen = 0;
        else                        test_cmp_bitLen = -1;
        if(test_size == p->size)    test_cmp_size = 0;
        else                        test_cmp_size = -1;
        printf("(ntype_s*):0x%p, bitLen:%lu[bit]:%s, size:%lu[Bytes]:%s\r\n", p,
            p->bitLen, (test_cmp_bitLen == 0)?"PASS":"FAIL", \
            p->size, (test_cmp_size == 0)?"PASS":"FAIL");
        rmNum(&p);

        test_bitLen = 512ul + 1ul;
        test_size = UIN_CEIL(test_bitLen, 8u);
        p = mkNum(test_bitLen);
        if(test_bitLen == p->bitLen)    test_cmp_bitLen = 0;
        else                        test_cmp_bitLen = -1;
        if(test_size == p->size)    test_cmp_size = 0;
        else                        test_cmp_size = -1;
        printf("(ntype_s*):0x%p, bitLen:%lu[bit]:%s, size:%lu[Bytes]:%s\r\n", p,
            p->bitLen, (test_cmp_bitLen == 0)?"PASS":"FAIL", \
            p->size, (test_cmp_size == 0)?"PASS":"FAIL");
        rmNum(&p);

        test_bitLen = 1023ul;
        test_size = UIN_CEIL(test_bitLen, 8u);
        p = mkNum(test_bitLen);
        if(test_bitLen == p->bitLen)    test_cmp_bitLen = 0;
        else                        test_cmp_bitLen = -1;
        if(test_size == p->size)    test_cmp_size = 0;
        else                        test_cmp_size = -1;
        printf("(ntype_s*):0x%p, bitLen:%lu[bit]:%s, size:%lu[Bytes]:%s\r\n", p,
            p->bitLen, (test_cmp_bitLen == 0)?"PASS":"FAIL", \
            p->size, (test_cmp_size == 0)?"PASS":"FAIL");
        rmNum(&p);
    }

    for(uint32_t tmp_bitLen = 1ul; tmp_bitLen < 20480ul; tmp_bitLen++) {
        test_bitLen = tmp_bitLen;
        test_size = UIN_CEIL(test_bitLen, 8u);
        p = mkNum(test_bitLen);
        if(test_bitLen == p->bitLen)    test_cmp_bitLen = 0;
        else                        test_cmp_bitLen = -1;
        if(test_size == p->size)    test_cmp_size = 0;
        else                        test_cmp_size = -1;
        printf("(ntype_s*):0x%p, bitLen:%lu[bit]:%s, size:%lu[Bytes]:%s\r\n", p,
            p->bitLen, (test_cmp_bitLen == 0)?"PASS":"FAIL", \
            p->size, (test_cmp_size == 0)?"PASS":"FAIL");
        rmNum(&p);

        if((test_cmp_bitLen != 0) || (test_cmp_size != 0)) {
            printf("config:bitLength=%lu,arrayLength=%lu\r\n", test_bitLen, test_size);
            break;
        } else {}
    }
}

#define TEST_ARITH_BITS 127u    //16Bytes
void test_arith_arrayLen(void) {
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
    memset(&test_ref->array[0], 0x0u, sizeof(NTYPE)*(test_opA->size));
    memset(&test_opA->array[0], 0x0u, sizeof(NTYPE)*(test_opA->size));
    memset(&test_opB->array[0], 0x0u, sizeof(NTYPE)*(test_opB->size));

    test_ref->array[0] = 0x00000000ul;
    test_ref->array[1] = 0x00000000ul;
    test_ref->array[2] = 0x00000000ul;
    test_ref->array[3] = 0x00000001ul;

    test_opA->array[0] = 0xFFFFFFFFul;
    test_opB->array[0] = 0x00000001ul;
    test_opA->array[1] = 0xFFFFFFFFul;
    test_opB->array[1] = 0x00000000ul;
    test_opA->array[2] = 0xFFFFFFFEul;
    test_opB->array[2] = 0x00000001ul;

    add_u32(test_dst->array, test_opA->array, test_opB->array, test_dst->size, 0ul);
    test_print_ntype(test_opA, "opA");
    test_print_ntype(test_opB, "opB");
    test_print_ntype(test_dst, "dst");
    test_print_ntype(test_ref, "ref");

    test_cmp = memcmp(test_ref->array, test_dst->array, sizeof(NTYPE)*(test_ref->size));
    printf("add_u32() is %s\r\n", ((test_cmp == 0)?"PASS":"FAIL"));

    /* Sum test */
    memset(&test_ref->array[0], 0x0u, sizeof(NTYPE)*(test_opA->size));
    memset(&test_opA->array[0], 0x0u, sizeof(NTYPE)*(test_opA->size));
    memset(&test_opB->array[0], 0x0u, sizeof(NTYPE)*(test_opB->size));

    test_ref->array[0] = 0xFFFFFFFEul;
    test_ref->array[1] = 0xFFFFFFFFul;
    test_ref->array[2] = 0xFFFFFFFFul;
    test_ref->array[3] = 0x00000001ul;

    test_opA->array[0] = 0xFFFFFFFFul;
    test_opB->array[0] = 0xFFFFFFFFul;
    test_opA->array[1] = 0xFFFFFFFFul;
    test_opB->array[1] = 0xFFFFFFFFul;
    test_opA->array[2] = 0xFFFFFFFFul;
    test_opB->array[2] = 0xFFFFFFFFul;
    test_opA->array[3] = 0x0ul;
    test_opB->array[3] = 0x0ul;

    add_u32(test_dst->array, test_opA->array, test_opB->array, test_dst->size, 0ul);
    test_print_ntype(test_opA, "opA");
    test_print_ntype(test_opB, "opB");
    test_print_ntype(test_dst, "dst");
    test_print_ntype(test_ref, "ref");

    test_cmp = memcmp(test_ref->array, test_dst->array, sizeof(NTYPE)*(test_ref->size));
    printf("add_u32() is %s\r\n", ((test_cmp == 0)?"PASS":"FAIL"));
}

void test_sequence(void) {
    test_macro();
    test_ntype();
    test_arith_arrayLen();
}

int main(int argc, char** argv) {
    printf("arg:%d, ",argc);
    for(unsigned int i=0; i<argc; i++) {
        printf("arg[%d]:%s, ", i, argv[i]);
    }
    printf("\r\n");

    test_sequence();
}
