#include <stdio.h>
#include <stdint.h>

#include <sys/sysinfo.h>

#include "common/util.h"
#include "common/ntype.h"

void _memChk(void) {
    struct sysinfo info;

    sysinfo(&info);

    printf("load: %ld %ld %ld\n", info.loads[0], info.loads[1], info.loads[2]);
    printf("mem : %ld %ld %ld\n", info.totalram, info.totalram-info.freeram, info.freeram);
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

    uint32_t test_blen, test_alen;
    int test_cmp_blen, test_cmp_alen;

    {
        test_blen = 1ul;
        test_alen = UIN_CEIL(test_blen, 8u);
        p = mkNum(test_blen);
        if(test_blen == p->blen)    test_cmp_blen = 0;
        else                        test_cmp_blen = -1;
        if(test_alen == p->alen)    test_cmp_alen = 0;
        else                        test_cmp_alen = -1;
        printf("(ntype_s*):0x%p, blen:%u[bit]:%s, alen:%u[Bytes]:%s\r\n", p,
            p->blen, (test_cmp_blen == 0)?"PASS":"FAIL", \
            p->alen, (test_cmp_alen == 0)?"PASS":"FAIL");
        rmNum(&p);

        test_blen = 8ul - 1ul;
        test_alen = UIN_CEIL(test_blen, 8u);
        p = mkNum(test_blen);
        if(test_blen == p->blen)    test_cmp_blen = 0;
        else                        test_cmp_blen = -1;
        if(test_alen == p->alen)    test_cmp_alen = 0;
        else                        test_cmp_alen = -1;
        printf("(ntype_s*):0x%p, blen:%u[bit]:%s, alen:%u[Bytes]:%s\r\n", p,
            p->blen, (test_cmp_blen == 0)?"PASS":"FAIL", \
            p->alen, (test_cmp_alen == 0)?"PASS":"FAIL");
        rmNum(&p);

        test_blen = 8ul;
        test_alen = UIN_CEIL(test_blen, 8u);
        p = mkNum(test_blen);
        if(test_blen == p->blen)    test_cmp_blen = 0;
        else                        test_cmp_blen = -1;
        if(test_alen == p->alen)    test_cmp_alen = 0;
        else                        test_cmp_alen = -1;
        printf("(ntype_s*):0x%p, blen:%u[bit]:%s, alen:%u[Bytes]:%s\r\n", p,
            p->blen, (test_cmp_blen == 0)?"PASS":"FAIL", \
            p->alen, (test_cmp_alen == 0)?"PASS":"FAIL");
        rmNum(&p);

        test_blen = 8ul + 1ul;
        test_alen = UIN_CEIL(test_blen, 8u);
        p = mkNum(test_blen);
        if(test_blen == p->blen)    test_cmp_blen = 0;
        else                        test_cmp_blen = -1;
        if(test_alen == p->alen)    test_cmp_alen = 0;
        else                        test_cmp_alen = -1;
        printf("(ntype_s*):0x%p, blen:%u[bit]:%s, alen:%u[Bytes]:%s\r\n", p,
            p->blen, (test_cmp_blen == 0)?"PASS":"FAIL", \
            p->alen, (test_cmp_alen == 0)?"PASS":"FAIL");
        rmNum(&p);

        test_blen = 16ul - 1ul;
        test_alen = UIN_CEIL(test_blen, 8u);
        p = mkNum(test_blen);
        if(test_blen == p->blen)    test_cmp_blen = 0;
        else                        test_cmp_blen = -1;
        if(test_alen == p->alen)    test_cmp_alen = 0;
        else                        test_cmp_alen = -1;
        printf("(ntype_s*):0x%p, blen:%u[bit]:%s, alen:%u[Bytes]:%s\r\n", p,
            p->blen, (test_cmp_blen == 0)?"PASS":"FAIL", \
            p->alen, (test_cmp_alen == 0)?"PASS":"FAIL");
        rmNum(&p);

        test_blen = 16ul;
        test_alen = UIN_CEIL(test_blen, 8u);
        p = mkNum(test_blen);
        if(test_blen == p->blen)    test_cmp_blen = 0;
        else                        test_cmp_blen = -1;
        if(test_alen == p->alen)    test_cmp_alen = 0;
        else                        test_cmp_alen = -1;
        printf("(ntype_s*):0x%p, blen:%u[bit]:%s, alen:%u[Bytes]:%s\r\n", p,
            p->blen, (test_cmp_blen == 0)?"PASS":"FAIL", \
            p->alen, (test_cmp_alen == 0)?"PASS":"FAIL");
        rmNum(&p);

        test_blen = 16ul + 1ul;
        test_alen = UIN_CEIL(test_blen, 8u);
        p = mkNum(test_blen);
        if(test_blen == p->blen)    test_cmp_blen = 0;
        else                        test_cmp_blen = -1;
        if(test_alen == p->alen)    test_cmp_alen = 0;
        else                        test_cmp_alen = -1;
        printf("(ntype_s*):0x%p, blen:%u[bit]:%s, alen:%u[Bytes]:%s\r\n", p,
            p->blen, (test_cmp_blen == 0)?"PASS":"FAIL", \
            p->alen, (test_cmp_alen == 0)?"PASS":"FAIL");
        rmNum(&p);

        test_blen = 512ul - 1ul;
        test_alen = UIN_CEIL(test_blen, 8u);
        p = mkNum(test_blen);
        if(test_blen == p->blen)    test_cmp_blen = 0;
        else                        test_cmp_blen = -1;
        if(test_alen == p->alen)    test_cmp_alen = 0;
        else                        test_cmp_alen = -1;
        printf("(ntype_s*):0x%p, blen:%u[bit]:%s, alen:%u[Bytes]:%s\r\n", p,
            p->blen, (test_cmp_blen == 0)?"PASS":"FAIL", \
            p->alen, (test_cmp_alen == 0)?"PASS":"FAIL");
        rmNum(&p);

        test_blen = 512ul;
        test_alen = UIN_CEIL(test_blen, 8u);
        p = mkNum(test_blen);
        if(test_blen == p->blen)    test_cmp_blen = 0;
        else                        test_cmp_blen = -1;
        if(test_alen == p->alen)    test_cmp_alen = 0;
        else                        test_cmp_alen = -1;
        printf("(ntype_s*):0x%p, blen:%u[bit]:%s, alen:%u[Bytes]:%s\r\n", p,
            p->blen, (test_cmp_blen == 0)?"PASS":"FAIL", \
            p->alen, (test_cmp_alen == 0)?"PASS":"FAIL");
        rmNum(&p);

        test_blen = 512ul + 1ul;
        test_alen = UIN_CEIL(test_blen, 8u);
        p = mkNum(test_blen);
        if(test_blen == p->blen)    test_cmp_blen = 0;
        else                        test_cmp_blen = -1;
        if(test_alen == p->alen)    test_cmp_alen = 0;
        else                        test_cmp_alen = -1;
        printf("(ntype_s*):0x%p, blen:%u[bit]:%s, alen:%u[Bytes]:%s\r\n", p,
            p->blen, (test_cmp_blen == 0)?"PASS":"FAIL", \
            p->alen, (test_cmp_alen == 0)?"PASS":"FAIL");
        rmNum(&p);

        test_blen = 1023ul;
        test_alen = UIN_CEIL(test_blen, 8u);
        p = mkNum(test_blen);
        if(test_blen == p->blen)    test_cmp_blen = 0;
        else                        test_cmp_blen = -1;
        if(test_alen == p->alen)    test_cmp_alen = 0;
        else                        test_cmp_alen = -1;
        printf("(ntype_s*):0x%p, blen:%u[bit]:%s, alen:%u[Bytes]:%s\r\n", p,
            p->blen, (test_cmp_blen == 0)?"PASS":"FAIL", \
            p->alen, (test_cmp_alen == 0)?"PASS":"FAIL");
        rmNum(&p);
    }

    for(uint32_t tmp_blen = 1ul; tmp_blen < 20480ul; tmp_blen++) {
        test_blen = tmp_blen;
        test_alen = UIN_CEIL(test_blen, 8u);
        p = mkNum(test_blen);
        if(test_blen == p->blen)    test_cmp_blen = 0;
        else                        test_cmp_blen = -1;
        if(test_alen == p->alen)    test_cmp_alen = 0;
        else                        test_cmp_alen = -1;
        printf("(ntype_s*):0x%p, blen:%u[bit]:%s, alen:%u[Bytes]:%s\r\n", p,
            p->blen, (test_cmp_blen == 0)?"PASS":"FAIL", \
            p->alen, (test_cmp_alen == 0)?"PASS":"FAIL");
        rmNum(&p);

        if((test_cmp_blen != 0) || (test_cmp_alen != 0)) {
            printf("config:bitLength=%u,arrayLength=%u\r\n", test_blen, test_alen);
            break;
        } else {}
    }
}

void test_sequence(void) {
    test_macro();
    test_ntype();
}

int main(int argc, char** argv) {
    printf("arg:%d, ",argc);
    for(unsigned int i=0; i<argc; i++) {
        printf("arg[%d]:%s, ", i, argv[i]);
    }
    printf("\r\n");

    test_sequence();
}
