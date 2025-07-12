#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <sys/sysinfo.h>

#include <time.h>

#include "common/util.h"
#include "common/ntype.h"

void _memChk(void) {
    struct sysinfo info;

    sysinfo(&info);

    printf("load: %ld %ld %ld\n", info.loads[0], info.loads[1], info.loads[2]);
    printf("mem : %ld %ld %ld\n", info.totalram, info.totalram-info.freeram, info.freeram);
}

bool chkVector(uint8_t* va, uint8_t* vb, size_t size)
{
    bool chkResult = (memcmp(va, vb, size) == 0);

    printf("Test is \"%s\"\r\n", (chkResult?"PASS":"FAIL"));

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
    printf("%s:%s\r\n", (examResult?"PASS":"FAIL"), (DESCRIPTION)); \
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

#if 0 /* DISABLED:test_doCipher call static vars */
void test_doCipher(void)
{
    printf("%s:%d:%s\r\n", __FILE__, __LINE__, __func__);

    int fRtn;
    (void)memset(test_AES_out, 0x0, sizeof(test_AES_out));

    TEST_AES_RUN(keyExpansion(tv_AES128_key, AES128_Nk, AES128_Nr), fRtn);
    TEST_AES_RUN(doCipher(test_AES_out, tv_AES128_FIPS197_pTxt_ref, AES128_Nr, (uint32_t*)g_extKey), fRtn);
    DBG_PRINT_ARRAY(test_AES_out, sizeof(test_AES_out), "NIST, FIPS197, May 9, 2023, Appendix B - Cipher Example(AES128)", 4UL);
    TEST_AES_EXAM(memcmp(test_AES_out, tv_AES128_FIPS197_cTxt_ref, sizeof(tv_AES128_FIPS197_cTxt_ref)) == 0, \
            "NIST, FIPS197, AES128 TestVector");
}
#else
#define test_doCipher()
#endif/* DISABLED:test_doCipher call static vars */
#if 0 /* DISABLED:test_doCipherInv call static vars */
void test_doCipherInv(void)
{
    printf("%s:%d:%s\r\n", __FILE__, __LINE__, __func__);

    int fRtn;
    (void)memset(test_AES_out, 0x0, sizeof(test_AES_out));

    TEST_AES_RUN(keyExpansionEIC(tv_AES128_key, AES128_Nk, AES128_Nr), fRtn);
    TEST_AES_RUN(doCipherInv(test_AES_out, tv_AES128_FIPS197_cTxt_ref, AES128_Nr, (uint32_t*)g_extKey), fRtn);
    DBG_PRINT_ARRAY(test_AES_out, sizeof(test_AES_out), "NIST, FIPS197, May 9, 2023, Appendix B - Inv Cipher Example(AES128)", 4UL);
    TEST_AES_EXAM(memcmp(test_AES_out, tv_AES128_FIPS197_pTxt_ref, sizeof(tv_AES128_FIPS197_pTxt_ref)) == 0, \
            "NIST, FIPS197, AES128 TestVector");
}
#else
#define test_doCipherInv()
#endif/* DISABLED:test_doCipherInv call static vars */

#if 0 /* DISABLED:test_doCipherInv2 call static vars */
void test_doCipherInv2(void)
{
    printf("%s:%d:%s\r\n", __FILE__, __LINE__, __func__);

    int fRtn;
    (void)memset(test_AES_out, 0x0, sizeof(test_AES_out));

    TEST_AES_RUN(keyExpansion(tv_AES128_key, AES128_Nk, AES128_Nr), fRtn);
    TEST_AES_RUN(doCipherInv2(test_AES_out, tv_AES128_FIPS197_cTxt_ref, AES128_Nr, (uint32_t*)g_extKey), fRtn);
    DBG_PRINT_ARRAY(test_AES_out, sizeof(test_AES_out), "NIST, FIPS197, May 9, 2023, Appendix B - Inv Cipher Example(AES128)", 4UL);
    TEST_AES_EXAM(memcmp(test_AES_out, tv_AES128_FIPS197_pTxt_ref, sizeof(tv_AES128_FIPS197_pTxt_ref)) == 0, \
            "NIST, FIPS197, AES128 TestVector");
}
#else
#define test_doCipherInv2()
#endif/* DISABLED:test_doCipherInv2 call static vars */

void test_aesEnc(void)
{
    printf("%s:%d:%s\r\n", __FILE__, __LINE__, __func__);

    int fRtn;

    printf("[AES128 Encryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES_NIST_Ex_pTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        TEST_AES_RUN(aesEnc(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], tv_AES128_key, sizeof(tv_AES128_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        TEST_AES_EXAM(memcmp(test_AES_out, tv_AES128_NIST_Ex_cTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES128 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Encrypt Values", AES_S_SIZE);
    }

    printf("[AES192 Encryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES_NIST_Ex_pTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        TEST_AES_RUN(aesEnc(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], tv_AES192_key, sizeof(tv_AES192_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        TEST_AES_EXAM(memcmp(test_AES_out, tv_AES192_NIST_Ex_cTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES192 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Encrypt Values", AES_S_SIZE);
    }

    printf("[AES256 Encryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES_NIST_Ex_pTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        TEST_AES_RUN(aesEnc(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], tv_AES256_key, sizeof(tv_AES256_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        TEST_AES_EXAM(memcmp(test_AES_out, tv_AES256_NIST_Ex_cTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES256 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Encrypt Values", AES_S_SIZE);
    }
}

void test_aesDec(void)
{
    printf("%s:%d:%s\r\n", __FILE__, __LINE__, __func__);

    int fRtn;

    printf("[AES128 Decryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES128_NIST_Ex_cTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        TEST_AES_RUN(aesDec(test_AES_out, tv_AES128_NIST_Ex_cTxt_ref[tvi], tv_AES128_key, sizeof(tv_AES128_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        TEST_AES_EXAM(memcmp(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES128 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Decrypt Values", AES_S_SIZE);
    }

    printf("[AES192 Decryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES192_NIST_Ex_cTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        TEST_AES_RUN(aesDec(test_AES_out, tv_AES192_NIST_Ex_cTxt_ref[tvi], tv_AES192_key, sizeof(tv_AES192_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        TEST_AES_EXAM(memcmp(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES192 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Decrypt Values", AES_S_SIZE);
    }

    printf("[AES256 Decryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES256_NIST_Ex_cTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        TEST_AES_RUN(aesDec(test_AES_out, tv_AES256_NIST_Ex_cTxt_ref[tvi], tv_AES256_key, sizeof(tv_AES256_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        TEST_AES_EXAM(memcmp(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES256 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Decrypt Values", AES_S_SIZE);
    }

}

void test_aesDec2(void)
{
    int fRtn;
    printf("%s:%d:%s\r\n", __FILE__, __LINE__, __func__);

    printf("[AES128 Decryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES128_NIST_Ex_cTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        TEST_AES_RUN(aesDec2(test_AES_out, tv_AES128_NIST_Ex_cTxt_ref[tvi], tv_AES128_key, sizeof(tv_AES128_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        TEST_AES_EXAM(memcmp(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES128 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Decrypt Values", AES_S_SIZE);
    }

    printf("[AES192 Decryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES192_NIST_Ex_cTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        TEST_AES_RUN(aesDec2(test_AES_out, tv_AES192_NIST_Ex_cTxt_ref[tvi], tv_AES192_key, sizeof(tv_AES192_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        TEST_AES_EXAM(memcmp(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES192 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Decrypt Values", AES_S_SIZE);
    }

    printf("[AES256 Decryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES256_NIST_Ex_cTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        TEST_AES_RUN(aesDec2(test_AES_out, tv_AES256_NIST_Ex_cTxt_ref[tvi], tv_AES256_key, sizeof(tv_AES256_key)), fRtn);
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
    aesEnc(test_AES_out, test_allZero, test_gcm211_key, sizeof(test_gcm211_key));
    printHex(test_AES_out, sizeof(test_AES_out), "2.1.1. GCM, H", AES_S_SIZE);
}

void test_aes(void)
{
    int fRtn;
    uint32_t u32_v = 0xfedcba98U;
    uint8_t u8a_p[4] = {0x98U,0xbaU,0xdcU,0xfeU};

    printf("[rotWord test]");
    printf("u32_v(origin): 0x%08x\r\n", u32_v);
    printHex((void*)(&u32_v), sizeof(u32_v), "u32_v(origin)",  0UL);
    TEST_AES_RUN(rotWord(u32_v), fRtn);
    printf("u32_v(result): 0x%08x\r\n", u32_v);
    printHex((void*)(&u32_v), sizeof(u32_v), "u32_v(result)",  0UL);

    printHex((void*)(u8a_p), sizeof(u8a_p), "u8a_p(origin)", 0UL);
    TEST_AES_RUN(rotWord((*((uint32_t*)u8a_p))), fRtn);
    printHex((void*)(u8a_p), sizeof(u8a_p), "u8a_p(result)", 0UL);

#ifdef DEBUG
    printf("[TEST: AES128 keyExpansion]\r\n");
    TEST_AES_RUN(keyExpansion(tv_AES128_key, AES128_Nk, AES128_Nr), fRtn);

    printf("[TEST: AES192 keyExpansion]\r\n");
    TEST_AES_RUN(keyExpansion(tv_AES192_key, AES192_Nk, AES192_Nr), fRtn);

    printf("[TEST: AES256 keyExpansion]\r\n");
    TEST_AES_RUN(keyExpansion(tv_AES256_key, AES256_Nk, AES256_Nr), fRtn);
#endif /* DEBUG */

    test_doCipher();

    test_aesEnc();

    test_doCipherInv();

    test_aesDec();

    test_doCipherInv2();

    test_aesDec2();

    test_aes_blanks(); // calcaulates AES-GCM H
}
#endif /* TEST_AES */

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

        convSymbolToStream256((uint32_t*)g_sha256Dg_8bStm, (const uint32_t*)g_sha256Dg32bSym, SHA256_DIGEST_SIZE);
        printf("[DIGEST]\n");
        printf("(32bit) 0x ");
        for(size_t si = 0UL; si < SIZE2UI32LEN(sizeof(g_sha256Dg32bSym)); si++)
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
            for(size_t si = 0UL; si < SIZE2UI32LEN(sizeof(ref_mes_abc_pad)); si++)
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
            for(size_t si = 0UL; si < SIZE2UI32LEN(sizeof(mes_abc_32b_symbol)); si++)
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

        convSymbolToStream256((uint32_t*)g_sha256Dg_8bStm, (const uint32_t*)g_sha256Dg32bSym, SHA256_DIGEST_SIZE);
        printf("[DIGEST]\n");
        printf("(32bit) 0x ");
        for(size_t si = 0UL; si < SIZE2UI32LEN(sizeof(g_sha256Dg32bSym)); si++)
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

        convStreamToSymbol256((uint32_t*)mes_abc_8b_stream, (const uint32_t*)mes_abc_8b_stream, sizeof(mes_abc_8b_stream));

        startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

        updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)mes_abc_8b_stream, mes_abc_size);

        finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

        convSymbolToStream256((uint32_t*)g_sha256Dg_8bStm, (const uint32_t*)g_sha256Dg32bSym, SHA256_DIGEST_SIZE);
        printf("[DIGEST]\n");
        printf("(32bit) 0x ");
        for(size_t si = 0UL; si < SIZE2UI32LEN(sizeof(g_sha256Dg32bSym)); si++)
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

        convStreamToSymbol256((uint32_t*)mes_string_8b_stream, (const uint32_t*)mes_string_8b_stream, sizeof(mes_string_8b_stream));

        startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

        updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)mes_string_8b_stream, mes_string_size);

        finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

        convSymbolToStream256((uint32_t*)g_sha256Dg_8bStm, (const uint32_t*)g_sha256Dg32bSym, SHA256_DIGEST_SIZE);
        printf("[DIGEST]\n");
        printf("(32bit) 0x ");
        for(size_t si = 0UL; si < SIZE2UI32LEN(sizeof(g_sha256Dg32bSym)); si++)
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

            convStreamToSymbol256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

            updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)tv_mesStm, tv_sz);

            finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

            printf("SHA-256 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

            convStreamToSymbol256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

            updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)tv_mesStm, tv_sz);

            finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

            printf("SHA-256 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

            convStreamToSymbol256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

            updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)tv_mesStm, tv_sz);

            finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

            printf("SHA-256 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

            convStreamToSymbol256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

            updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)tv_mesStm, tv_sz);

            finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

            printf("SHA-256 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

            convStreamToSymbol256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

            updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)tv_mesStm, tv_sz);

            finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

            printf("SHA-256 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

            convStreamToSymbol256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

            updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)tv_mesStm, tv_sz);

            finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

            printf("SHA-256 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

            convStreamToSymbol256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

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
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

            convStreamToSymbol256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

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
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

            convStreamToSymbol256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

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
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

            convStreamToSymbol256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

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
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

            convStreamToSymbol256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

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
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

            convStreamToSymbol256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

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
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

            convStreamToSymbol256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

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
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

            convStreamToSymbol512((uint64_t*)tv_mesStm, (const uint64_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha512(g_sha512Dg64bSym, (const uint64_t*)H0_512, sizeof(H0_512));

            updateSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym), (uint64_t*)tv_mesStm, tv_sz);

            finishSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym));

            printf("SHA-512 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha512Dg64bSym, SHA512_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

            convStreamToSymbol512((uint64_t*)tv_mesStm, (const uint64_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha512(g_sha512Dg64bSym, (const uint64_t*)H0_512, sizeof(H0_512));

            updateSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym), (uint64_t*)tv_mesStm, tv_sz);

            finishSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym));

            printf("SHA-512 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha512Dg64bSym, SHA512_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

            convStreamToSymbol512((uint64_t*)tv_mesStm, (const uint64_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha512(g_sha512Dg64bSym, (const uint64_t*)H0_512, sizeof(H0_512));

            updateSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym), (uint64_t*)tv_mesStm, tv_sz);

            finishSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym));

            printf("SHA-512 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha512Dg64bSym, SHA512_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

            convStreamToSymbol512((uint64_t*)tv_mesStm, (const uint64_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha512(g_sha512Dg64bSym, (const uint64_t*)H0_512, sizeof(H0_512));

            updateSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym), (uint64_t*)tv_mesStm, tv_sz);

            finishSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym));

            printf("SHA-512 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha512Dg64bSym, SHA512_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

            convStreamToSymbol512((uint64_t*)tv_mesStm, (const uint64_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha512(g_sha512Dg64bSym, (const uint64_t*)H0_512, sizeof(H0_512));

            updateSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym), (uint64_t*)tv_mesStm, tv_sz);

            finishSha512(g_sha512Dg64bSym, sizeof(g_sha512Dg64bSym));

            printf("SHA-512 #%lu: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha512Dg64bSym, SHA512_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

            convStreamToSymbol512((uint64_t*)tv_mesStm, (const uint64_t*)tv_mesStm, sizeof(tv_mesStm));

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
            printf("%s\n",((memcmp(ref_dgSym, g_sha512Dg64bSym, SHA512_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

            convStreamToSymbol512((uint64_t*)tv_mesStm, (const uint64_t*)tv_mesStm, sizeof(tv_mesStm));

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
            printf("%s\n",((memcmp(ref_dgSym, g_sha512Dg64bSym, SHA512_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

            convStreamToSymbol512((uint64_t*)tv_mesStm, (const uint64_t*)tv_mesStm, sizeof(tv_mesStm));

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
            printf("%s\n",((memcmp(ref_dgSym, g_sha512Dg64bSym, SHA512_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

            convStreamToSymbol512((uint64_t*)tv_mesStm, (const uint64_t*)tv_mesStm, sizeof(tv_mesStm));

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
            printf("%s\n",((memcmp(ref_dgSym, g_sha512Dg64bSym, SHA512_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

            convStreamToSymbol512((uint64_t*)tv_mesStm, (const uint64_t*)tv_mesStm, sizeof(tv_mesStm));

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
            printf("%s\n",((memcmp(ref_dgSym, g_sha512Dg64bSym, SHA512_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

            convStreamToSymbol512((uint64_t*)tv_mesStm, (const uint64_t*)tv_mesStm, sizeof(tv_mesStm));

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
            printf("%s\n",((memcmp(ref_dgSym, g_sha512Dg64bSym, SHA512_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

            convStreamToSymbol512((uint64_t*)tv_mesStm, (const uint64_t*)tv_mesStm, sizeof(tv_mesStm));

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
            printf("%s\n",((memcmp(ref_dgSym, g_sha512Dg64bSym, SHA512_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

        convStreamToSymbol256((uint32_t*)textStm, (const uint32_t*)textStm, sizeof(textStm));

        startHmac256(keySym, keySize, SHA256_DIGEST_SIZE);
        updateHmac256(SHA256_DIGEST_SIZE, (const uint32_t*)textStm, textLen);
        finishHmac256(g_hmac256Sym, SHA256_DIGEST_SIZE);

        printf("[HMAC256]\n");
        printf("(32bit) 0x ");
        for(size_t si = 0UL; si < SIZE2UI32LEN(sizeof(g_hmac256Sym)); si++)
        {
            printf("%08x", g_hmac256Sym[si]);
        }
        printf("\n");

        printf("[%2lu]HMAC-256: ", testNum);
        printf("%s\n",((memcmp(ref_mac, g_hmac256Sym, SHA256_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

        convStreamToSymbol256((uint32_t*)textStm, (const uint32_t*)textStm, sizeof(textStm));

        startHmac256(keySym, keySize, SHA256_DIGEST_SIZE);
        updateHmac256(SHA256_DIGEST_SIZE, (const uint32_t*)textStm, textLen);
        finishHmac256(g_hmac256Sym, SHA256_DIGEST_SIZE);

        printf("[HMAC256]\n");
        printf("(32bit) 0x ");
        for(size_t si = 0UL; si < SIZE2UI32LEN(sizeof(g_hmac256Sym)); si++)
        {
            printf("%08x", g_hmac256Sym[si]);
        }
        printf("\n");

        printf("[%2lu]HMAC-256: ", testNum);
        printf("%s\n",((memcmp(ref_mac, g_hmac256Sym, SHA256_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

        convStreamToSymbol256((uint32_t*)textStm, (const uint32_t*)textStm, sizeof(textStm));

        startHmac256(keySym, keySize, SHA256_DIGEST_SIZE);
        updateHmac256(SHA256_DIGEST_SIZE, (const uint32_t*)textStm, textLen);
        finishHmac256(g_hmac256Sym, SHA256_DIGEST_SIZE);

        printf("[HMAC256]\n");
        printf("(32bit) 0x ");
        for(size_t si = 0UL; si < SIZE2UI32LEN(sizeof(g_hmac256Sym)); si++)
        {
            printf("%08x", g_hmac256Sym[si]);
        }
        printf("\n");

        printf("[%2lu]HMAC-256: ", testNum);
        printf("%s\n",((memcmp(ref_mac, g_hmac256Sym, SHA256_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

        convStreamToSymbol256((uint32_t*)textStm, (const uint32_t*)textStm, sizeof(textStm));

        startHmac256(keySym, keySize, SHA256_DIGEST_SIZE);
        updateHmac256(SHA256_DIGEST_SIZE, (const uint32_t*)textStm, textLen);
        finishHmac256(g_hmac256Sym, SHA256_DIGEST_SIZE);

        printf("[HMAC256]\n");
        printf("(32bit) 0x ");
        for(size_t si = 0UL; si < SIZE2UI32LEN(ref_mac_truncated_size); si++)
        {
            printf("%08x", g_hmac256Sym[si]);
        }
        printf("\n");

        printf("[%2lu]HMAC-256(truncated to %lu Bytes): ", testNum, ref_mac_truncated_size);
        printf("%s\n",((memcmp(ref_mac, g_hmac256Sym, ref_mac_truncated_size) == 0)?"PASS":"FAIL"));

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

        convStreamToSymbol512((uint64_t*)textStm, (const uint64_t*)textStm, sizeof(textStm));

        startHmac512(keySym, keySize, SHA512_DIGEST_SIZE);
        updateHmac512(SHA512_DIGEST_SIZE, (const uint64_t*)textStm, textLen);
        finishHmac512(g_hmac512Sym, SHA512_DIGEST_SIZE);

        printf("[HMAC512]\n");
        printf("(64bit) 0x ");
        for(size_t si = 0UL; si < SIZE2UI32LEN(sizeof(g_hmac512Sym)); si++)
        {
            printf("%016lx", g_hmac512Sym[si]);
        }
        printf("\n");

        printf("[%2lu]HMAC-512: ", testNum);
        printf("%s\n",((memcmp(ref_mac, g_hmac512Sym, SHA512_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

        convStreamToSymbol512((uint64_t*)textStm, (const uint64_t*)textStm, sizeof(textStm));

        startHmac512(keySym, keySize, SHA512_DIGEST_SIZE);
        updateHmac512(SHA512_DIGEST_SIZE, (const uint64_t*)textStm, textLen);
        finishHmac512(g_hmac512Sym, SHA512_DIGEST_SIZE);

        printf("[HMAC512]\n");
        printf("(64bit) 0x ");
        for(size_t si = 0UL; si < SIZE2UI32LEN(sizeof(g_hmac512Sym)); si++)
        {
            printf("%016lx", g_hmac512Sym[si]);
        }
        printf("\n");

        printf("[%2lu]HMAC-512: ", testNum);
        printf("%s\n",((memcmp(ref_mac, g_hmac512Sym, SHA512_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

        convStreamToSymbol512((uint64_t*)textStm, (const uint64_t*)textStm, sizeof(textStm));

        startHmac512(keySym, keySize, SHA512_DIGEST_SIZE);
        updateHmac512(SHA512_DIGEST_SIZE, (const uint64_t*)textStm, textLen);
        finishHmac512(g_hmac512Sym, SHA512_DIGEST_SIZE);

        printf("[HMAC512]\n");
        printf("(64bit) 0x ");
        for(size_t si = 0UL; si < SIZE2UI32LEN(sizeof(g_hmac512Sym)); si++)
        {
            printf("%016lx", g_hmac512Sym[si]);
        }
        printf("\n");

        printf("[%2lu]HMAC-512: ", testNum);
        printf("%s\n",((memcmp(ref_mac, g_hmac512Sym, SHA512_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

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

        convStreamToSymbol512((uint64_t*)textStm, (const uint64_t*)textStm, sizeof(textStm));

        startHmac512(keySym, keySize, SHA512_DIGEST_SIZE);
        updateHmac512(SHA512_DIGEST_SIZE, (const uint64_t*)textStm, textLen);
        finishHmac512(g_hmac512Sym, SHA512_DIGEST_SIZE);

        printf("[HMAC512]\n");
        printf("(64bit) 0x ");
        for(size_t si = 0UL; si < SIZE2UI32LEN(ref_mac_truncated_size); si++)
        {
            printf("%016lx", g_hmac512Sym[si]);
        }
        printf("\n");

        printf("[%2lu]HMAC-512(truncated to %lu Bytes): ", testNum, ref_mac_truncated_size);
        printf("%s\n",((memcmp(ref_mac, g_hmac512Sym, ref_mac_truncated_size) == 0)?"PASS":"FAIL"));

        printf("--------------------------------------------------------------------------------\n");
    }
}
#endif /* TEST_HMAC */

void test_sequence(void) {
    test_macro();
    test_ntype();
    test_ghash();
#ifdef TEST_AES
    test_aes();
#endif /* TEST_AES */
#ifdef TEST_SHA
    test_sha2();
#endif /* TEST_SHA */
#ifdef TEST_HMAC
    test_FIPS_198_hamc256_imVal();
    test_FIPS_198_hamc512_imVal();
#endif /* TEST_HMAC */
}

int main(int argc, char** argv) {
    printf("arg:%d, ",argc);
    for(unsigned int i=0; i<argc; i++) {
        printf("arg[%d]:%s, ", i, argv[i]);
    }
    printf("\r\n");

    test_sequence();
}
