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

void test_sequence(void) {
    test_macro();
    test_ntype();
    test_ghash();
}

int main(int argc, char** argv) {
    printf("arg:%d, ",argc);
    for(unsigned int i=0; i<argc; i++) {
        printf("arg[%d]:%s, ", i, argv[i]);
    }
    printf("\r\n");

    test_sequence();
}
