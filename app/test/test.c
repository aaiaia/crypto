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

#ifdef TEST_SHA
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h> // exit()

#include "hash/sha2.h"

uint32_t g_sha256Dg32bSym[SHA256_DIGEST_NUM];
uint8_t  g_sha256Dg_8bStm[SHA256_DIGEST_SIZE];

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
        for(size_t si = 0UL; si < SIZE2LEN256(sizeof(g_sha256Dg32bSym)); si++)
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
void test_FIPS_180_2_imVal(void)
{
    printf("%s\n", ref_test_FIPS_180_2_imVal);

    {
        const uint32_t ref_mes_abc_pad[SHA256_BLOCK_NUM] = {
            0x61626380u, 0x00000000u, 0x00000000u, 0x00000000u, 
            0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 
            0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 
            0x00000000u, 0x00000000u, 0x00000000u, 0x00000018u
        };
        {
            printf("(ref_mes_abc_pad 32bit)\n0x ");
            for(size_t si = 0UL; si < SIZE2LEN256(sizeof(ref_mes_abc_pad)); si++)
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

        uint32_t mes_abc_32b_symbol[SHA256_BLOCK_NUM] = {
            0x616263ffu, 0xffffffffu, 0xffffffffu, 0xffffffffu, 
            0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu, 
            0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu, 
            0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu
        };
        const size_t mes_abc_size = 3UL;
        {
            printf("(mes_abc_32b_symbol 32bit)\n0x ");
            for(size_t si = 0UL; si < SIZE2LEN256(sizeof(mes_abc_32b_symbol)); si++)
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
        for(size_t si = 0UL; si < SIZE2LEN256(sizeof(g_sha256Dg32bSym)); si++)
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
        for(size_t si = 0UL; si < SIZE2LEN256(sizeof(g_sha256Dg32bSym)); si++)
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
        for(size_t si = 0UL; si < SIZE2LEN256(sizeof(g_sha256Dg32bSym)); si++)
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

            uint32_t tv_num = 1U;
            uint8_t tv_mesStm[SHA256_BLOCK_SIZE] = { 0xbdu, };
            const size_t tv_sz = 1UL;
            const uint32_t ref_dgSym[SHA256_DIGEST_SIZE] = {
                0x68325720U, 0xaabd7c82U, 0xf30f554bU, 0x313d0570U, 0xc95accbbU, 0x7dc4b5aaU, 0xe11204c0U, 0x8ffe732bU,
            };

            convStreamToSymbol256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

            updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)tv_mesStm, tv_sz);

            finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

            printf("SHA-256 #%u: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

            printf("================================================================================\n");
        }
        /* #2) 4 bytes 0xc98c8e55                           */
        {
            printf("--------------------------------------------------------------------------------\n");

            uint32_t tv_num = 2U;
            uint8_t tv_mesStm[SHA256_BLOCK_SIZE] = { 0xc9u, 0x8cu, 0x8eu, 0x55u, };
            const size_t tv_sz = 4UL;
            const uint32_t ref_dgSym[SHA256_DIGEST_SIZE] = {
                0x7abc22c0U, 0xae5af26cU, 0xe93dbb94U, 0x433a0e0bU, 0x2e119d01U, 0x4f8e7f65U, 0xbd56c61cU, 0xcccd9504U,
            };

            convStreamToSymbol256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

            updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)tv_mesStm, tv_sz);

            finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

            printf("SHA-256 #%u: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

            printf("================================================================================\n");
        }
        /* #3) 55 bytes of zeros                            */
        {
            printf("--------------------------------------------------------------------------------\n");

            uint32_t tv_num = 3U;
            uint8_t tv_mesStm[SHA256_BLOCK_SIZE] = { 0x0u, };
            const size_t tv_sz = 55UL;
            const uint32_t ref_dgSym[SHA256_DIGEST_SIZE] = {
                0x02779466U, 0xcdec1638U, 0x11d07881U, 0x5c633f21U, 0x90141308U, 0x1449002fU, 0x24aa3e80U, 0xf0b88ef7U,
            };

            convStreamToSymbol256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

            updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)tv_mesStm, tv_sz);

            finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

            printf("SHA-256 #%u: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

            printf("================================================================================\n");
        }
        /* #4) 56 bytes of zeros                            */
        {
            printf("--------------------------------------------------------------------------------\n");

            uint32_t tv_num = 4U;
            uint8_t tv_mesStm[SHA256_BLOCK_SIZE] = { 0x0u, };
            const size_t tv_sz = 56UL;
            const uint32_t ref_dgSym[SHA256_DIGEST_SIZE] = {
                0xd4817aa5U, 0x497628e7U, 0xc77e6b60U, 0x6107042bU, 0xbba31308U, 0x88c5f47aU, 0x375e6179U, 0xbe789fbbU,
            };

            convStreamToSymbol256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

            updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)tv_mesStm, tv_sz);

            finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

            printf("SHA-256 #%u: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

            printf("================================================================================\n");
        }
        /* #5) 57 bytes of zeros                            */
        {
            printf("--------------------------------------------------------------------------------\n");

            uint32_t tv_num = 5U;
            uint8_t tv_mesStm[SHA256_BLOCK_SIZE] = { 0x0u, };
            const size_t tv_sz = 57UL;
            const uint32_t ref_dgSym[SHA256_DIGEST_SIZE] = {
                0x65a16cb7U, 0x861335d5U, 0xace3c607U, 0x18b5052eU, 0x44660726U, 0xda4cd13bU, 0xb745381bU, 0x235a1785U,
            };

            convStreamToSymbol256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

            updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)tv_mesStm, tv_sz);

            finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

            printf("SHA-256 #%u: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

            printf("================================================================================\n");
        }
        /* #6) 64 bytes of zeros                            */
        {
            printf("--------------------------------------------------------------------------------\n");

            uint32_t tv_num = 6U;
            uint8_t tv_mesStm[SHA256_BLOCK_SIZE] = { 0x0u, };
            const size_t tv_sz = 64UL;
            const uint32_t ref_dgSym[SHA256_DIGEST_SIZE] = {
                0xf5a5fd42U, 0xd16a2030U, 0x2798ef6eU, 0xd309979bU, 0x43003d23U, 0x20d9f0e8U, 0xea9831a9U, 0x2759fb4bU,
            };

            convStreamToSymbol256((uint32_t*)tv_mesStm, (const uint32_t*)tv_mesStm, sizeof(tv_mesStm));

            startSha256(g_sha256Dg32bSym, (const uint32_t*)H0_256, sizeof(H0_256));

            updateSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym), (uint32_t*)tv_mesStm, tv_sz);

            finishSha256(g_sha256Dg32bSym, sizeof(g_sha256Dg32bSym));

            printf("SHA-256 #%u: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

            printf("================================================================================\n");
        }
        /* #7) 1000 bytes of zeros                          */
        {
            printf("--------------------------------------------------------------------------------\n");

            uint32_t tv_num = 7U;
            uint8_t tv_mesStm[SHA256_BLOCK_SIZE];
            const size_t tv_sz = 1000UL;
            const uint32_t ref_dgSym[SHA256_DIGEST_SIZE] = {
                0x541b3e9dU, 0xaa09b20bU, 0xf85fa273U, 0xe5cbd3e8U, 0x0185aa4eU, 0xc298e765U, 0xdb87742bU, 0x70138a53U,
            };
            size_t tv_chSz, tv_remSz, tv_prcSz;
            (void)memset(tv_mesStm, 0, SHA256_BLOCK_SIZE);

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

            printf("SHA-256 #%u: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

            printf("================================================================================\n");
        }
        /* #8) 1000 bytes of 0x41 ‘A’                       */
        {
            printf("--------------------------------------------------------------------------------\n");

            uint32_t tv_num = 8U;
            uint8_t tv_mesStm[SHA256_BLOCK_SIZE];
            const size_t tv_sz = 1000UL;
            const uint32_t ref_dgSym[SHA256_DIGEST_SIZE] = {
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

            printf("SHA-256 #%u: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

            printf("================================================================================\n");
        }
        /* #9) 1005 bytes of 0x55 ‘U’                       */
        {
            printf("--------------------------------------------------------------------------------\n");

            uint32_t tv_num = 9U;
            uint8_t tv_mesStm[SHA256_BLOCK_SIZE];
            const size_t tv_sz = 1005UL;
            const uint32_t ref_dgSym[SHA256_DIGEST_SIZE] = {
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

            printf("SHA-256 #%u: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

            printf("================================================================================\n");
        }
        /* #10) 1000000 bytes of zeros                      */
        {
            printf("--------------------------------------------------------------------------------\n");

            uint32_t tv_num = 10U;
            uint8_t tv_mesStm[SHA256_BLOCK_SIZE];
            const size_t tv_sz = 1000000UL;
            const uint32_t ref_dgSym[SHA256_DIGEST_SIZE] = {
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

            printf("SHA-256 #%u: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

            printf("================================================================================\n");
        }
        /* #11) 0x20000000 (536870912) bytes of 0x5a ‘Z’    */
        {
            printf("--------------------------------------------------------------------------------\n");

            uint32_t tv_num = 11U;
            uint8_t tv_mesStm[SHA256_BLOCK_SIZE];
            const size_t tv_sz = 536870912UL;
            const uint32_t ref_dgSym[SHA256_DIGEST_SIZE] = {
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

            printf("SHA-256 #%u: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

            printf("================================================================================\n");
        }
        /* #12) 0x41000000 (1090519040) bytes of zeros      */
        {
            printf("--------------------------------------------------------------------------------\n");

            uint32_t tv_num = 12U;
            uint8_t tv_mesStm[SHA256_BLOCK_SIZE];
            const size_t tv_sz = 1090519040UL;
            const uint32_t ref_dgSym[SHA256_DIGEST_SIZE] = {
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

            printf("SHA-256 #%u: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

            printf("================================================================================\n");
        }
        /* #13) 0x6000003e (1610612798) bytes of 0x42 ‘B’   */
        {
            printf("--------------------------------------------------------------------------------\n");

            uint32_t tv_num = 13U;
            uint8_t tv_mesStm[SHA256_BLOCK_SIZE];
            const size_t tv_sz = 1610612798UL;
            const uint32_t ref_dgSym[SHA256_DIGEST_SIZE] = {
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

            printf("SHA-256 #%u: ", tv_num);
            printf("%s\n",((memcmp(ref_dgSym, g_sha256Dg32bSym, SHA256_DIGEST_SIZE) == 0)?"PASS":"FAIL"));

            printf("================================================================================\n");
        }
    }
}

void test_sha256(void)
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

    /* Print init Hash and Const Value */
    {
        printf("--------------------------------------------------------------------------------\n");

        for(size_t i = 0; i < sizeof(H0_256)/sizeof(uint32_t); i++)
        {
            printf("H[%2lu] = 0x%08x ", i, ((uint32_t*)H0_256)[i]);
            if((i != 0U) && ((i&0x3U) == 0x03)) printf("\n");
        }
        printf("\n");

        for(size_t i = 0; i < sizeof(K256)/sizeof(uint32_t); i++)
        {
            printf("K[%2lu] = 0x%08x ", i, ((uint32_t*)K256)[i]);
            if((i != 0U) && ((i&0x3U) == 0x03)) printf("\n");
        }
        printf("\n");

        printf("================================================================================\n");
    }
    testSha256_environments();

    test_CAVP();
    test_FIPS_180_2_imVal();
    test_FIPS_180_2_example_SHA2_Additional();
}
#endif /* TEST_SHA */

void test_sequence(void) {
    test_macro();
    test_ntype();
    test_ghash();

#ifdef TEST_SHA
    test_sha256();
#endif /* TEST_SHA */
}

int main(int argc, char** argv) {
    printf("arg:%d, ",argc);
    for(unsigned int i=0; i<argc; i++) {
        printf("arg[%d]:%s, ", i, argv[i]);
    }
    printf("\r\n");

    test_sequence();
}
