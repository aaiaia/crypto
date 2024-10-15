#include "ghash/gf128.h"
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define TMP_byte2bit(bytes)     ((bytes) << 3U)
#define TMP_byte2word(bytes)    ((bytes) >> 2U)

static int gf128_mul_sftl_u32(uint32_t* z, uint32_t* x, uint32_t* y);
static int gf128_mul_sftr_u32(uint32_t* z, uint32_t* x, uint32_t* y);

int xor_u32(uint32_t* z, uint32_t* x, uint32_t* y, size_t length)
{
    int fs = 0;

    if(z != NULL && x != NULL && y != NULL)
    {
        for(size_t i = 0U; i < length; i++)
        {
           z[i] = x[i] ^ y[i];
        }
    }
    else
    {
        fs = -1;
    }

    return fs;
}

int xor_u8(uint8_t* z, uint8_t* x, uint8_t* y, size_t size)
{
    int fs = 0;

    if(z != NULL && x != NULL && y != NULL)
    {
        for(size_t i = 0U; i < size; i++)
        {
           z[i] = x[i] ^ y[i];
        }
    }
    else
    {
        fs = -1;
    }

    return fs;
}

bool sftl_u32(uint32_t* z, uint32_t* x, size_t length)
{
    bool c_i_lsb = false;
    bool c_o_msb = false;
    for(size_t i = 0U; i < (length); i++)
    {
        c_o_msb = ((x[i] & (0x1U << 31U)) != 0x0U);
        z[i] = ((x[i] << 1U) | (c_i_lsb ? (0x1U << 0U) : 0x0U));
        c_i_lsb = c_o_msb;
    }
    return c_o_msb;
}

bool sftr_u32(uint32_t* z, uint32_t* x, size_t length)
{
    bool c_i_msb = false;
    bool c_o_lsb = false;
    for(size_t i = (length - 1UL); i != SIZE_MAX; i--)
    {
        c_o_lsb = ((x[(i)] & (0x1U << 0U)) != 0x0U);
        z[i] = ((x[(i)] >> 1U) | (c_i_msb ? (0x1U << 31U) : 0x0U));
        c_i_msb = c_o_lsb;
    }
    return c_o_lsb;
}

static int gf128_mul_sftl_u32(uint32_t* z, uint32_t* x, uint32_t* y)
{
#define TMP_Yi_idx(bit)             ((bit) >> 5U)
#define TMP_Yi_mv0(bit)            ((bit) & 0x1FU)
#define TMP_Yi_is_1_cond(bit, Y)    (((((Y)[TMP_Yi_idx(bit)]) >> TMP_Yi_mv0(bit)) & 0x1U) != 0x0U)
#define TMP_XOR_IDX                 (0U)
#define TMP_GF128_MOD               (((uint32_t)GHASH_LSB_POLY) << 0U)
    int fs = 0;

    if((z != NULL) && (x != NULL) && (y != NULL))
    {
        bool carry = false;
        uint32_t u32_z[GHASH_U32_LEN];
        uint32_t u32_v[GHASH_U32_LEN];
        (void)memset((void*)u32_z, 0, ((size_t)GHASH_SIZE));
        (void)memcpy((void*)u32_v, (void*)x, ((size_t)GHASH_SIZE));

        for(size_t i = 0UL; i < TMP_byte2bit(GHASH_SIZE); i++)
        {
            if(TMP_Yi_is_1_cond(i, y))
            {
                xor_u32(u32_z, u32_z, u32_v, GHASH_U32_LEN);
            }
            else
            {
                /* Do Nothing */
            }

            carry = sftl_u32(u32_v, u32_v, GHASH_U32_LEN);
            u32_v[TMP_XOR_IDX] ^= (carry ? TMP_GF128_MOD : 0x0U);
        }

        (void)memcpy(z, u32_z, ((size_t)GHASH_SIZE));
    }
    else
    {
        fs = -1;
    }

    return fs;
#undef TMP_Yi_idx
#undef TMP_Yi_mv0
#undef TMP_Yi_is_1_cond
#undef TMP_XOR_IDX
#undef TMP_GF128_MOD
}

static int gf128_mul_sftr_u32(uint32_t* z, uint32_t* x, uint32_t* y)
{
#define TMP_Yi_idx(bit)             ((bit) >> 5U)
#define TMP_Yi_mv0(bit)             ((bit) & 0x1FU)
#define TMP_Yi_is_1_cond(bit, Y)    ((((Y)[TMP_Yi_idx(bit)] >> TMP_Yi_mv0(bit)) & (1UL << 0UL)) != 0x0U)
#define TMP_XOR_IDX                 (GHASH_U32_LEN - 1U)
#define TMP_GF128_MOD               (((uint32_t)GHASH_MSB_POLY) << 24U)
    int fs = 0;

    if((z != NULL) && (x != NULL) && (y != NULL))
    {
        bool carry = false;
        uint32_t u32_z[GHASH_U32_LEN];
        uint32_t u32_v[GHASH_U32_LEN];
        (void)memset((void*)u32_z, 0, ((size_t)GHASH_SIZE));
        (void)memcpy((void*)u32_v, (void*)x, ((size_t)GHASH_SIZE));

        for(size_t i = TMP_byte2bit(GHASH_SIZE) - 1UL; i != SIZE_MAX; i--)
        {
            if(TMP_Yi_is_1_cond(i, y))
            {
                xor_u32(u32_z, u32_z, u32_v, GHASH_U32_LEN);
            }
            else
            {
                /* Do Nothing */
            }

            carry = sftr_u32(u32_v, u32_v, GHASH_U32_LEN);
            u32_v[TMP_XOR_IDX] ^= (carry ? TMP_GF128_MOD : 0x0U);
        }

        (void)memcpy(z, u32_z, ((size_t)GHASH_SIZE));
    }
    else
    {
        fs = -1;
    }

    return fs;
#undef TMP_Yi_idx
#undef TMP_Yi_mv0
#undef TMP_Yi_is_1_cond
#undef TMP_XOR_IDX
#undef TMP_GF128_MOD
}

#if 0 /* DISABLE_bitReflect128_u32 */
int bitReflect128_u32(uint32_t* vi, uint32_t* vf)
{
    int fs = 0;
    uint32_t invMsk;
    uint32_t msk;

    if(vi != NULL && vf != NULL)
    {
        invMsk = 0x80000000U;
        msk = 0x00000001U;
        vi[3] = 0U;
        for(unsigned int i = 0U; i < 32U; i++)
        {
            if(vf[0] & msk)  vi[3] = vi[3] | invMsk;
            invMsk = invMsk >> 1U;
            msk = msk << 1U;
        }

        invMsk = 0x80000000U;
        msk = 0x00000001U;
        vi[2] = 0U;
        for(unsigned int i = 0U; i < 32U; i++)
        {
            if(vf[1] & msk)  vi[2] = vi[2] | invMsk;
            invMsk = invMsk >> 1U;
            msk = msk << 1U;
        }

        invMsk = 0x80000000U;
        msk = 0x00000001U;
        vi[1] = 0U;
        for(unsigned int i = 0U; i < 32U; i++)
        {
            if(vf[2] & msk)  vi[1] = vi[1] | invMsk;
            invMsk = invMsk >> 1U;
            msk = msk << 1U;
        }

        invMsk = 0x80000000U;
        msk = 0x00000001U;
        vi[0] = 0U;
        for(unsigned int i = 0U; i < 32U; i++)
        {
            if(vf[3] & msk)  vi[0] = vi[0] | invMsk;
            invMsk = invMsk >> 1U;
            msk = msk << 1U;
        }
    }
    else
    {
        fs = -1;
    }

    return fs;
}
#endif/* DISABLE_bitReflect128_u32 */

int bitReflect8_u8(uint8_t* vi, uint8_t* vf, size_t size)
{
    int fs = 0;
    uint8_t invMsk;
    uint8_t msk;

    if(vi != NULL && vf != NULL && size != 0UL)
    {
        for(size_t i = 0UL; i < size; i++)
        {
            uint8_t t = 0U;
            for(size_t j = 0UL; j < 8UL; j++)
            {
                if((vf[i] >> j) & 0x01U)
                {
                    t |= (1U << ((8UL - 1UL) - j));
                }
            }
            vi[i] = t;
        }
    }
    else
    {
        fs = -1;
    }

    return fs;
}

int hexSwap(uint8_t* vs, uint8_t* vf, size_t size)
{
#define HEX_BIT_LEN 4U
    int fs = 0;

    if(vs != NULL && vf != NULL && size != 0UL)
    {
        for(size_t i = 0UL; i < size; i++)
        {
            vs[i] = ((vf[i] << HEX_BIT_LEN) | (vf[i] >> HEX_BIT_LEN));
        }
    }
    else
    {
        fs = -1;
    }

    return fs;
#undef HEX_BIT_LEN
}

int byteSwap(uint8_t* vs, uint8_t* vf, size_t size)
{
#define TMP_INV_IDX(idx, len)    (len - idx - 1UL)
    int fs = 0;

    if(vs != NULL && vf != NULL & size != 0UL)
    {
        for(size_t i = 0UL; i < (size >> 1UL); i++)
        {
            uint8_t t = vf[i];
            vs[i] = vf[TMP_INV_IDX(i, size)];
            vs[TMP_INV_IDX(i, size)] = t;
        }
    }
    else
    {
        fs = -1;
    }

    return fs;
#undef TMP_INV_IDX
}

int gf128_mul_sftl_u32_byte_reflect(uint32_t* z, uint32_t* x, uint32_t* y)
{
    int fs = 0;

    if((z != NULL) && (x != NULL) && (y != NULL))
    {
        uint32_t rfc_x[GHASH_U32_LEN];
        uint32_t rfc_y[GHASH_U32_LEN];
        uint32_t rfc_z[GHASH_U32_LEN];

        bitReflect8_u8((uint8_t*)rfc_x, (uint8_t*)x, GHASH_SIZE);

        bitReflect8_u8((uint8_t*)rfc_y, (uint8_t*)y, GHASH_SIZE);

        gf128_mul_sftl_u32(rfc_z, rfc_x, rfc_y);

        bitReflect8_u8((uint8_t*)z, (uint8_t*)rfc_z, GHASH_SIZE);
    }
    else
    {
        fs = -1;
    }

    return fs;
}

int gf128_mul_sftr_u32_byte_swap(uint32_t* z, uint32_t* x, uint32_t* y)
{
    int fs = 0;

    if((z != NULL) && (x != NULL) && (y != NULL))
    {
        uint32_t swp_x[GHASH_U32_LEN];
        uint32_t swp_y[GHASH_U32_LEN];
        uint32_t swp_z[GHASH_U32_LEN];

        byteSwap((uint8_t*)swp_x, (uint8_t*)x, GHASH_SIZE);

        byteSwap((uint8_t*)swp_y, (uint8_t*)y, GHASH_SIZE);

        gf128_mul_sftr_u32(swp_z, swp_x, swp_y);

        byteSwap((uint8_t*)z, (uint8_t*)swp_z, GHASH_SIZE);
    }
    else
    {
        fs = -1;
    }

    return fs;
}

int gf128_ghash(uint8_t* ghash, uint8_t* H, uint8_t* data, size_t size)
{
    int fs = 0;

    if(ghash != NULL && H != NULL && data != NULL)
    {
        uint8_t xor_x[GHASH_SIZE];
        uint8_t mul_y[GHASH_SIZE];
        size_t iter;
        size_t prcSize, remSize;

        memset(xor_x, 0, sizeof(xor_x));
        memset(mul_y, 0, sizeof(mul_y));
        iter = size >> 4UL;// divide by 16(=GHASH_SIZE)
        prcSize = 0UL;
        remSize = size;
        for(size_t i = 0UL; i < iter; i++)
        {
            xor_u32((uint32_t*)xor_x, (uint32_t*)mul_y, (uint32_t*)(&data[prcSize]), GHASH_U32_LEN);
            gf128_mul_sftr_u32_byte_swap((uint32_t*)mul_y, (uint32_t*)xor_x, (uint32_t*)H);
            prcSize += GHASH_SIZE;
            remSize -= GHASH_SIZE;
        }

        if(remSize != 0UL)
        {
            xor_u8(xor_x, mul_y, &data[prcSize], remSize);
            gf128_mul_sftr_u32_byte_swap((uint32_t*)mul_y, (uint32_t*)xor_x, (uint32_t*)H);
            prcSize += remSize;
            remSize -= remSize;
        }

        memcpy(ghash, mul_y, GHASH_SIZE);
    }
    else
    {
        fs = -1;
    }

    return fs;
}
#ifdef SELFTEST
#include <time.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
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

int main(void)
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

#undef TMP_byte2bit
#undef TMP_byte2word

#endif /* SELFTEST */
