#include "ghash/gf128.h"
#include "common/util.h"
#include "common/bitwise.h"
#include <stdbool.h>
#include <string.h>

int gf128_mul_sftl_u32(uint32_t* z, uint32_t* x, uint32_t* y)
{
#define TMP_Yi_idx(bit)             ((bit) >> 5U)
#define TMP_Yi_mv0(bit)             ((bit) & 0x1FU)
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

        for(size_t i = 0UL; i < BYTE2BITS(GHASH_SIZE); i++)
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

int gf128_mul_sftr_u32(uint32_t* z, uint32_t* x, uint32_t* y)
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

        for(size_t i = BYTE2BITS(GHASH_SIZE) - 1UL; i != SIZE_MAX; i--)
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
        uint8_t buf_X[GHASH_SIZE];
        uint8_t reg_Y[GHASH_SIZE];
        size_t iter;
        size_t prcSize, remSize;

        //memset(buf_X, 0, sizeof(buf_X)); // Not required
        memcpy(reg_Y, ghash, sizeof(reg_Y));
        iter = size >> 4UL;// divide by 16(=GHASH_SIZE)
        prcSize = 0UL;
        remSize = size;
        for(size_t i = 0UL; i < iter; i++)
        {
            xor_u32((uint32_t*)buf_X, (uint32_t*)reg_Y, (uint32_t*)(&data[prcSize]), GHASH_U32_LEN);
            gf128_mul_sftr_u32_byte_swap((uint32_t*)reg_Y, (uint32_t*)buf_X, (uint32_t*)H);
            prcSize += GHASH_SIZE;
            remSize -= GHASH_SIZE;
        }

        if(remSize != 0UL)
        {
#if 1
            /* calculating aad tail method 1 */
            xor_u8(buf_X, reg_Y, &data[prcSize], remSize);
            memcpy(&buf_X[remSize], &reg_Y[remSize], (GHASH_SIZE - remSize));
#else
            /* calculating aad tail method 2, is equavalent with method 1 */
            xor_u8(reg_Y, reg_Y, &data[prcSize], remSize);
#endif
            gf128_mul_sftr_u32_byte_swap((uint32_t*)reg_Y, (uint32_t*)buf_X, (uint32_t*)H);
            prcSize += remSize;
            remSize -= remSize;
        }

        memcpy(ghash, reg_Y, GHASH_SIZE);
    }
    else
    {
        fs = -1;
    }

    return fs;
}

