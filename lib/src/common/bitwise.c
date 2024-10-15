#include "common/bitwise.h"

int xor_u32(uint32_t* z, uint32_t* x, uint32_t* y, size_t length)
{
    int fs = 0;

    BITWISE_OPERATION(z, x, y, length, ^, fs);

    return fs;
}

int xor_u8(uint8_t* z, uint8_t* x, uint8_t* y, size_t size)
{
    int fs = 0;

    BITWISE_OPERATION(z, x, y, size, ^, fs);

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

