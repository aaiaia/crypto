#ifdef DEBUG
#include <stdio.h>
#include <stdint.h>
#define dprintf(...)    printf(__VA_ARGS__)
void dprint_aesBlk(const char* title, const uint8_t* blk, const size_t bSize)
{
    size_t i;

    dprintf("[%s]\n", ((title != NULL)?title:"NO TITLE"));
    if(bSize != 0UL)
    {
        dprintf("0x ");
        for(i = 0UL; i < bSize; i++)
        {
            dprintf("%02x ", blk[i]);
            if(i == (bSize - 1UL))      dprintf("\n");
            else if((i&0xfU) == 0xfU)   dprintf("\n");
        }
    }
    else
    {
        dprintf("NO-DATA:0 bytes\n");
    }
}
#else
#define dprintf(...)
#define dprint_aesBlk(title, blk, bSize)
#endif /* DEBUG */

#include <stddef.h> // NULL, size_t
#include <stdint.h>
#include <string.h>

#include "aes/aes.h"

#define TMP_KEY_SIZE    32U // AES128: 16B, AES256: 32B

/*
 * https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
 * FIPS197, Advanced Encryption Standard (AES), NIST, May 9, 2023
 * Table 2. Indices for bytes and bits
 * Bit idx in seq   | 0| 1| 2| 3| 4| 5| 6| 7| 8| 9|10|11|12|13|14|15|...
 * Byte index       |           0           |            1          |...
 * Bit idx in byte  | 7| 6| 5| 4| 3| 2| 1| 0| 7| 6| 5| 4| 3| 2| 1| 0|...
 */
#define MSB1(X, L)  (((X)[0])>>7U)
#define LSB1(X, L)  (((X)[(L)-1U])&0x1U)

#define R64     0x1BU
#define R128    0x87U

#define ENDB    0x80U

/* Internal Variables */
static uint8_t tmp_l_key[TMP_KEY_SIZE];
static size_t tmp_l_kSize;
static uint8_t l_Nd[AES_S_SIZE];
static uint8_t l_K1[AES_S_SIZE];
static uint8_t l_K2[AES_S_SIZE];

/* Internal Funtions */
static void shl1BlkModByte_self(uint8_t* blk, const size_t bSize, const uint8_t byte);
static void genSubKey(const uint8_t* key, const size_t kSize);
static void xorBlk(uint8_t* out, const uint8_t* inA, const uint8_t* inB, const size_t bSize);

/* Implement Functions */
static void shl1BlkModByte_self(uint8_t* blk, const size_t bSize, const uint8_t byte)
{
    const uint8_t msb1 = MSB1(blk, bSize);

    for(size_t i = 0UL; i < bSize - 1UL; i++)
    {
        blk[i] = ((blk[i]<<1U)|(blk[i+1U]>>7U));
    }
    blk[bSize-1U] = (blk[bSize-1U]<<1U);
    if(msb1 != 0x0U)
    {
        blk[bSize-1U] ^= byte;
    }
}

static void genSubKey(const uint8_t* key, const size_t kSize)
{
    /* 0^b: 'l_Nd', L: 'l_K1' */
    (void)aesEnc(l_K1, l_Nd, key, kSize);
    dprint_aesBlk("L", l_K1, AES_S_SIZE);

    shl1BlkModByte_self(l_K1, AES_S_SIZE, R128);
    dprint_aesBlk("K1", l_K1, AES_S_SIZE);

    memcpy(l_K2, l_K1, AES_S_SIZE);
    shl1BlkModByte_self(l_K2, AES_S_SIZE, R128);
    dprint_aesBlk("K2", l_K2, AES_S_SIZE);
}

static void xorBlk(uint8_t* out, const uint8_t* inA, const uint8_t* inB, const size_t bSize)
{
    for(size_t i = 0UL; i < bSize; i++)
    {
        out[i] = (inA[i]^inB[i]);
    }
}

void startCmac(const uint8_t* key, const size_t kSize)
{
#if 1 /* Temporary_Implements: Backup 'key' and 'kSize' to 'tmp_l_key' and 'tmp_l_kSize' */
    (void)memcpy(tmp_l_key, key, TMP_KEY_SIZE);
    tmp_l_kSize = kSize;
#endif/* Temporary_Implements: Backup 'key' and 'kSize' to 'tmp_l_key' and 'tmp_l_kSize' */
    dprint_aesBlk("KEY", key, kSize);

    memset(l_Nd, 0, AES_S_SIZE);

    genSubKey(key, kSize);
}

void updateCmac(const uint8_t* mes, const size_t mSize)
{
    dprint_aesBlk("MES", mes, mSize);
    dprint_aesBlk("l_Nd", l_Nd, sizeof(l_Nd));

    /*
     * 'mSize' have to multiple of 'AES_S_SIZE'.
     * If not, 'mes' is became to lastest message.
     */
    xorBlk(l_Nd, l_Nd, mes, mSize);
    dprint_aesBlk("XOR(M)", l_Nd, sizeof(l_Nd));

#if 1 /* Temporary_Implements: function 'aesEnc()' is not consider zero size message */
    if(0UL < mSize)
    {
        (void)aesEnc(l_Nd, l_Nd, tmp_l_key, tmp_l_kSize);
        dprint_aesBlk("AES", l_Nd, sizeof(l_Nd));
    }
#endif/* Temporary_Implements: function 'aesEnc()' is not consider zero size message */
}

void finishCmac(uint8_t* tag, const uint8_t* mes, const size_t mSize)
{
    dprint_aesBlk("MES", mes, mSize);
    dprint_aesBlk("l_Nd", l_Nd, sizeof(l_Nd));

    xorBlk(l_Nd, l_Nd, mes, mSize);
    dprint_aesBlk("XOR(M)", l_Nd, sizeof(l_Nd));

    /* The condition of if statement is not consider that 'mSize' is larger then 'AES_S_SIZE' */
    if(mSize == AES_S_SIZE)
    {
        xorBlk(l_Nd, l_Nd, l_K1, AES_S_SIZE);
        dprint_aesBlk("XOR(K1)", l_Nd, sizeof(l_Nd));
    }
    else
    {
        l_Nd[mSize]^=ENDB;
        xorBlk(l_Nd, l_Nd, l_K2, AES_S_SIZE);
        dprint_aesBlk("XOR(K2)", l_Nd, sizeof(l_Nd));
    }
#if 1 /* Temporary_Implements: function 'aesEnc()' is not consider zero size message */
    (void)aesEnc(l_Nd, l_Nd, tmp_l_key, tmp_l_kSize);
#endif/* Temporary_Implements: function 'aesEnc()' is not consider zero size message */
    dprint_aesBlk("TAG", l_Nd, sizeof(l_Nd));

    (void)memcpy(tag, l_Nd, AES_S_SIZE);
}
