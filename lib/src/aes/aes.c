#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "aes/aes.h"

#ifdef DEBUG
#define TEST_PRINT_U32_VALUE
#define TEST_PRINT_ARRAY_VALUE
#else
#undef TEST_PRINT_U32_VALUE
#undef TEST_PRINT_ARRAY_VALUE
#endif

#ifdef TEST_PRINT_U32_VALUE
#define DBG_PRINT_U32(U32VAR, INDEX, VAR_NAME)  {                       \
    printf("[%ld]%s => ", (INDEX), (VAR_NAME));                         \
    uint8_t* tmp_u8p = (uint8_t*)(&(U32VAR));                           \
    for(size_t tmp_u8i = 0UL; tmp_u8i < sizeof(uint32_t); tmp_u8i++)    \
        printf("%02x ", tmp_u8p[tmp_u8i]);                              \
    printf("\r\n");                                                     \
}
#else
#define DBG_PRINT_U32(U32VAR, INDEX, VAR_NAME)
#endif /* TEST_PRINT_U32_VALUE */

#ifdef TEST_PRINT_ARRAY_VALUE
#define DBG_PRINT_ARRAY(ARRAY, AR_SIZE, TITLE, LF)  {                   \
    printf("[%s]\r\n", (TITLE));                                        \
    uint8_t* tmp_u8p = (uint8_t*)(&(ARRAY));                            \
    for(size_t ti = 0UL; ti < (AR_SIZE); ti++)                          \
    {                                                                   \
        if((ti % (LF)) == 0UL)          printf("0x%016lx: ", ti);       \
        printf("%02x ", tmp_u8p[ti]);                                   \
        if((ti % (LF)) == ((LF) - 1UL)) printf("\r\n");                 \
    }                                                                   \
}
#define DBG_PRINT_4X4_MATRIX(ARRAY, TITLE)  {                           \
    printf("[%s]\r\n", (TITLE));                                        \
    uint8_t* tmp_u8p = (uint8_t*)(&(ARRAY));                            \
    for(size_t ti = 0UL; ti < 4UL; ti++)                                \
    {                                                                   \
        printf("%02x ", tmp_u8p[4UL*0UL+ti]);                           \
        printf("%02x ", tmp_u8p[4UL*1UL+ti]);                           \
        printf("%02x ", tmp_u8p[4UL*2UL+ti]);                           \
        printf("%02x ", tmp_u8p[4UL*3UL+ti]);                           \
        printf("\r\n");                                                 \
    }                                                                   \
}
#else
#define DBG_PRINT_ARRAY(ARRAY, AR_SIZE, TITLE, LF)
#define DBG_PRINT_4X4_MATRIX(ARRAY, TITLE)
#endif /* TEST_PRINT_ARRAY_VALUE */

/* Define AES Specifications */
// Number is count of word(32bits)
// AES COMMON
#define AES_Nb      4U
#define AES_Nr_BASE 6U

// AES128
#define AES128_Nk   4U
#define AES128_Nb   4U
#define AES128_Nr   10U
// AES192
#define AES192_Nk   6U
#define AES192_Nb   4U
#define AES192_Nr   12U
// AES256
#define AES256_Nk   8U
#define AES256_Nb   4U
#define AES256_Nr   14U

#define EXP_KEY_MAX_SIZE    (60U*4U)

/* Decalre Types */
typedef int (*fn_aesCipher)(uint8_t*, const uint8_t*, const uint8_t, const uint32_t*);

/* Declare Internal Variables */
static size_t l_Nr;
static uint8_t l_extKey[EXP_KEY_MAX_SIZE];
static uint8_t l_state[4][4] = {0};
static fn_aesCipher l_fp_cipher = NULL;

/* Declare Internal Function */
/* Galois Field */
static uint8_t gf8_mul2(const uint8_t v);
static uint8_t gf8_mulInv(const uint8_t v, const uint8_t c);
/*******************************************************************************
 * A brief AES Key Expansion
 *
 * AES key Expansion
 *
 * @param w     [out]   Word array for the key schedule
 *                      (Words = 32bits, Round(=Nr) per proc block size = 16B)
 *                      Initial: round = 0
 *                      Process: 0 < round < Nr
 *                      Finish : round = Nr
 *                      AES128(Nr=d10): 40-Words + 4-Word(Last round key) = 44Word
 *                      AES192(Nr=d12): 48-Words + 4-Word(Last round key) = 52Word
 *                      AES256(Nr=d14): 56-Words + 4-Word(Last round key) = 64Word
 * @param key   [in]    AES key(Bytes array)
 * @param Nk    [in]    Number of key for word
 *                      AES128(Nk=d4)
 *                      AES192(Nk=d6) : using index 0~7
 *                      AES256(Nk=d8) : using index 0~6
 * @param Nr    [in]    Number of round
 *                      AES128(Nr=d10)
 *                      AES192(Nr=d12)
 *                      AES256(Nr=d14)
 * @return              Result of function call
 *
 ******************************************************************************/
static int keyExpansion(const uint8_t* key, const size_t Nk, const size_t Nr);
static int keyExpansionEIC(const uint8_t* key, const size_t Nk, const size_t Nr);

/*******************************************************************************
 * A brief AES CIPHER
 *
 * AES CIPHER
 *
 * @param out   [out]   Output Data(Bytes array, 128bits -> 16Bytes)
 * @param in    [in]    Input Data(Bytes array, 128bits -> 16Bytes)
 * @param Nr    [in]    The number of rounds
 * @param w     [in]    Word array for the key schedule
 * @return              Result of function call
 *
 ******************************************************************************/
static int doCipher(uint8_t* out, const uint8_t* in, const uint8_t Nr, const uint32_t* w);
static int doCipherInv(uint8_t* out, const uint8_t* in, const uint8_t Nr, const uint32_t* dw);
static int doCipherInv2(uint8_t* out, const uint8_t* in, const uint8_t Nr, const uint32_t* w);

static int addRoundKey(uint32_t* s, const uint32_t* w);

#define subWord(w)  subByte((uint8_t*)(&(w)), sizeof(w))
static int subByte(uint8_t* w, const size_t size);
static int subByteInv(uint8_t* w, const size_t size);

#define rotWord(w) shiftColumn(&(w), sizeof(w)/sizeof(uint32_t))
static int shiftColumn(uint32_t* w, const size_t wLen);

static int shiftRows(uint8_t* s, const size_t size);
static int shiftRowsInv(uint8_t* s, const size_t size);

static int mixColumns(uint8_t* s, const size_t size);
static int mixColumnsInv(uint8_t* s, const size_t size);

/* Implement Function */
static uint8_t gf8_mul2(const uint8_t v)
{
#define _GF_X8_   0x1bU
    if(v&0x80)
    {
        return ((v<<1U) ^ _GF_X8_);
    }
    else
    {
        return (v<<1U);
    }
#undef _GF_X8_
}

static uint8_t gf8_mulInv(const uint8_t v, const uint8_t c)
{
#define _GF_X8_   0x1bU
#define _GF_X9_   0x36U
#define _GF_X10_  0x6cU
    uint16_t tmp = (((uint16_t)v)<<3U);
    uint8_t r;

    switch(c)
    {
        case 0xeU:
            tmp ^= ((((uint16_t)v)<<2U) ^ (((uint16_t)v)<<1U));
        break;
        case 0xdU:
            tmp ^= ((((uint16_t)v)<<2U) ^ (((uint16_t)v)<<0U));
        break;
        case 0xbU:
            tmp ^= ((((uint16_t)v)<<1U) ^ (((uint16_t)v)<<0U));
        break;
        case 0x9U:
            tmp ^= (((uint16_t)v)<<0U);
        break;

        default:
            tmp = 0U;
        break;
    }
    r = (uint8_t)(tmp & 0xffU);
    if((tmp & 0x100U) != 0x0U)  r ^= _GF_X8_;
    if((tmp & 0x200U) != 0x0U)  r ^= _GF_X9_;
    if((tmp & 0x400U) != 0x0U)  r ^= _GF_X10_;

    return r;
#undef _GF_X8_
#undef _GF_X9_
#undef _GF_X10_
}

const uint8_t g_SBOX[0x10U * 0x10U] = 
{
/* column(=x) \ row(=y) */
/* x\y   00     01     02     03     04     05     06     07     08     09     0a     0b     0c     0d     0e     0f */
/* 00 */ 0x63U, 0x7cU, 0x77U, 0x7bU, 0xf2U, 0x6bU, 0x6fU, 0xc5U, 0x30U, 0x01U, 0x67U, 0x2bU, 0xfeU, 0xd7U, 0xabU, 0x76U, 
/* 10 */ 0xcaU, 0x82U, 0xc9U, 0x7dU, 0xfaU, 0x59U, 0x47U, 0xf0U, 0xadU, 0xd4U, 0xa2U, 0xafU, 0x9cU, 0xa4U, 0x72U, 0xc0U, 
/* 20 */ 0xb7U, 0xfdU, 0x93U, 0x26U, 0x36U, 0x3fU, 0xf7U, 0xccU, 0x34U, 0xa5U, 0xe5U, 0xf1U, 0x71U, 0xd8U, 0x31U, 0x15U, 
/* 30 */ 0x04U, 0xc7U, 0x23U, 0xc3U, 0x18U, 0x96U, 0x05U, 0x9aU, 0x07U, 0x12U, 0x80U, 0xe2U, 0xebU, 0x27U, 0xb2U, 0x75U, 
/* 40 */ 0x09U, 0x83U, 0x2cU, 0x1aU, 0x1bU, 0x6eU, 0x5aU, 0xa0U, 0x52U, 0x3bU, 0xd6U, 0xb3U, 0x29U, 0xe3U, 0x2fU, 0x84U, 
/* 50 */ 0x53U, 0xd1U, 0x00U, 0xedU, 0x20U, 0xfcU, 0xb1U, 0x5bU, 0x6aU, 0xcbU, 0xbeU, 0x39U, 0x4aU, 0x4cU, 0x58U, 0xcfU, 
/* 60 */ 0xd0U, 0xefU, 0xaaU, 0xfbU, 0x43U, 0x4dU, 0x33U, 0x85U, 0x45U, 0xf9U, 0x02U, 0x7fU, 0x50U, 0x3cU, 0x9fU, 0xa8U, 
/* 70 */ 0x51U, 0xa3U, 0x40U, 0x8fU, 0x92U, 0x9dU, 0x38U, 0xf5U, 0xbcU, 0xb6U, 0xdaU, 0x21U, 0x10U, 0xffU, 0xf3U, 0xd2U, 
/* 80 */ 0xcdU, 0x0cU, 0x13U, 0xecU, 0x5fU, 0x97U, 0x44U, 0x17U, 0xc4U, 0xa7U, 0x7eU, 0x3dU, 0x64U, 0x5dU, 0x19U, 0x73U, 
/* 90 */ 0x60U, 0x81U, 0x4fU, 0xdcU, 0x22U, 0x2aU, 0x90U, 0x88U, 0x46U, 0xeeU, 0xb8U, 0x14U, 0xdeU, 0x5eU, 0x0bU, 0xdbU, 
/* a0 */ 0xe0U, 0x32U, 0x3aU, 0x0aU, 0x49U, 0x06U, 0x24U, 0x5cU, 0xc2U, 0xd3U, 0xacU, 0x62U, 0x91U, 0x95U, 0xe4U, 0x79U, 
/* b0 */ 0xe7U, 0xc8U, 0x37U, 0x6dU, 0x8dU, 0xd5U, 0x4eU, 0xa9U, 0x6cU, 0x56U, 0xf4U, 0xeaU, 0x65U, 0x7aU, 0xaeU, 0x08U, 
/* c0 */ 0xbaU, 0x78U, 0x25U, 0x2eU, 0x1cU, 0xa6U, 0xb4U, 0xc6U, 0xe8U, 0xddU, 0x74U, 0x1fU, 0x4bU, 0xbdU, 0x8bU, 0x8aU, 
/* d0 */ 0x70U, 0x3eU, 0xb5U, 0x66U, 0x48U, 0x03U, 0xf6U, 0x0eU, 0x61U, 0x35U, 0x57U, 0xb9U, 0x86U, 0xc1U, 0x1dU, 0x9eU, 
/* e0 */ 0xe1U, 0xf8U, 0x98U, 0x11U, 0x69U, 0xd9U, 0x8eU, 0x94U, 0x9bU, 0x1eU, 0x87U, 0xe9U, 0xceU, 0x55U, 0x28U, 0xdfU, 
/* f0 */ 0x8cU, 0xa1U, 0x89U, 0x0dU, 0xbfU, 0xe6U, 0x42U, 0x68U, 0x41U, 0x99U, 0x2dU, 0x0fU, 0xb0U, 0x54U, 0xbbU, 0x16U, 
};

const uint8_t g_SBOX_inv[0x10U * 0x10U] = 
{
/* column(=x) \ row(=y) */
/* x\y   00     01     02     03     04     05     06     07     08     09     0a     0b     0c     0d     0e     0f */
/* 00 */ 0x52U, 0x09U, 0x6aU, 0xd5U, 0x30U, 0x36U, 0xa5U, 0x38U, 0xbfU, 0x40U, 0xa3U, 0x9eU, 0x81U, 0xf3U, 0xd7U, 0xfbU, 
/* 10 */ 0x7cU, 0xe3U, 0x39U, 0x82U, 0x9bU, 0x2fU, 0xffU, 0x87U, 0x34U, 0x8eU, 0x43U, 0x44U, 0xc4U, 0xdeU, 0xe9U, 0xcbU, 
/* 20 */ 0x54U, 0x7bU, 0x94U, 0x32U, 0xa6U, 0xc2U, 0x23U, 0x3dU, 0xeeU, 0x4cU, 0x95U, 0x0bU, 0x42U, 0xfaU, 0xc3U, 0x4eU, 
/* 30 */ 0x08U, 0x2eU, 0xa1U, 0x66U, 0x28U, 0xd9U, 0x24U, 0xb2U, 0x76U, 0x5bU, 0xa2U, 0x49U, 0x6dU, 0x8bU, 0xd1U, 0x25U, 
/* 40 */ 0x72U, 0xf8U, 0xf6U, 0x64U, 0x86U, 0x68U, 0x98U, 0x16U, 0xd4U, 0xa4U, 0x5cU, 0xccU, 0x5dU, 0x65U, 0xb6U, 0x92U, 
/* 50 */ 0x6cU, 0x70U, 0x48U, 0x50U, 0xfdU, 0xedU, 0xb9U, 0xdaU, 0x5eU, 0x15U, 0x46U, 0x57U, 0xa7U, 0x8dU, 0x9dU, 0x84U, 
/* 60 */ 0x90U, 0xd8U, 0xabU, 0x00U, 0x8cU, 0xbcU, 0xd3U, 0x0aU, 0xf7U, 0xe4U, 0x58U, 0x05U, 0xb8U, 0xb3U, 0x45U, 0x06U, 
/* 70 */ 0xd0U, 0x2cU, 0x1eU, 0x8fU, 0xcaU, 0x3fU, 0x0fU, 0x02U, 0xc1U, 0xafU, 0xbdU, 0x03U, 0x01U, 0x13U, 0x8aU, 0x6bU, 
/* 80 */ 0x3aU, 0x91U, 0x11U, 0x41U, 0x4fU, 0x67U, 0xdcU, 0xeaU, 0x97U, 0xf2U, 0xcfU, 0xceU, 0xf0U, 0xb4U, 0xe6U, 0x73U, 
/* 90 */ 0x96U, 0xacU, 0x74U, 0x22U, 0xe7U, 0xadU, 0x35U, 0x85U, 0xe2U, 0xf9U, 0x37U, 0xe8U, 0x1cU, 0x75U, 0xdfU, 0x6eU, 
/* a0 */ 0x47U, 0xf1U, 0x1aU, 0x71U, 0x1dU, 0x29U, 0xc5U, 0x89U, 0x6fU, 0xb7U, 0x62U, 0x0eU, 0xaaU, 0x18U, 0xbeU, 0x1bU, 
/* b0 */ 0xfcU, 0x56U, 0x3eU, 0x4bU, 0xc6U, 0xd2U, 0x79U, 0x20U, 0x9aU, 0xdbU, 0xc0U, 0xfeU, 0x78U, 0xcdU, 0x5aU, 0xf4U, 
/* c0 */ 0x1fU, 0xddU, 0xa8U, 0x33U, 0x88U, 0x07U, 0xc7U, 0x31U, 0xb1U, 0x12U, 0x10U, 0x59U, 0x27U, 0x80U, 0xecU, 0x5fU, 
/* d0 */ 0x60U, 0x51U, 0x7fU, 0xa9U, 0x19U, 0xb5U, 0x4aU, 0x0dU, 0x2dU, 0xe5U, 0x7aU, 0x9fU, 0x93U, 0xc9U, 0x9cU, 0xefU, 
/* e0 */ 0xa0U, 0xe0U, 0x3bU, 0x4dU, 0xaeU, 0x2aU, 0xf5U, 0xb0U, 0xc8U, 0xebU, 0xbbU, 0x3cU, 0x83U, 0x53U, 0x99U, 0x61U, 
/* f0 */ 0x17U, 0x2bU, 0x04U, 0x7eU, 0xbaU, 0x77U, 0xd6U, 0x26U, 0xe1U, 0x69U, 0x14U, 0x63U, 0x55U, 0x21U, 0x0cU, 0x7dU, 
};

/* 
 * AES128(Nk=4) : using 1~10
 * AES192(Nk=6) : using 1~8
 * AES256(Nk=8) : using 1~7
 */
const uint32_t g_Rcon[11] = 
{
    0x00000000U,    // Index 0 is dummy => Not used
    0x00000001U,
    0x00000002U,
    0x00000004U,
    0x00000008U,
    0x00000010U,
    0x00000020U,
    0x00000040U,
    0x00000080U,
    0x0000001bU,
    0x00000036U,
};

static int keyExpansion(const uint8_t* key, const size_t Nk, const size_t Nr)
{
    uint32_t wTemp;
    const uint32_t* wKey = (const uint32_t*)key;         // w:word
    uint32_t* w = (uint32_t*)l_extKey;    // w:word
    size_t wi;
    (void)memset(w, 0x0, sizeof(l_extKey));

    // Set word index
    wi = 0UL;
    // Copy AES key to expansion key
    while(wi <= Nk -1UL)
    {
        w[wi] = wKey[wi];
        DBG_PRINT_U32(w[wi], wi, "w");
        wi++;
    }

    while(wi <= (4UL*Nr+3UL))
    {
        wTemp = w[wi-1UL];
        DBG_PRINT_U32(wTemp, wi, "wTemp");
        if((wi % Nk) == 0UL)
        {
            (void)rotWord(wTemp);
            DBG_PRINT_U32(wTemp, wi, "rotWord");
            (void)subWord(wTemp);
            DBG_PRINT_U32(wTemp, wi, "subByte");
            wTemp = wTemp ^ (g_Rcon[wi/Nk]);
            DBG_PRINT_U32(g_Rcon[wi/Nk], wi, "Rcon");
            DBG_PRINT_U32(wTemp, wi, "xorRcon");
        }
        else if((Nk > 6UL) && ((wi % Nk) == 4UL))
        {
            (void)subByte((uint8_t*)(&wTemp), sizeof(wTemp));
        }
        else
        {
            /* Do Nothing */
        }
        w[wi] = w[wi-Nk] ^ wTemp;
        wi++;
    }
    DBG_PRINT_ARRAY(l_extKey, sizeof(l_extKey), "EXPANSION_KEY", 4UL);
    return 0;
}

static int keyExpansionEIC(const uint8_t* key, const size_t Nk, const size_t Nr)
{
    uint32_t dwTemp;
    const uint32_t* wKey = (const uint32_t*)key;        // dw:word
    uint32_t* dw = (uint32_t*)l_extKey;     // dw:word
    size_t wi;
    (void)memset(dw, 0x0, sizeof(l_extKey));

    // Set word index
    wi = 0UL;
    // Copy AES key to expansion key
    while(wi <= Nk -1UL)
    {
        dw[wi] = wKey[wi];
        DBG_PRINT_U32(dw[wi], wi, "dw");
        wi++;
    }

    while(wi <= (4UL*Nr+3UL))
    {
        dwTemp = dw[wi-1UL];
        DBG_PRINT_U32(dwTemp, wi, "dwTemp");
        if((wi % Nk) == 0UL)
        {
            (void)rotWord(dwTemp);
            DBG_PRINT_U32(dwTemp, wi, "rotWord");
            (void)subWord(dwTemp);
            DBG_PRINT_U32(dwTemp, wi, "subByte");
            dwTemp = dwTemp ^ (g_Rcon[wi/Nk]);
            DBG_PRINT_U32(g_Rcon[wi/Nk], wi, "Rcon");
            DBG_PRINT_U32(dwTemp, wi, "xorRcon");
        }
        else if((Nk > 6UL) && ((wi % Nk) == 4UL))
        {
            (void)subByte((uint8_t*)(&dwTemp), sizeof(dwTemp));
        }
        else
        {
            /* Do Nothing */
        }
        dw[wi] = dw[wi-Nk] ^ dwTemp;
        wi++;
    }
    for(size_t round = 1; round <= Nr - 1UL; round++)
    {
        (void)mixColumnsInv((uint8_t*)(&dw[(round<<2UL)]), AES_S_SIZE);
    }
    DBG_PRINT_ARRAY(l_extKey, sizeof(l_extKey), "EXPANSION_KEY_EIC", 4UL);

    return 0;
}

static int doCipher(uint8_t* out, const uint8_t* in, const uint8_t Nr, const uint32_t* w)
{
    int fs = 0;
    if((out != NULL) && (in != NULL) && (w != NULL))
    {
        size_t round;
#ifdef DEBUG
        printf("Input\r\n");
#endif /* DEBUG */
        (void)memcpy(l_state, in, (sizeof(uint32_t)*AES_Nb));
        DBG_PRINT_4X4_MATRIX(l_state, "input");

        round = 0UL;
#ifdef DEBUG
        printf("Round Number = %ld\r\n", round);
#endif /* DEBUG */

        if(fs == 0) fs = addRoundKey((uint32_t*)l_state, &w[AES_Nb*round]);
        DBG_PRINT_4X4_MATRIX(w[AES_Nb*round], "Round Key Value");
        DBG_PRINT_4X4_MATRIX(l_state, "After addRoundKey");

        if(fs == 0)
        {
            for(round = 1UL; round < Nr; round++)
            {
#ifdef DEBUG
                printf("Round Number = %ld\r\n", round);
#endif /* DEBUG */
                DBG_PRINT_4X4_MATRIX(l_state, "Start of Round");

                if(fs == 0) fs = subByte((uint8_t*)l_state, sizeof(l_state));
                DBG_PRINT_4X4_MATRIX(l_state, "After SubBytes");

                if(fs == 0) fs = shiftRows((uint8_t*)l_state, sizeof(l_state));
                DBG_PRINT_4X4_MATRIX(l_state, "After ShiftRows");

                if(fs == 0) fs = mixColumns((uint8_t*)l_state, sizeof(l_state));
                DBG_PRINT_4X4_MATRIX(l_state, "After MixColumns");

                DBG_PRINT_4X4_MATRIX(w[AES_Nb*round], "Round Key Value");
                if(fs == 0) fs = addRoundKey((uint32_t*)l_state, &w[AES_Nb*round]);
                DBG_PRINT_4X4_MATRIX(l_state, "After addRoundKey");
            }
#ifdef DEBUG
            printf("Round Number = %ld\r\n", round);
#endif /* DEBUG */
            DBG_PRINT_4X4_MATRIX(l_state, "End of Round");

            if(fs == 0) fs = subByte((uint8_t*)l_state, sizeof(l_state));
            DBG_PRINT_4X4_MATRIX(l_state, "After SubBytes");

            if(fs == 0) fs = shiftRows((uint8_t*)l_state, sizeof(l_state));
            DBG_PRINT_4X4_MATRIX(l_state, "After ShiftRows");

            if(fs == 0) fs = addRoundKey((uint32_t*)l_state, &w[AES_Nb*Nr]);
            DBG_PRINT_4X4_MATRIX(w[AES_Nb*round], "Round Key Value");
        }
#ifdef DEBUG
        printf("Output\r\n");
#endif /* DEBUG */
        (void)memcpy(out, l_state, (sizeof(uint32_t)*AES_Nb));
        DBG_PRINT_4X4_MATRIX(l_state, "output");
    }
    else
    {
        fs = -1;
    }

    return fs;
}

static int doCipherInv(uint8_t* out, const uint8_t* in, const uint8_t Nr, const uint32_t* dw)
{
    int fs = 0;
    if((out != NULL) && (in != NULL) && (dw != NULL))
    {
        size_t round;
#ifdef DEBUG
        printf("Input\r\n");
#endif /* DEBUG */
        (void)memcpy(l_state, in, (sizeof(uint32_t)*AES_Nb));
        DBG_PRINT_4X4_MATRIX(l_state, "input");

        round = Nr;
#ifdef DEBUG
        printf("Inv Round Number = %ld\r\n", round);
#endif /* DEBUG */

        if(fs == 0) fs = addRoundKey((uint32_t*)l_state, &dw[AES_Nb*round]);
        DBG_PRINT_4X4_MATRIX(dw[AES_Nb*round], "Inv Round Key Value");
        DBG_PRINT_4X4_MATRIX(l_state, "After Inv addRoundKey");

        if(fs == 0)
        {
            for(round = (size_t)(Nr - 1U); round > 0UL; round--)
            {
#ifdef DEBUG
                printf("Inv Round Number = %ld\r\n", round);
#endif /* DEBUG */
                DBG_PRINT_4X4_MATRIX(l_state, "Start of Inv Round");

                if(fs == 0) fs = subByteInv((uint8_t*)l_state, sizeof(l_state));
                DBG_PRINT_4X4_MATRIX(l_state, "After Inv SubBytes");

                if(fs == 0) fs = shiftRowsInv((uint8_t*)l_state, sizeof(l_state));
                DBG_PRINT_4X4_MATRIX(l_state, "After Inv ShiftRows");

                if(fs == 0) fs = mixColumnsInv((uint8_t*)l_state, sizeof(l_state));
                DBG_PRINT_4X4_MATRIX(l_state, "After Inv MixColumns");

                DBG_PRINT_4X4_MATRIX(dw[AES_Nb*round], "Inv Round Key Value");
                if(fs == 0) fs = addRoundKey((uint32_t*)l_state, &dw[AES_Nb*round]);
                DBG_PRINT_4X4_MATRIX(l_state, "After Inv addRoundKey");

            }
#ifdef DEBUG
            printf("Inv Round Number = %ld\r\n", round);
#endif /* DEBUG */
            DBG_PRINT_4X4_MATRIX(l_state, "End of Round");

            if(fs == 0) fs = subByteInv((uint8_t*)l_state, sizeof(l_state));
            DBG_PRINT_4X4_MATRIX(l_state, "After Inv SubBytes");

            if(fs == 0) fs = shiftRowsInv((uint8_t*)l_state, sizeof(l_state));
            DBG_PRINT_4X4_MATRIX(l_state, "After Inv ShiftRows");

            if(fs == 0) fs = addRoundKey((uint32_t*)l_state, &dw[AES_Nb*0U]);
            DBG_PRINT_4X4_MATRIX(dw[AES_Nb*round], "Inv Round Key Value");
        }
#ifdef DEBUG
        printf("Output\r\n");
#endif /* DEBUG */
        (void)memcpy(out, l_state, (sizeof(uint32_t)*AES_Nb));
        DBG_PRINT_4X4_MATRIX(l_state, "output");
    }
    else
    {
        fs = -1;
    }

    return fs;
}

static int doCipherInv2(uint8_t* out, const uint8_t* in, const uint8_t Nr, const uint32_t* w)
{
    int fs = 0;
    if((out != NULL) && (in != NULL) && (w != NULL))
    {
        size_t round;
#ifdef DEBUG
        printf("Input\r\n");
#endif /* DEBUG */
        (void)memcpy(l_state, in, (sizeof(uint32_t)*AES_Nb));
        DBG_PRINT_4X4_MATRIX(l_state, "input");

        round = Nr;
#ifdef DEBUG
        printf("Inv Round Number = %ld\r\n", round);
#endif /* DEBUG */

        if(fs == 0) fs = addRoundKey((uint32_t*)l_state, &w[AES_Nb*round]);
        DBG_PRINT_4X4_MATRIX(w[AES_Nb*round], "Round Key Value");
        DBG_PRINT_4X4_MATRIX(l_state, "After addRoundKey");

        if(fs == 0) fs = subByteInv((uint8_t*)l_state, sizeof(l_state));
        DBG_PRINT_4X4_MATRIX(l_state, "After Inv SubBytes");

        if(fs == 0) fs = shiftRowsInv((uint8_t*)l_state, sizeof(l_state));
        DBG_PRINT_4X4_MATRIX(l_state, "After Inv ShiftRows");

        if(fs == 0)
        {
            for(round = (size_t)(Nr - 1U); round > 0UL; round--)
            {
#ifdef DEBUG
                printf("Inv Round Number = %ld\r\n", round);
#endif /* DEBUG */
                DBG_PRINT_4X4_MATRIX(l_state, "Start of Inv Round");

                DBG_PRINT_4X4_MATRIX(w[AES_Nb*round], "Round Key Value");
                if(fs == 0) fs = addRoundKey((uint32_t*)l_state, &w[AES_Nb*round]);
                DBG_PRINT_4X4_MATRIX(l_state, "After addRoundKey");

                if(fs == 0) fs = mixColumnsInv((uint8_t*)l_state, sizeof(l_state));
                DBG_PRINT_4X4_MATRIX(l_state, "After Inv MixColumns");

                if(fs == 0) fs = shiftRowsInv((uint8_t*)l_state, sizeof(l_state));
                DBG_PRINT_4X4_MATRIX(l_state, "After Inv ShiftRows");

                if(fs == 0) fs = subByteInv((uint8_t*)l_state, sizeof(l_state));
                DBG_PRINT_4X4_MATRIX(l_state, "After Inv SubBytes");
            }
#ifdef DEBUG
            printf("Inv Round Number = %ld\r\n", round);
#endif /* DEBUG */
            DBG_PRINT_4X4_MATRIX(l_state, "End of Round");
            if(fs == 0) fs = addRoundKey((uint32_t*)l_state, &w[AES_Nb*0U]);
            DBG_PRINT_4X4_MATRIX(w[AES_Nb*round], "Round Key Value");
        }
#ifdef DEBUG
        printf("Output\r\n");
#endif /* DEBUG */
        (void)memcpy(out, l_state, (sizeof(uint32_t)*AES_Nb));
        DBG_PRINT_4X4_MATRIX(l_state, "output");
    }
    else
    {
        fs = -1;
    }

    return fs;
}

static int addRoundKey(uint32_t* s, const uint32_t* w)
{
    int fs = 0;

    if((s != NULL) && (w != NULL))
    {
        for(size_t c = 0UL; c < AES_Nb; c++)
        {
            s[c] = s[c] ^ w[c];
        }
    }
    else
    {
        fs = -1;
    }

    return fs;
}

static int subByte(uint8_t* w, const size_t size)
{
    int fs = 0;

    if(w != NULL)
    {
        for(size_t i = 0UL; i < size; i++)
        {
            w[i] = g_SBOX[w[i]];
        }
    }
    else
    {
        fs = -1;
    }

    return fs;
}

static int subByteInv(uint8_t* w, const size_t size)
{
    int fs = 0;

    if(w != NULL)
    {
        for(size_t i = 0UL; i < size; i++)
        {
            w[i] = g_SBOX_inv[w[i]];
        }
    }
    else
    {
        fs = -1;
    }

    return fs;
}

static int shiftColumn(uint32_t* w, const size_t wLen)
{
    int fs = 0;

    if(w != NULL)
    {
        for(size_t wIdx = 0UL; wIdx < wLen; wIdx++)
        {
            w[wIdx] = (((w[wIdx])>>8U) | ((w[wIdx])<<24U));
        }
    }
    else
    {
        fs = -1;
    }
    return fs;
}

static int shiftRows(uint8_t* s, const size_t size)
{
    int fs = 0;

    uint8_t sp [4][4];

    if(s != NULL)
    {
        (void)memcpy(sp, s, size);
        // in r = 0, any values are not changed
        // // sr is abbreviation of a start row
        for(unsigned int sr = 1U; sr < 4U; sr++)
        {
            for(unsigned int r = sr; r < 4U; r++)
            {
                // have to alternates rotWord() using function(option: internal) or defined macros
                uint8_t s0 = sp[0UL][r]; // back up w(r,0) state value to shift w(r,3)
                for(size_t c = 0UL; c < 3UL; c++)
                {
                    sp[c][r] = sp[c+1U][r];
                }
                sp[3U][r] = s0;
            }
        }
        (void)memcpy(s, sp, size);
    }
    else
    {
        fs = -1;
    }
    return fs;
}

static int shiftRowsInv(uint8_t* s, const size_t size)
{
    int fs = 0;

    uint8_t sp [4][4];

    if(s != NULL)
    {
        (void)memcpy(sp, s, size);
        // in r = 0, any values are not changed
        // // sr is abbreviation of a start row
        for(unsigned int sr = 1U; sr < 4U; sr++)
        {
            for(unsigned int r = sr; r < 4U; r++)
            {
                // have to alternates rotWord() using function(option: internal) or defined macros
                uint8_t s3 = sp[3UL][r]; // back up w(3,r) state value to shift w(0,r)
                for(size_t c = 3UL; c > 0UL; c--)
                {
                    sp[c][r] = sp[c-1U][r];
                }
                sp[0UL][r] = s3;
            }
        }
        (void)memcpy(s, sp, size);
    }
    else
    {
        fs = -1;
    }
    return fs;
}

static int mixColumns(uint8_t* s, const size_t size)
{
#define _GF8_MUL1_(v)   (v)
#define _GF8_MUL2_(v)   (gf8_mul2(v))
#define _GF8_MUL3_(v)   (gf8_mul2(v) ^ (v))

    int fs = 0;

    uint8_t sp [4][4];
    uint8_t sb [4][4];  // s buffer
    (void)memcpy(sb, s, size);

    // r = 0
    for(unsigned int c = 0; c < 4; c++)
    {
        sp[c][0] = _GF8_MUL2_(sb[c][0]) ^ _GF8_MUL3_(sb[c][1])
                      ^ _GF8_MUL1_(sb[c][2]) ^ _GF8_MUL1_(sb[c][3]);
    }
    // r = 1
    for(unsigned int c = 0; c < 4; c++)
    {
        sp[c][1] = _GF8_MUL1_(sb[c][0]) ^ _GF8_MUL2_(sb[c][1])
                      ^ _GF8_MUL3_(sb[c][2]) ^ _GF8_MUL1_(sb[c][3]);
    }
    // r = 2
    for(unsigned int c = 0; c < 4; c++)
    {
        sp[c][2] = _GF8_MUL1_(sb[c][0]) ^ _GF8_MUL1_(sb[c][1])
                      ^ _GF8_MUL2_(sb[c][2]) ^ _GF8_MUL3_(sb[c][3]);
    }
    // r = 3
    for(unsigned int c = 0; c < 4; c++)
    {
        sp[c][3] = _GF8_MUL3_(sb[c][0]) ^ _GF8_MUL1_(sb[c][1])
                      ^ _GF8_MUL1_(sb[c][2]) ^ _GF8_MUL2_(sb[c][3]);
    }

    (void)memcpy(s, sp, size);

    return fs;
#undef _GF8_MUL1_
#undef _GF8_MUL2_
#undef _GF8_MUL3_
    return fs;
}

static int mixColumnsInv(uint8_t* s, const size_t size)
{
#define _GF8_MULe_(v)   gf8_mulInv(v, 0xeU)
#define _GF8_MULb_(v)   gf8_mulInv(v, 0xbU)
#define _GF8_MULd_(v)   gf8_mulInv(v, 0xdU)
#define _GF8_MUL9_(v)   gf8_mulInv(v, 0x9U)

    int fs = 0;

    uint8_t sp [4][4];
    uint8_t sb [4][4];  // s buffer
    (void)memcpy(sb, s, size);

    // r = 0
    for(unsigned int c = 0; c < 4; c++)
    {
        sp[c][0] = _GF8_MULe_(sb[c][0]) ^ _GF8_MULb_(sb[c][1])
                      ^ _GF8_MULd_(sb[c][2]) ^ _GF8_MUL9_(sb[c][3]);
    }
    // r = 1
    for(unsigned int c = 0; c < 4; c++)
    {
        sp[c][1] = _GF8_MUL9_(sb[c][0]) ^ _GF8_MULe_(sb[c][1])
                      ^ _GF8_MULb_(sb[c][2]) ^ _GF8_MULd_(sb[c][3]);
    }
    // r = 2
    for(unsigned int c = 0; c < 4; c++)
    {
        sp[c][2] = _GF8_MULd_(sb[c][0]) ^ _GF8_MUL9_(sb[c][1])
                      ^ _GF8_MULe_(sb[c][2]) ^ _GF8_MULb_(sb[c][3]);
    }
    // r = 3
    for(unsigned int c = 0; c < 4; c++)
    {
        sp[c][3] = _GF8_MULb_(sb[c][0]) ^ _GF8_MULd_(sb[c][1])
                      ^ _GF8_MUL9_(sb[c][2]) ^ _GF8_MULe_(sb[c][3]);
    }

    (void)memcpy(s, sp, size);

    return fs;
#undef _GF8_MULe_
#undef _GF8_MULb_
#undef _GF8_MULd_
#undef _GF8_MUL9_
}

int aesEncV1(uint8_t* out, const uint8_t* in, const uint8_t* key, const size_t kSize)
{
    int fs = 0;

    size_t Nk = (kSize>>2UL);
    size_t Nr = (((size_t)AES_Nr_BASE)+(kSize>>2UL));

    if(fs == 0) fs = keyExpansion(key, Nk, Nr);
    if(fs == 0) fs = doCipher(out, in, Nr, (uint32_t*)l_extKey);

    return fs;
}

int aesDecV1(uint8_t* out, const uint8_t* in, const uint8_t* key, const size_t kSize)
{
    int fs = 0;

    size_t Nk = (kSize>>2UL);
    size_t Nr = (((size_t)AES_Nr_BASE)+(kSize>>2UL));

    if(fs == 0) fs = keyExpansionEIC(key, Nk, Nr);
    if(fs == 0) fs = doCipherInv(out, in, Nr, (uint32_t*)l_extKey);

    return fs;
}

int aesDecV2(uint8_t* out, const uint8_t* in, const uint8_t* key, const size_t kSize)
{
    int fs = 0;

    size_t Nk = (kSize>>2UL);
    size_t Nr = (((size_t)AES_Nr_BASE)+(kSize>>2UL));

    if(fs == 0) fs = keyExpansion(key, Nk, Nr);
    if(fs == 0) fs = doCipherInv2(out, in, Nr, (uint32_t*)l_extKey);

    return fs;
}

int startAes(const uint8_t* key, const size_t kSize, const bool decrypt)
{
    int fs = 0;

    size_t Nk = (kSize>>2UL);

    l_Nr = (((size_t)AES_Nr_BASE)+(kSize>>2UL));

    if(fs == 0) fs = keyExpansion(key, Nk, l_Nr);
    if(!decrypt)l_fp_cipher = doCipher;
    else        l_fp_cipher = doCipherInv2;

    return fs;
}

int updateAes(uint8_t* out, const uint8_t* in, const size_t size)
{
#define _SIZE_MASK_ (AES_S_SIZE - 1U)
    int fs = 0;

    if((size & _SIZE_MASK_) == 0UL)
    {
        for(size_t i = 0UL; i < size; i+=AES_S_SIZE)
        {
            fs = l_fp_cipher(&out[i], &in[i], l_Nr, (uint32_t*)l_extKey);
            if(fs != 0) break;
        }
    }
    else
    {
        fs = -1;
    }

    return fs;
#undef _SIZE_MASK_
}

int finishAes(void)
{
    return 0;
}

#ifdef SELFTEST
#define RUN_TEST(STATEMENTS, FRTN)                  \
{                                                   \
    if(((FRTN) = (STATEMENTS)) != 0)                \
    {                                               \
        printf("%s=%d\r\n", "STATEMENT", (FRTN));   \
    }                                               \
}

#define EXAM_TEST(STATEMENTS, DESCRIPTION)                      \
{                                                               \
    bool examResult = ((STATEMENTS));                           \
    printf("%s:%s\r\n", (examResult?"PASS":"FAIL"), (DESCRIPTION));\
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

void test_doCipher(void)
{
    printf("%s:%d:%s\r\n", __FILE__, __LINE__, __func__);

    int fRtn;
    (void)memset(test_AES_out, 0x0, sizeof(test_AES_out));

    RUN_TEST(keyExpansion(tv_AES128_key, AES128_Nk, AES128_Nr), fRtn);
    RUN_TEST(doCipher(test_AES_out, tv_AES128_FIPS197_pTxt_ref, AES128_Nr, (uint32_t*)l_extKey), fRtn);
    DBG_PRINT_ARRAY(test_AES_out, sizeof(test_AES_out), "NIST, FIPS197, May 9, 2023, Appendix B - Cipher Example(AES128)", 4UL);
    EXAM_TEST(memcmp(test_AES_out, tv_AES128_FIPS197_cTxt_ref, sizeof(tv_AES128_FIPS197_cTxt_ref)) == 0, \
            "NIST, FIPS197, AES128 TestVector");
}

void test_doCipherInv(void)
{
    printf("%s:%d:%s\r\n", __FILE__, __LINE__, __func__);

    int fRtn;
    (void)memset(test_AES_out, 0x0, sizeof(test_AES_out));

    RUN_TEST(keyExpansionEIC(tv_AES128_key, AES128_Nk, AES128_Nr), fRtn);
    RUN_TEST(doCipherInv(test_AES_out, tv_AES128_FIPS197_cTxt_ref, AES128_Nr, (uint32_t*)l_extKey), fRtn);
    DBG_PRINT_ARRAY(test_AES_out, sizeof(test_AES_out), "NIST, FIPS197, May 9, 2023, Appendix B - Inv Cipher Example(AES128)", 4UL);
    EXAM_TEST(memcmp(test_AES_out, tv_AES128_FIPS197_pTxt_ref, sizeof(tv_AES128_FIPS197_pTxt_ref)) == 0, \
            "NIST, FIPS197, AES128 TestVector");
}

void test_doCipherInv2(void)
{
    printf("%s:%d:%s\r\n", __FILE__, __LINE__, __func__);

    int fRtn;
    (void)memset(test_AES_out, 0x0, sizeof(test_AES_out));

    RUN_TEST(keyExpansion(tv_AES128_key, AES128_Nk, AES128_Nr), fRtn);
    RUN_TEST(doCipherInv2(test_AES_out, tv_AES128_FIPS197_cTxt_ref, AES128_Nr, (uint32_t*)l_extKey), fRtn);
    DBG_PRINT_ARRAY(test_AES_out, sizeof(test_AES_out), "NIST, FIPS197, May 9, 2023, Appendix B - Inv Cipher Example(AES128)", 4UL);
    EXAM_TEST(memcmp(test_AES_out, tv_AES128_FIPS197_pTxt_ref, sizeof(tv_AES128_FIPS197_pTxt_ref)) == 0, \
            "NIST, FIPS197, AES128 TestVector");
}

void test_aesEncV1(void)
{
    printf("%s:%d:%s\r\n", __FILE__, __LINE__, __func__);

    int fRtn;

    printf("[AES128 Encryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES_NIST_Ex_pTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        RUN_TEST(aesEncV1(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], tv_AES128_key, sizeof(tv_AES128_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        EXAM_TEST(memcmp(test_AES_out, tv_AES128_NIST_Ex_cTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES128 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Encrypt Values", AES_S_SIZE);
    }

    printf("[AES192 Encryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES_NIST_Ex_pTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        RUN_TEST(aesEncV1(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], tv_AES192_key, sizeof(tv_AES192_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        EXAM_TEST(memcmp(test_AES_out, tv_AES192_NIST_Ex_cTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES192 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Encrypt Values", AES_S_SIZE);
    }

    printf("[AES256 Encryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES_NIST_Ex_pTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        RUN_TEST(aesEncV1(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], tv_AES256_key, sizeof(tv_AES256_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        EXAM_TEST(memcmp(test_AES_out, tv_AES256_NIST_Ex_cTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES256 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Encrypt Values", AES_S_SIZE);
    }
}

void test_aesDecV1(void)
{
    printf("%s:%d:%s\r\n", __FILE__, __LINE__, __func__);

    int fRtn;

    printf("[AES128 Decryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES128_NIST_Ex_cTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        RUN_TEST(aesDecV1(test_AES_out, tv_AES128_NIST_Ex_cTxt_ref[tvi], tv_AES128_key, sizeof(tv_AES128_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        EXAM_TEST(memcmp(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES128 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Decrypt Values", AES_S_SIZE);
    }

    printf("[AES192 Decryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES192_NIST_Ex_cTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        RUN_TEST(aesDecV1(test_AES_out, tv_AES192_NIST_Ex_cTxt_ref[tvi], tv_AES192_key, sizeof(tv_AES192_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        EXAM_TEST(memcmp(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES192 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Decrypt Values", AES_S_SIZE);
    }

    printf("[AES256 Decryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES256_NIST_Ex_cTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        RUN_TEST(aesDecV1(test_AES_out, tv_AES256_NIST_Ex_cTxt_ref[tvi], tv_AES256_key, sizeof(tv_AES256_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        EXAM_TEST(memcmp(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES256 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Decrypt Values", AES_S_SIZE);
    }

}

void test_aesDecV2(void)
{
    int fRtn;
    printf("%s:%d:%s\r\n", __FILE__, __LINE__, __func__);

    printf("[AES128 Decryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES128_NIST_Ex_cTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        RUN_TEST(aesDecV2(test_AES_out, tv_AES128_NIST_Ex_cTxt_ref[tvi], tv_AES128_key, sizeof(tv_AES128_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        EXAM_TEST(memcmp(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES128 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Decrypt Values", AES_S_SIZE);
    }

    printf("[AES192 Decryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES192_NIST_Ex_cTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        RUN_TEST(aesDecV2(test_AES_out, tv_AES192_NIST_Ex_cTxt_ref[tvi], tv_AES192_key, sizeof(tv_AES192_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        EXAM_TEST(memcmp(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES192 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Decrypt Values", AES_S_SIZE);
    }

    printf("[AES256 Decryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES256_NIST_Ex_cTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        RUN_TEST(aesDecV2(test_AES_out, tv_AES256_NIST_Ex_cTxt_ref[tvi], tv_AES256_key, sizeof(tv_AES256_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        EXAM_TEST(memcmp(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], AES_S_SIZE) == 0, \
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
    aesEncV1(test_AES_out, test_allZero, test_gcm211_key, sizeof(test_gcm211_key));
    printHex(test_AES_out, sizeof(test_AES_out), "2.1.1. GCM, H", AES_S_SIZE);
}

int main(int argc, char* argv[])
{
    int fRtn;
    uint32_t u32_v = 0xfedcba98U;
    uint8_t u8a_p[4] = {0x98U,0xbaU,0xdcU,0xfeU};

    printf("[rotWord test]");
    printf("u32_v(origin): 0x%08x\r\n", u32_v);
    printHex((void*)(&u32_v), sizeof(u32_v), "u32_v(origin)",  0UL);
    RUN_TEST(rotWord(u32_v), fRtn);
    printf("u32_v(result): 0x%08x\r\n", u32_v);
    printHex((void*)(&u32_v), sizeof(u32_v), "u32_v(result)",  0UL);

    printHex((void*)(u8a_p), sizeof(u8a_p), "u8a_p(origin)", 0UL);
    RUN_TEST(rotWord((*((uint32_t*)u8a_p))), fRtn);
    printHex((void*)(u8a_p), sizeof(u8a_p), "u8a_p(result)", 0UL);

#ifdef DEBUG
    printf("[TEST: AES128 keyExpansion]\r\n");
    RUN_TEST(keyExpansion(tv_AES128_key, AES128_Nk, AES128_Nr), fRtn);

    printf("[TEST: AES192 keyExpansion]\r\n");
    RUN_TEST(keyExpansion(tv_AES192_key, AES192_Nk, AES192_Nr), fRtn);

    printf("[TEST: AES256 keyExpansion]\r\n");
    RUN_TEST(keyExpansion(tv_AES256_key, AES256_Nk, AES256_Nr), fRtn);
#endif /* DEBUG */

    test_doCipher();

    test_aesEncV1();

    test_doCipherInv();

    test_aesDecV1();

    test_doCipherInv2();

    test_aesDecV2();

    test_aes_blanks(); // calcaulates AES-GCM H

    return 0;
}
#endif /* SELFTEST */
