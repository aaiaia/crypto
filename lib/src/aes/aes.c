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

#define GF_X8   0x1bU
#define GF_X9   0x36U
#define GF_X10  0x6cU
uint8_t gf8_mul2(uint8_t v)
{
    if(v&0x80)
    {
        v = (v<<1U) ^ 0x1bU;
    }
    else
    {
        v = (v<<1U);
    }

    return v;
}

uint8_t gf8_mulInv(uint8_t v, uint8_t c)
{
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
    if((tmp & 0x100U) != 0x0U)  r ^= GF_X8;
    if((tmp & 0x200U) != 0x0U)  r ^= GF_X9;
    if((tmp & 0x400U) != 0x0U)  r ^= GF_X10;

    return r;
}
#undef GF_X8
#undef GF_X9
#undef GF_X10

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

static uint8_t g_state[4][4] = {0};

#define EXP_KEY_MAX_SIZE    (60U*4U)
static uint8_t g_extKey[EXP_KEY_MAX_SIZE];

int keyExpansion(uint8_t* key, size_t Nk, size_t Nr)
{
    uint32_t wTemp;
    uint32_t* wKey = (uint32_t*)key;         // w:word
    uint32_t* w = (uint32_t*)g_extKey;    // w:word
    size_t wi;
    (void)memset(w, 0x0, sizeof(g_extKey));

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
    DBG_PRINT_ARRAY(g_extKey, sizeof(g_extKey), "EXPANSION_KEY", 4UL);
    return 0;
}

int keyExpansionEIC(uint8_t* key, size_t Nk, size_t Nr)
{
    uint32_t dwTemp;
    uint32_t* wKey = (uint32_t*)key;        // dw:word
    uint32_t* dw = (uint32_t*)g_extKey;     // dw:word
    size_t wi;
    (void)memset(dw, 0x0, sizeof(g_extKey));

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
    DBG_PRINT_ARRAY(g_extKey, sizeof(g_extKey), "EXPANSION_KEY_EIC", 4UL);

    return 0;
}

int doCipher(uint8_t* out, uint8_t* in, uint8_t Nr, uint32_t* w)
{
    int fs = 0;
    if((out != NULL) && (in != NULL) && (w != NULL))
    {
        size_t round;
#ifdef DEBUG
        printf("Input\r\n");
#endif /* DEBUG */
        (void)memcpy(g_state, in, (sizeof(uint32_t)*AES_Nb));
        DBG_PRINT_4X4_MATRIX(g_state, "input");

        round = 0UL;
#ifdef DEBUG
        printf("Round Number = %ld\r\n", round);
#endif /* DEBUG */

        if(fs == 0) fs = addRoundKey((uint32_t*)g_state, &w[AES_Nb*round]);
        DBG_PRINT_4X4_MATRIX(w[AES_Nb*round], "Round Key Value");
        DBG_PRINT_4X4_MATRIX(g_state, "After addRoundKey");

        if(fs == 0)
        {
            for(round = 1UL; round < Nr; round++)
            {
#ifdef DEBUG
                printf("Round Number = %ld\r\n", round);
#endif /* DEBUG */
                DBG_PRINT_4X4_MATRIX(g_state, "Start of Round");

                if(fs == 0) fs = subByte((uint8_t*)g_state, sizeof(g_state));
                DBG_PRINT_4X4_MATRIX(g_state, "After SubBytes");

                if(fs == 0) fs = shiftRows((uint8_t*)g_state, sizeof(g_state));
                DBG_PRINT_4X4_MATRIX(g_state, "After ShiftRows");

                if(fs == 0) fs = mixColumns((uint8_t*)g_state, sizeof(g_state));
                DBG_PRINT_4X4_MATRIX(g_state, "After MixColumns");

                DBG_PRINT_4X4_MATRIX(w[AES_Nb*round], "Round Key Value");
                if(fs == 0) fs = addRoundKey((uint32_t*)g_state, &w[AES_Nb*round]);
                DBG_PRINT_4X4_MATRIX(g_state, "After addRoundKey");
            }
#ifdef DEBUG
            printf("Round Number = %ld\r\n", round);
#endif /* DEBUG */
            DBG_PRINT_4X4_MATRIX(g_state, "End of Round");

            if(fs == 0) fs = subByte((uint8_t*)g_state, sizeof(g_state));
            DBG_PRINT_4X4_MATRIX(g_state, "After SubBytes");

            if(fs == 0) fs = shiftRows((uint8_t*)g_state, sizeof(g_state));
            DBG_PRINT_4X4_MATRIX(g_state, "After ShiftRows");

            if(fs == 0) fs = addRoundKey((uint32_t*)g_state, &w[AES_Nb*Nr]);
            DBG_PRINT_4X4_MATRIX(w[AES_Nb*round], "Round Key Value");
        }
#ifdef DEBUG
        printf("Output\r\n");
#endif /* DEBUG */
        (void)memcpy(out, g_state, (sizeof(uint32_t)*AES_Nb));
        DBG_PRINT_4X4_MATRIX(g_state, "output");
    }
    else
    {
        fs = -1;
    }

    return fs;
}

int doCipherInv(uint8_t* out, uint8_t* in, uint8_t Nr, uint32_t* dw)
{
    int fs = 0;
    if((out != NULL) && (in != NULL) && (dw != NULL))
    {
        size_t round;
#ifdef DEBUG
        printf("Input\r\n");
#endif /* DEBUG */
        (void)memcpy(g_state, in, (sizeof(uint32_t)*AES_Nb));
        DBG_PRINT_4X4_MATRIX(g_state, "input");

        round = Nr;
#ifdef DEBUG
        printf("Inv Round Number = %ld\r\n", round);
#endif /* DEBUG */

        if(fs == 0) fs = addRoundKey((uint32_t*)g_state, &dw[AES_Nb*round]);
        DBG_PRINT_4X4_MATRIX(dw[AES_Nb*round], "Inv Round Key Value");
        DBG_PRINT_4X4_MATRIX(g_state, "After Inv addRoundKey");

        if(fs == 0)
        {
            for(round = (size_t)(Nr - 1U); round > 0UL; round--)
            {
#ifdef DEBUG
                printf("Inv Round Number = %ld\r\n", round);
#endif /* DEBUG */
                DBG_PRINT_4X4_MATRIX(g_state, "Start of Inv Round");

                if(fs == 0) fs = subByteInv((uint8_t*)g_state, sizeof(g_state));
                DBG_PRINT_4X4_MATRIX(g_state, "After Inv SubBytes");

                if(fs == 0) fs = shiftRowsInv((uint8_t*)g_state, sizeof(g_state));
                DBG_PRINT_4X4_MATRIX(g_state, "After Inv ShiftRows");

                if(fs == 0) fs = mixColumnsInv((uint8_t*)g_state, sizeof(g_state));
                DBG_PRINT_4X4_MATRIX(g_state, "After Inv MixColumns");

                DBG_PRINT_4X4_MATRIX(dw[AES_Nb*round], "Inv Round Key Value");
                if(fs == 0) fs = addRoundKey((uint32_t*)g_state, &dw[AES_Nb*round]);
                DBG_PRINT_4X4_MATRIX(g_state, "After Inv addRoundKey");

            }
#ifdef DEBUG
            printf("Inv Round Number = %ld\r\n", round);
#endif /* DEBUG */
            DBG_PRINT_4X4_MATRIX(g_state, "End of Round");

            if(fs == 0) fs = subByteInv((uint8_t*)g_state, sizeof(g_state));
            DBG_PRINT_4X4_MATRIX(g_state, "After Inv SubBytes");

            if(fs == 0) fs = shiftRowsInv((uint8_t*)g_state, sizeof(g_state));
            DBG_PRINT_4X4_MATRIX(g_state, "After Inv ShiftRows");

            if(fs == 0) fs = addRoundKey((uint32_t*)g_state, &dw[AES_Nb*0U]);
            DBG_PRINT_4X4_MATRIX(dw[AES_Nb*round], "Inv Round Key Value");
        }
#ifdef DEBUG
        printf("Output\r\n");
#endif /* DEBUG */
        (void)memcpy(out, g_state, (sizeof(uint32_t)*AES_Nb));
        DBG_PRINT_4X4_MATRIX(g_state, "output");
    }
    else
    {
        fs = -1;
    }

    return fs;
}

int doCipherInv2(uint8_t* out, uint8_t* in, uint8_t Nr, uint32_t* w)
{
    int fs = 0;
    if((out != NULL) && (in != NULL) && (w != NULL))
    {
        size_t round;
#ifdef DEBUG
        printf("Input\r\n");
#endif /* DEBUG */
        (void)memcpy(g_state, in, (sizeof(uint32_t)*AES_Nb));
        DBG_PRINT_4X4_MATRIX(g_state, "input");

        round = Nr;
#ifdef DEBUG
        printf("Inv Round Number = %ld\r\n", round);
#endif /* DEBUG */

        if(fs == 0) fs = addRoundKey((uint32_t*)g_state, &w[AES_Nb*round]);
        DBG_PRINT_4X4_MATRIX(w[AES_Nb*round], "Round Key Value");
        DBG_PRINT_4X4_MATRIX(g_state, "After addRoundKey");

        if(fs == 0) fs = subByteInv((uint8_t*)g_state, sizeof(g_state));
        DBG_PRINT_4X4_MATRIX(g_state, "After Inv SubBytes");

        if(fs == 0) fs = shiftRowsInv((uint8_t*)g_state, sizeof(g_state));
        DBG_PRINT_4X4_MATRIX(g_state, "After Inv ShiftRows");

        if(fs == 0)
        {
            for(round = (size_t)(Nr - 1U); round > 0UL; round--)
            {
#ifdef DEBUG
                printf("Inv Round Number = %ld\r\n", round);
#endif /* DEBUG */
                DBG_PRINT_4X4_MATRIX(g_state, "Start of Inv Round");

                DBG_PRINT_4X4_MATRIX(w[AES_Nb*round], "Round Key Value");
                if(fs == 0) fs = addRoundKey((uint32_t*)g_state, &w[AES_Nb*round]);
                DBG_PRINT_4X4_MATRIX(g_state, "After addRoundKey");

                if(fs == 0) fs = mixColumnsInv((uint8_t*)g_state, sizeof(g_state));
                DBG_PRINT_4X4_MATRIX(g_state, "After Inv MixColumns");

                if(fs == 0) fs = shiftRowsInv((uint8_t*)g_state, sizeof(g_state));
                DBG_PRINT_4X4_MATRIX(g_state, "After Inv ShiftRows");

                if(fs == 0) fs = subByteInv((uint8_t*)g_state, sizeof(g_state));
                DBG_PRINT_4X4_MATRIX(g_state, "After Inv SubBytes");
            }
#ifdef DEBUG
            printf("Inv Round Number = %ld\r\n", round);
#endif /* DEBUG */
            DBG_PRINT_4X4_MATRIX(g_state, "End of Round");
            if(fs == 0) fs = addRoundKey((uint32_t*)g_state, &w[AES_Nb*0U]);
            DBG_PRINT_4X4_MATRIX(w[AES_Nb*round], "Round Key Value");
        }
#ifdef DEBUG
        printf("Output\r\n");
#endif /* DEBUG */
        (void)memcpy(out, g_state, (sizeof(uint32_t)*AES_Nb));
        DBG_PRINT_4X4_MATRIX(g_state, "output");
    }
    else
    {
        fs = -1;
    }

    return fs;
}

int addRoundKey(uint32_t* s, uint32_t* w)
{
    int fs = 0;

    if(w != NULL)
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

int subByte(uint8_t* w, size_t size)
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

int subByteInv(uint8_t* w, size_t size)
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

int shiftColumn(uint32_t* w, size_t wLen)
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

int shiftRows(uint8_t* s, size_t size)
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

int shiftRowsInv(uint8_t* s, size_t size)
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

int mixColumns(uint8_t* s, size_t size)
{
#define GF8_MUL1(v) (v)
#define GF8_MUL2(v) (gf8_mul2(v))
#define GF8_MUL3(v) (gf8_mul2(v) ^ (v))

    int fs = 0;

    uint8_t sp [4][4];
    uint8_t sb [4][4];  // s buffer
    (void)memcpy(sb, s, size);

    // r = 0
    for(unsigned int c = 0; c < 4; c++)
    {
        sp[c][0] = GF8_MUL2(sb[c][0]) ^ GF8_MUL3(sb[c][1])
                      ^ GF8_MUL1(sb[c][2]) ^ GF8_MUL1(sb[c][3]);
    }
    // r = 1
    for(unsigned int c = 0; c < 4; c++)
    {
        sp[c][1] = GF8_MUL1(sb[c][0]) ^ GF8_MUL2(sb[c][1])
                      ^ GF8_MUL3(sb[c][2]) ^ GF8_MUL1(sb[c][3]);
    }
    // r = 2
    for(unsigned int c = 0; c < 4; c++)
    {
        sp[c][2] = GF8_MUL1(sb[c][0]) ^ GF8_MUL1(sb[c][1])
                      ^ GF8_MUL2(sb[c][2]) ^ GF8_MUL3(sb[c][3]);
    }
    // r = 3
    for(unsigned int c = 0; c < 4; c++)
    {
        sp[c][3] = GF8_MUL3(sb[c][0]) ^ GF8_MUL1(sb[c][1])
                      ^ GF8_MUL1(sb[c][2]) ^ GF8_MUL2(sb[c][3]);
    }

    (void)memcpy(s, sp, size);

    return fs;
#undef GF8_MUL1
#undef GF8_MUL2
#undef GF8_MUL3
    return fs;
}

int mixColumnsInv(uint8_t* s, size_t size)
{
#define GF8_MULe(v) gf8_mulInv(v, 0xeU)
#define GF8_MULb(v) gf8_mulInv(v, 0xbU)
#define GF8_MULd(v) gf8_mulInv(v, 0xdU)
#define GF8_MUL9(v) gf8_mulInv(v, 0x9U)

    int fs = 0;

    uint8_t sp [4][4];
    uint8_t sb [4][4];  // s buffer
    (void)memcpy(sb, s, size);

    // r = 0
    for(unsigned int c = 0; c < 4; c++)
    {
        sp[c][0] = GF8_MULe(sb[c][0]) ^ GF8_MULb(sb[c][1])
                      ^ GF8_MULd(sb[c][2]) ^ GF8_MUL9(sb[c][3]);
    }
    // r = 1
    for(unsigned int c = 0; c < 4; c++)
    {
        sp[c][1] = GF8_MUL9(sb[c][0]) ^ GF8_MULe(sb[c][1])
                      ^ GF8_MULb(sb[c][2]) ^ GF8_MULd(sb[c][3]);
    }
    // r = 2
    for(unsigned int c = 0; c < 4; c++)
    {
        sp[c][2] = GF8_MULd(sb[c][0]) ^ GF8_MUL9(sb[c][1])
                      ^ GF8_MULe(sb[c][2]) ^ GF8_MULb(sb[c][3]);
    }
    // r = 3
    for(unsigned int c = 0; c < 4; c++)
    {
        sp[c][3] = GF8_MULb(sb[c][0]) ^ GF8_MULd(sb[c][1])
                      ^ GF8_MUL9(sb[c][2]) ^ GF8_MULe(sb[c][3]);
    }

    (void)memcpy(s, sp, size);

    return fs;
#undef GF8_MULe
#undef GF8_MULb
#undef GF8_MULd
#undef GF8_MUL9
    return fs;
}

int aesEnc(uint8_t* out, uint8_t* in, uint8_t* key, size_t kSize)
{
    int fs = 0;

    size_t Nk = (kSize>>2UL);
    size_t Nr = (((size_t)AES_Nr_BASE)+(kSize>>2UL));

    if(fs == 0) fs = keyExpansion(key, Nk, Nr);
    if(fs == 0) fs = doCipher(out, in, Nr, (uint32_t*)g_extKey);

    return fs;
}

int aesDec(uint8_t* out, uint8_t* in, uint8_t* key, size_t kSize)
{
    int fs = 0;

    size_t Nk = (kSize>>2UL);
    size_t Nr = (((size_t)AES_Nr_BASE)+(kSize>>2UL));

    if(fs == 0) fs = keyExpansionEIC(key, Nk, Nr);
    if(fs == 0) fs = doCipherInv(out, in, Nr, (uint32_t*)g_extKey);

    return fs;
}

int aesDec2(uint8_t* out, uint8_t* in, uint8_t* key, size_t kSize)
{
    int fs = 0;

    size_t Nk = (kSize>>2UL);
    size_t Nr = (((size_t)AES_Nr_BASE)+(kSize>>2UL));

    if(fs == 0) fs = keyExpansion(key, Nk, Nr);
    if(fs == 0) fs = doCipherInv2(out, in, Nr, (uint32_t*)g_extKey);

    return fs;
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
    RUN_TEST(doCipher(test_AES_out, tv_AES128_FIPS197_pTxt_ref, AES128_Nr, (uint32_t*)g_extKey), fRtn);
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
    RUN_TEST(doCipherInv(test_AES_out, tv_AES128_FIPS197_cTxt_ref, AES128_Nr, (uint32_t*)g_extKey), fRtn);
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
    RUN_TEST(doCipherInv2(test_AES_out, tv_AES128_FIPS197_cTxt_ref, AES128_Nr, (uint32_t*)g_extKey), fRtn);
    DBG_PRINT_ARRAY(test_AES_out, sizeof(test_AES_out), "NIST, FIPS197, May 9, 2023, Appendix B - Inv Cipher Example(AES128)", 4UL);
    EXAM_TEST(memcmp(test_AES_out, tv_AES128_FIPS197_pTxt_ref, sizeof(tv_AES128_FIPS197_pTxt_ref)) == 0, \
            "NIST, FIPS197, AES128 TestVector");
}

void test_aesEnc(void)
{
    printf("%s:%d:%s\r\n", __FILE__, __LINE__, __func__);

    int fRtn;

    printf("[AES128 Encryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES_NIST_Ex_pTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        RUN_TEST(aesEnc(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], tv_AES128_key, sizeof(tv_AES128_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        EXAM_TEST(memcmp(test_AES_out, tv_AES128_NIST_Ex_cTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES128 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Encrypt Values", AES_S_SIZE);
    }

    printf("[AES192 Encryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES_NIST_Ex_pTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        RUN_TEST(aesEnc(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], tv_AES192_key, sizeof(tv_AES192_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        EXAM_TEST(memcmp(test_AES_out, tv_AES192_NIST_Ex_cTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES192 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Encrypt Values", AES_S_SIZE);
    }

    printf("[AES256 Encryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES_NIST_Ex_pTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        RUN_TEST(aesEnc(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], tv_AES256_key, sizeof(tv_AES256_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        EXAM_TEST(memcmp(test_AES_out, tv_AES256_NIST_Ex_cTxt_ref[tvi], AES_S_SIZE) == 0, \
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
        RUN_TEST(aesDec(test_AES_out, tv_AES128_NIST_Ex_cTxt_ref[tvi], tv_AES128_key, sizeof(tv_AES128_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        EXAM_TEST(memcmp(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES128 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Decrypt Values", AES_S_SIZE);
    }

    printf("[AES192 Decryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES192_NIST_Ex_cTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        RUN_TEST(aesDec(test_AES_out, tv_AES192_NIST_Ex_cTxt_ref[tvi], tv_AES192_key, sizeof(tv_AES192_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        EXAM_TEST(memcmp(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES192 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Decrypt Values", AES_S_SIZE);
    }

    printf("[AES256 Decryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES256_NIST_Ex_cTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        RUN_TEST(aesDec(test_AES_out, tv_AES256_NIST_Ex_cTxt_ref[tvi], tv_AES256_key, sizeof(tv_AES256_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        EXAM_TEST(memcmp(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], AES_S_SIZE) == 0, \
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
        RUN_TEST(aesDec2(test_AES_out, tv_AES128_NIST_Ex_cTxt_ref[tvi], tv_AES128_key, sizeof(tv_AES128_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        EXAM_TEST(memcmp(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES128 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Decrypt Values", AES_S_SIZE);
    }

    printf("[AES192 Decryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES192_NIST_Ex_cTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        RUN_TEST(aesDec2(test_AES_out, tv_AES192_NIST_Ex_cTxt_ref[tvi], tv_AES192_key, sizeof(tv_AES192_key)), fRtn);
        printf("[tvi=%02ld]", tvi);
        EXAM_TEST(memcmp(test_AES_out, tv_AES_NIST_Ex_pTxt_ref[tvi], AES_S_SIZE) == 0, \
                "NIST, FIPS197, AES192 Example values");
        printHex(test_AES_out, sizeof(test_AES_out), "Decrypt Values", AES_S_SIZE);
    }

    printf("[AES256 Decryption]\r\n");
    for(size_t tvi = 0UL; tvi < sizeof(tv_AES256_NIST_Ex_cTxt_ref)/AES_S_SIZE; tvi++)
    {
        (void)memset(test_AES_out, 0x0, AES_S_SIZE);
        RUN_TEST(aesDec2(test_AES_out, tv_AES256_NIST_Ex_cTxt_ref[tvi], tv_AES256_key, sizeof(tv_AES256_key)), fRtn);
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
    aesEnc(test_AES_out, test_allZero, test_gcm211_key, sizeof(test_gcm211_key));
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

    test_aesEnc();

    test_doCipherInv();

    test_aesDec();

    test_doCipherInv2();

    test_aesDec2();

    test_aes_blanks(); // calcaulates AES-GCM H

    return 0;
}
#endif /* SELFTEST */
