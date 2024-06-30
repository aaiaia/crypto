#ifndef AES_H
#define AES_H

#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

#include <stdint.h>

// Number is count of word(32bits)
// AES COMMON
#define AES_Nb      4U
#define AES_Nr_BASE 6U
#define AES_S_SIZE  16U // bytes
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
int keyExpansion(uint8_t* key, size_t Nk, size_t Nr);
int keyExpansionEIC(uint8_t* key, size_t Nk, size_t Nr);

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
int doCipher(uint8_t* out, uint8_t* in, uint8_t Nr, uint32_t* w);
int doCipherInv(uint8_t* out, uint8_t* in, uint8_t Nr, uint32_t* dw);
int doCipherInv2(uint8_t* out, uint8_t* in, uint8_t Nr, uint32_t* w);

int addRoundKey(uint32_t* s, uint32_t* w);

#define subWord(w)  subByte((uint8_t*)(&(w)), sizeof(w))
int subByte(uint8_t* w, size_t size);
int subByteInv(uint8_t* w, size_t size);

#define rotWord(w) shiftColumn(&(w), sizeof(w)/sizeof(uint32_t))
int shiftColumn(uint32_t* w, size_t wLen);

int shiftRows(uint8_t* s, size_t size);
int shiftRowsInv(uint8_t* s, size_t size);

int mixColumns(uint8_t* s, size_t size);
int mixColumnsInv(uint8_t* s, size_t size);

int aesEnc(uint8_t* out, uint8_t* in, uint8_t* key, size_t kSize);
int aesDec(uint8_t* out, uint8_t* in, uint8_t* key, size_t kSize);
int aesDec2(uint8_t* out, uint8_t* in, uint8_t* key, size_t kSize);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* AES_H */
