#ifndef CAL_AES_GCM_H
#define CAL_AES_GCM_H

#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

#include <stdint.h>

#define AEAD_AES_GCM_IV_SIZE        12U

int calH(uint8_t* H, uint8_t* key, size_t keySize);
static inline int calGhash(uint8_t* ghash, uint8_t* H, uint8_t* data, size_t size);

int calJ0(uint8_t* j0, uint8_t* iv, size_t ivSize);
int calS(uint8_t* ghash, uint8_t* H, uint8_t* j0, size_t aSize, size_t cSize);
int inc32(uint8_t* ctrBlk);
int calGCTR(uint8_t* cipher, uint8_t* plain, size_t size, uint8_t* key, size_t keySize, uint8_t* ctrBlk);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* CAL_AES_GCM_H */
