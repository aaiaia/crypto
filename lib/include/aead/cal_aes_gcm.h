#ifndef CAL_AES_GCM_H
#define CAL_AES_GCM_H

#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

#include <stdint.h>

#define AEAD_IV_SIZE                12U
#define AEAD_J0_IV_BLEN_PAD_SIZE    8U  /* USE gen J0 */
#define AEAD_J0_IV_BLEN_SIZE        8U  /* USE gen J0 */

int calH(const uint8_t* H, const uint8_t* const key, const size_t keySize);
static inline int calGhash(const uint8_t* ghash, const uint8_t* const H, const uint8_t* const data, const size_t size);

int calJ0(const uint8_t* j0, const uint8_t* const iv, const size_t ivSize, const uint8_t* const H);
static inline int calS_head(const uint8_t* ghash, const uint8_t* const H, const uint8_t* const aad, const size_t size);
static inline int calS_body(const uint8_t* ghash, const uint8_t* const H, const uint8_t* const data, const size_t size);
int calS_tail(const uint8_t* ghash, const uint8_t* const H, const size_t aSize, const size_t cSize);
int inc32(const uint8_t* ctrBlk);
int calGCTR(const uint8_t* cipher, const uint8_t* plain, const size_t size, const uint8_t* const key, const size_t keySize, const uint8_t* const ctrBlk);
int calT(const uint8_t* msb, const uint8_t* const ghash, const uint8_t* const key, const size_t keySize, const uint8_t* const j0);

int gcm_ae(uint8_t* const cipher, uint8_t* const tag, \
        const uint8_t* const iv, const size_t ivSize, \
        const uint8_t* const aad, const size_t aadSize, \
        const uint8_t* const key, const size_t keySize, \
        const uint8_t* const plain, const size_t size);
int gcm_ad(uint8_t* const plain, const uint8_t* const tag, \
        const uint8_t* const iv, const size_t ivSize, \
        const uint8_t* const aad, const size_t aadSize, \
        const uint8_t* const key, const size_t keySize, \
        const uint8_t* const cipher, const size_t size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* CAL_AES_GCM_H */
