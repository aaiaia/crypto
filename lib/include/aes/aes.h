#ifndef AES_H
#define AES_H

#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h> // size_t, NULL

#define AES_ENCRYPT false
#define AES_DECRYPT true
#define AES_S_SIZE  16U // bytes

int aesEncV1(uint8_t* out, const uint8_t* in, const uint8_t* key, const size_t kSize);
int aesDecV1(uint8_t* out, const uint8_t* in, const uint8_t* key, const size_t kSize);
int aesDecV2(uint8_t* out, const uint8_t* in, const uint8_t* key, const size_t kSize);

inline static int aesEnc(uint8_t* out, const uint8_t* in, const uint8_t* key, const size_t kSize)
{
    return aesEncV1(out, in, key, kSize);
}
inline static int aesDec(uint8_t* out, const uint8_t* in, const uint8_t* key, const size_t kSize)
{
    return aesDecV2(out, in, key, kSize);
}

int startAes(const uint8_t* key, const size_t kSize, const bool decrypt);
int updateAes(uint8_t* out, const uint8_t* in, const size_t size);
int finishAes(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* AES_H */
