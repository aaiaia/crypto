#ifndef CMAC_H
#define CMAC_H

#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

#include <stddef.h> // NULL, size_t
#include <stdint.h>

#define CMAC_TAG128b_SIZE   16U

void startCmac(const uint8_t* key, const size_t kSize);
void updateCmac(const uint8_t* mes, const size_t mSize);
void finishCmac(uint8_t* tag, const uint8_t* mes, const size_t msize);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* CMAC_H */
