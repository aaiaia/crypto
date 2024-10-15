#ifndef BITWISE_H
#define BITWISE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */
/* bitwise vector templete */
#define BITWISE_OPERATION(OUT_PTR, INA_PTR, INB_PTR, LEN, OPERATOR, FN_RTN) \
{                                                                           \
    if((OUT_PTR) != NULL && (INA_PTR) != NULL && (INB_PTR) != NULL)         \
    {                                                                       \
        for(size_t i = 0U; i < (LEN); i++)                                  \
        {                                                                   \
           (OUT_PTR)[i] = (INA_PTR)[i] OPERATOR (INB_PTR)[i];               \
        }                                                                   \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        (FN_RTN) = -1;                                                      \
    }                                                                       \
}

/* basic bitwise operation */
int xor_u32(uint32_t* z, uint32_t* x, uint32_t* y, size_t length);
int xor_u8(uint8_t* z, uint8_t* x, uint8_t* y, size_t size);

bool sftl_u32(uint32_t* z, uint32_t* x, size_t length);
bool sftr_u32(uint32_t* z, uint32_t* x, size_t length);

#if 0 /* DISABLE_bitReflect128_u32 */
int bitReflect128_u32(uint32_t* vi, uint32_t* vf);
#endif/* DISABLE_bitReflect128_u32 */
int bitReflect8_u8(uint8_t* vi, uint8_t* vf, size_t size);

int hexSwap(uint8_t* vs, uint8_t* vf, size_t size);
int byteSwap(uint8_t* vs, uint8_t* vf, size_t size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* BITWISE_H */
