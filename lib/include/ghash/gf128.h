#ifndef GHASH_H
#define GHASH_H

#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

#define GHASH_SIZE      16U
#define GHASH_LSB_POLY  0x87U
#define GHASH_MSB_POLY  0xE1U

#define GHASH_U32_LEN   (16U>>2U)

int xor_u32(uint32_t* z, uint32_t* x, uint32_t* y, size_t length);

bool sftl_u32(uint32_t* z, uint32_t* x, size_t length);
bool sftr_u32(uint32_t* z, uint32_t* x, size_t length);

#if 0 /* DISABLE_bitReflect128_u32 */
int bitReflect128_u32(uint32_t* vi, uint32_t* vf);
#endif/* DISABLE_bitReflect128_u32 */
int bitReflect8_u8(uint8_t* vi, uint8_t* vf, size_t size);

int hexSwap(uint8_t* vs, uint8_t* vf, size_t size);
int byteSwap(uint8_t* vs, uint8_t* vf, size_t size);

int gf8_mul_u32(uint32_t* z, uint32_t* x, uint32_t* y);
int gf128_mul_sftl_u32_byte_reflect(uint32_t* z, uint32_t* x, uint32_t* y);
int gf128_mul_sftr_u32_byte_swap(uint32_t* z, uint32_t* x, uint32_t* y);

int gf128_ghash(uint8_t* ghash, uint8_t* H, uint8_t* data, size_t size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* GHASH_H */
