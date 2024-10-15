#ifndef GHASH_H
#define GHASH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

#define GHASH_SIZE      16U
#define GHASH_LSB_POLY  0x87U
#define GHASH_MSB_POLY  0xE1U

#define GHASH_U32_LEN   (16U>>2U)

int gf128_mul_sftl_u32(uint32_t* z, uint32_t* x, uint32_t* y);
int gf128_mul_sftr_u32(uint32_t* z, uint32_t* x, uint32_t* y);

int gf128_mul_sftl_u32_byte_reflect(uint32_t* z, uint32_t* x, uint32_t* y);
int gf128_mul_sftr_u32_byte_swap(uint32_t* z, uint32_t* x, uint32_t* y);

int gf128_ghash(uint8_t* ghash, uint8_t* H, uint8_t* data, size_t size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* GHASH_H */
