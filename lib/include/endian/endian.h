#ifndef ENDIAN_H
#define ENDIAN_H

#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

#include <stdlib.h> // defines 'LITTLE_ENDIAN'

#include <stdint.h>
#include <stddef.h> //  size_t, NULL

#include "common/util.h"

#if defined(LITTLE_ENDIAN)
#define EDCVAL32(X32) \
    ( (((X32)&0x000000ffU)<<24U)|(((X32)&0xff000000U)>>24U) \
     |(((X32)&0x0000ff00U)<< 8U)|(((X32)&0x00ff0000U)>> 8U) )
#define EDCVAL64(X64) \
    ( (((X64)&0x00000000000000ffUL)<<56UL)|(((X64)&0xff00000000000000UL)>>56UL) \
     |(((X64)&0x000000000000ff00UL)<<40UL)|(((X64)&0x00ff000000000000UL)>>40UL) \
     |(((X64)&0x0000000000ff0000UL)<<24UL)|(((X64)&0x0000ff0000000000UL)>>24UL) \
     |(((X64)&0x00000000ff000000UL)<< 8UL)|(((X64)&0x000000ff00000000UL)>> 8UL))
#define EDCIDX(TYPE, IDX, MSK)  (((IDX)&(~((TYPE)(MSK))))|(((TYPE)(MSK))-((IDX)&((TYPE)(MSK)))))
#define EDCIDX32(TYPE, IDX)     EDCIDX(TYPE, IDX, 0x03U)
#define EDCIDX64(TYPE, IDX)     EDCIDX(TYPE, IDX, 0x07U)
#else
#define EDCVAL32(X32)
#define EDCVAL64(X64)
#define EDCIDX(TYPD, IDX, MSK)  (IDX)
#define EDCIDX32(TYPE, IDX)     EDCIDX(TYPE, IDX, 0x03U)
#define EDCIDX64(TYPE, IDX)     EDCIDX(TYPE, IDX, 0x07U)
#endif /* LITTLE_ENDIAN */

/* 32bits */
#define EDCSIZE2W32LEN(SIZE)    BYTE2U32L(SIZE)
#define EDCW32LEN2SIZE(LEN)     U32L2BYTE(LEN)
void conv32bitEndian(uint32_t* dst, const uint32_t* src, const size_t size);
/* 64bits */
#define EDCSIZE2W64LEN(SIZE)    BYTE2U64L(SIZE)
#define EDCW64LEN2SIZE(LEN)     U64L2BYTE(LEN)
void conv64bitEndian(uint64_t* dst, const uint64_t* src, const size_t size);

#ifdef DEBUG
void test_endian_environments(void);
#else
#define test_endian_environments()
#endif /* DEBUG */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENDIAN_H */
