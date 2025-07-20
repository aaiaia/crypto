#ifndef SHA2_H
#define SHA2_H

#include <stdint.h>
#include <stddef.h> // size_t, NULL

#include "endian/endian.h"  // Endian converting

/* SHA2(SHA256, SHA512) Commons */
#define SHA2_BLOCK_NUM      16U // length of symbol
#define SHA2_DIGEST_NUM     8U  // length of symbol

/* SHA256 */
#define SHA256_SYMBOL_SIZE  4U
#define SHA256_BLOCK_SIZE   64U
#define SHA256_DIGEST_SIZE  32U
#define SHA256_ROUND_NUM    64U

/* SHA512 */
#define SHA512_SYMBOL_SIZE  8U
#define SHA512_BLOCK_SIZE   128U
#define SHA512_DIGEST_SIZE  64U
#define SHA512_ROUND_NUM    80U

/* SHA256 */
extern const uint32_t H0_224[SHA2_DIGEST_NUM];
extern const uint32_t H0_256[SHA2_DIGEST_NUM];

/* SHA512 */
extern const uint64_t H0_384[SHA2_DIGEST_NUM];
extern const uint64_t H0_512[SHA2_DIGEST_NUM];
extern const uint64_t H0_512_224[SHA2_DIGEST_NUM];
extern const uint64_t H0_512_256[SHA2_DIGEST_NUM];

/* Data Convertion */
/* SHA256 */
static inline void convStreamToSymbolSha256(uint32_t* dst, const uint32_t* src, const size_t size)
{
    conv32bitEndian(dst, src, size);
};
static inline void convSymbolToStreamSha256(uint32_t* dst, const uint32_t* src, const size_t size)
{
    conv32bitEndian(dst, src, size);
};

/* SHA512 */
static inline void convStreamToSymbolSha512(uint64_t* dst, const uint64_t* src, const size_t size)
{
    conv64bitEndian(dst, src, size);
};
static inline void convSymbolToStreamSHA512(uint64_t* dst, const uint64_t* src, const size_t size)
{
    conv64bitEndian(dst, src, size);
};

/* SHA256 */
void startSha256(uint32_t* hash, const uint32_t* iHash, const size_t hashSize);
void updateSha256(uint32_t* hash, const size_t hashSize, const uint32_t* mes, const size_t mesSize);
void finishSha256(uint32_t* hash, const size_t hashSize);

/* SHA512 */
void startSha512(uint64_t* hash, const uint64_t* iHash, const size_t hashSize);
void updateSha512(uint64_t* hash, const size_t hashSize, const uint64_t* mes, const size_t mesSize);
void finishSha512(uint64_t* hash, const size_t hashSize);

#ifdef DEBUG
void test_sha2_environments(void);
#else
#define test_sha2_environments()
#endif /* DEBUG */

#endif /* SHA2_H */
