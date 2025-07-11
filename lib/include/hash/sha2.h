#ifndef SHA2_H
#define SHA2_H

/* SHA2(SHA256, SHA512) Commons */
#define SHA2_BLOCK_NUM      16U // length of symbol
#define SHA2_DIGEST_NUM     8U  // length of symbol

/* SHA256 */
#define SHA256_SYMBOL_SIZE  4U
#define SHA256_BLOCK_SIZE   64U
#define SHA256_DIGEST_SIZE  32U
#define SHA256_ROUND_NUM    64U

#define SIZE2UI32LEN(SIZE)   ((SIZE)>>2U)    // /4

/* SHA512 */
#define SHA512_SYMBOL_SIZE  8U
#define SHA512_BLOCK_SIZE   128U
#define SHA512_DIGEST_SIZE  64U
#define SHA512_ROUND_NUM    80U

#define SIZE2UI64LEN(SIZE)   ((SIZE)>>3U)    // /8

/* SHA256 */
extern const uint32_t H0_224[SHA2_DIGEST_NUM];
extern const uint32_t H0_256[SHA2_DIGEST_NUM];

/* SHA512 */
extern const uint64_t H0_384[SHA2_DIGEST_NUM];
extern const uint64_t H0_512[SHA2_DIGEST_NUM];
extern const uint64_t H0_512_224[SHA2_DIGEST_NUM];
extern const uint64_t H0_512_256[SHA2_DIGEST_NUM];

/* SHA256 */
void conv32bitEndian(uint32_t* dst, const uint32_t* src, const size_t size);
static inline void convStreamToSymbol256(uint32_t* dst, const uint32_t* src, const size_t size)
{
    conv32bitEndian(dst, src, size);
};
static inline void convSymbolToStream256(uint32_t* dst, const uint32_t* src, const size_t size)
{
    conv32bitEndian(dst, src, size);
};

/* SHA512 */
void conv64bitEndian(uint64_t* dst, const uint64_t* src, const size_t size);
static inline void convStreamToSymbol512(uint64_t* dst, const uint64_t* src, const size_t size)
{
    conv64bitEndian(dst, src, size);
};
static inline void convSymbolToStream512(uint64_t* dst, const uint64_t* src, const size_t size)
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
