#ifndef SHA256_H
#define SHA256_H

/* SHA256 */
#define SHA256_BLOCK_SIZE   64U
#define SHA256_DIGEST_SIZE  32U
#define SHA256_ROUND_NUM    64U

#define SHA256_BLOCK_NUM    16U // length of symbol
#define SHA256_DIGEST_NUM   8U  // length of symbol

#define SIZE2LEN256(SIZE)   ((SIZE)>>2U)    // *2

extern const uint32_t H0_256[SHA256_DIGEST_NUM];
extern const uint32_t K256[SHA256_ROUND_NUM];

void conv32bitEndian(uint32_t* dst, const uint32_t* src, const size_t size);
static inline void convStreamToSymbol256(uint32_t* dst, const uint32_t* src, const size_t size)
{
    conv32bitEndian(dst, src, size);
};
static inline void convSymbolToStream256(uint32_t* dst, const uint32_t* src, const size_t size)
{
    conv32bitEndian(dst, src, size);
};
void startSha256(uint32_t* hash, const uint32_t* iHash, const size_t hashSize);
void updateSha256(uint32_t* hash, const size_t hashSize, const uint32_t* mes, const size_t mesSize);
void finishSha256(uint32_t* hash, const uint32_t hashSize);

#ifdef DEBUG
void testSha256_environments(void);
#else
#define testSha256_environments()
#endif /* DEBUG */

#endif /* SHA256_H */
