#ifdef DEBUG
#include <stdio.h>
#include <stdint.h>
#include "hash/sha2.h"
#define dprintf(...)    printf(__VA_ARGS__)
#define dprint_hmac256_blk(UI32_PTR, TITLE) _dprint_ui32_array_(UI32_PTR, SHA2_BLOCK_NUM, TITLE)
#define dprint_hmac256_mac(UI32_PTR, TITLE) _dprint_ui32_array_(UI32_PTR, SHA2_DIGEST_NUM, TITLE)
void _dprint_ui32_array_(const uint32_t* blk, const size_t len, const char* title)
{
    size_t i;

    if(title != NULL)   dprintf("[%s]\n", title);
    for(i = 0UL; i < len; i++)
    {
        dprintf("[%2lu]0x%08x ", i, blk[i]);
        if((i&0x7UL) == 0x7UL)  dprintf("\n");
    }
    if((i&0x7UL) != 0x7UL)  dprintf("\n");
}
#define dprint_hmac512_blk(UI64_PTR, TITLE) _dprint_ui64_array_(UI64_PTR, SHA2_BLOCK_NUM, TITLE)
#define dprint_hmac512_mac(UI64_PTR, TITLE) _dprint_ui64_array_(UI64_PTR, SHA2_DIGEST_NUM, TITLE)
void _dprint_ui64_array_(const uint64_t* blk, const size_t len, const char* title)
{
    size_t i;

    if(title != NULL)   dprintf("[%s]\n", title);
    dprintf("0x ");
    for(i = 0UL; i < len; i++)
    {
        dprintf("[%2lu]%016lx ", i, blk[i]);
        if((i&0x3UL) == 0x3UL)  dprintf("\n");
    }
    if((i&0x3UL) != 0x3UL)  dprintf("\n");
}
#else
#define dprintf(...)
#define dprint_hmac256_blk(UI32_PTR, TITLE)
#define dprint_hmac256_mac(UI32_PTR, TITLE)
#define dprint_hmac512_blk(UI64_PTR, TITLE)
#define dprint_hmac512_mac(UI64_PTR, TITLE)
#endif /* DEBUG */
#include <stdlib.h> // defines 'LITTLE_ENDIAN'
#include <stdint.h>
#include <string.h>

#include "mac/hmac.h"
#include "hash/sha2.h"

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

#define HMAC_IPAD_BYTE  0x36
#define HMAC_OPAD_BYTE  0x5c

#define HMAC_IPAD_256   0x36363636U
#define HMAC_OPAD_256   0x5c5c5c5cU
#define HMAC_IPAD_512   0x3636363636363636UL
#define HMAC_OPAD_512   0x5c5c5c5c5c5c5c5cUL

typedef union {
    uint32_t k0_256[SHA2_BLOCK_NUM];
    uint64_t k0_512[SHA2_BLOCK_NUM];
} hmac_key0_t;

static hmac_key0_t l_hmac;
#define l_hmac256_k0    l_hmac.k0_256
#define l_hmac512_k0    l_hmac.k0_512

typedef union {
    uint32_t sha256[SHA2_DIGEST_NUM];
    uint64_t sha512[SHA2_DIGEST_NUM];
} hmac_hash_t;

static hmac_hash_t l_hash;
#define l_hash256   l_hash.sha256
#define l_hash512   l_hash.sha512

static void keycpyHmac256(uint32_t* blk, const uint32_t* key, const size_t keySize)
{
    const size_t u32Len = SIZE2UI32LEN(keySize);

    if(u32Len <= SHA2_BLOCK_NUM)
    {
        for(size_t idx_32 = 0UL; idx_32 < u32Len; idx_32++)
        {
            blk[idx_32] = key[idx_32];
        }
    }
    if(keySize <= SHA256_BLOCK_SIZE)
    {
        blk[u32Len] = 0x0U;
        for(size_t idx_8 = UI32LEN2SIZE(u32Len); idx_8 < keySize; idx_8++)
        {
            ((uint8_t*)blk)[EDCIDX32(size_t, idx_8)] = ((uint8_t*)key)[EDCIDX32(size_t, idx_8)];
        }
        for(size_t idx_32 = u32Len + 1UL; idx_32 < SHA2_BLOCK_NUM; idx_32++)
        {
            blk[idx_32] = 0x0U;
        }
    }
}

void initHmac256_key(const uint32_t* key, const size_t keySize)
{
    size_t k0prcSize, k0remSize, k0chkSize;

    if(keySize <= SHA256_BLOCK_SIZE)
    {
        keycpyHmac256(l_hmac256_k0, key, keySize);
    }
    else
    {
        startSha256(l_hash256, H0_256, SHA256_DIGEST_SIZE);
        k0remSize = keySize;
        for(k0prcSize = 0UL; k0prcSize < keySize; k0prcSize += SHA256_BLOCK_SIZE)
        {
            if(k0remSize >= SHA256_BLOCK_SIZE)
            {
                k0chkSize = SHA256_BLOCK_SIZE;
                updateSha256(l_hash256, SHA256_DIGEST_SIZE, &key[SIZE2UI32LEN(k0prcSize)], k0chkSize);
            }
            else
            {
                k0chkSize = k0remSize;
                keycpyHmac256(l_hmac256_k0, &key[SIZE2UI32LEN(k0prcSize)], k0chkSize);
                updateSha256(l_hash256, SHA256_DIGEST_SIZE, l_hmac256_k0, k0chkSize);
            }
            k0remSize -= k0chkSize;
        }
        finishSha256(l_hash256, SHA256_DIGEST_SIZE);
        keycpyHmac256(l_hmac256_k0, l_hash256, SHA256_DIGEST_SIZE);
    }
    dprint_hmac256_blk(l_hmac256_k0, "K0_256");
}

void startHmac256(const size_t macSize)
{
    for(size_t i = 0UL; i < SHA2_BLOCK_NUM; i++)
    {
        l_hmac256_k0[i] ^= HMAC_IPAD_256;
    }
    dprint_hmac256_blk(l_hmac256_k0, "K0_256 ^ ipad");

    startSha256(l_hash256, H0_256, macSize);
    updateSha256(l_hash256, macSize, l_hmac256_k0, sizeof(l_hmac256_k0));
}

void updateHmac256(const size_t macSize, const uint32_t* text, const size_t textSize)
{
    updateSha256(l_hash256, macSize, text, textSize);
}

void finishHmac256(uint32_t* mac, const size_t macSize)
{
    finishSha256(l_hash256, macSize);
    dprint_hmac256_mac(l_hash256, "Hash((K0_256^ipad)||text)");

    for(size_t i = 0UL; i < SHA2_BLOCK_NUM; i++)
    {
        l_hmac256_k0[i] ^= (HMAC_IPAD_256 ^ HMAC_OPAD_256);
    }
    dprint_hmac256_blk(l_hmac256_k0, "K0_256 ^ opad");

    startSha256(mac, H0_256, macSize);
    updateSha256(mac, macSize, l_hmac256_k0, sizeof(l_hmac256_k0));
    updateSha256(mac, macSize, l_hash256, macSize);
    finishSha256(mac, macSize);
    dprint_hmac256_mac(mac, "Hash((K0^opad)||Hash((K0^ipad)||text))");
}
