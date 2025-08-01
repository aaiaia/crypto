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
#include <stdint.h>
#include <string.h>

#include "endian/endian.h"
#include "mac/hmac.h"
#include "hash/sha2.h"

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

static void keycpyHmac256(uint32_t* blk, const uint32_t* key, const size_t keySize);
static void keycpyHmac512(uint64_t* blk, const uint64_t* key, const size_t keySize);

static void initHmac256_key(const uint32_t* key, const size_t keySize);
static void initHmac512_key(const uint64_t* key, const size_t keySize);

static void keycpyHmac256(uint32_t* blk, const uint32_t* key, const size_t keySize)
{
    const size_t u32Len = EDCSIZE2W32LEN(keySize);

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
        for(size_t idx_8 = EDCW32LEN2SIZE(u32Len); idx_8 < keySize; idx_8++)
        {
            ((uint8_t*)blk)[EDCIDX32(size_t, idx_8)] = ((uint8_t*)key)[EDCIDX32(size_t, idx_8)];
        }
        for(size_t idx_32 = u32Len + 1UL; idx_32 < SHA2_BLOCK_NUM; idx_32++)
        {
            blk[idx_32] = 0x0U;
        }
    }
}

static void keycpyHmac512(uint64_t* blk, const uint64_t* key, const size_t keySize)
{
    const size_t u64Len = EDCSIZE2W64LEN(keySize);

    if(u64Len <= SHA2_BLOCK_NUM)
    {
        for(size_t idx_64 = 0UL; idx_64 < u64Len; idx_64++)
        {
            blk[idx_64] = key[idx_64];
        }
    }
    if(keySize <= SHA512_BLOCK_SIZE)
    {
        blk[u64Len] = 0x0U;
        for(size_t idx_8 = EDCW64LEN2SIZE(u64Len); idx_8 < keySize; idx_8++)
        {
            ((uint8_t*)blk)[EDCIDX64(size_t, idx_8)] = ((uint8_t*)key)[EDCIDX64(size_t, idx_8)];
        }
        for(size_t idx_64 = u64Len + 1UL; idx_64 < SHA2_BLOCK_NUM; idx_64++)
        {
            blk[idx_64] = 0x0U;
        }
    }
}

static void initHmac256_key(const uint32_t* key, const size_t keySize)
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
                updateSha256(l_hash256, SHA256_DIGEST_SIZE, &key[EDCSIZE2W32LEN(k0prcSize)], k0chkSize);
            }
            else
            {
                k0chkSize = k0remSize;
                keycpyHmac256(l_hmac256_k0, &key[EDCSIZE2W32LEN(k0prcSize)], k0chkSize);
                updateSha256(l_hash256, SHA256_DIGEST_SIZE, l_hmac256_k0, k0chkSize);
            }
            k0remSize -= k0chkSize;
        }
        finishSha256(l_hash256, SHA256_DIGEST_SIZE);
        keycpyHmac256(l_hmac256_k0, l_hash256, SHA256_DIGEST_SIZE);
    }
    dprint_hmac256_blk(l_hmac256_k0, "K0_256");
}

static void initHmac512_key(const uint64_t* key, const size_t keySize)
{
    size_t k0prcSize, k0remSize, k0chkSize;

    if(keySize <= SHA512_BLOCK_SIZE)
    {
        keycpyHmac512(l_hmac512_k0, key, keySize);
    }
    else
    {
        startSha512(l_hash512, H0_512, SHA512_DIGEST_SIZE);
        k0remSize = keySize;
        for(k0prcSize = 0UL; k0prcSize < keySize; k0prcSize += SHA512_BLOCK_SIZE)
        {
            if(k0remSize >= SHA512_BLOCK_SIZE)
            {
                k0chkSize = SHA512_BLOCK_SIZE;
                updateSha512(l_hash512, SHA512_DIGEST_SIZE, &key[EDCSIZE2W64LEN(k0prcSize)], k0chkSize);
            }
            else
            {
                k0chkSize = k0remSize;
                keycpyHmac512(l_hmac512_k0, &key[EDCSIZE2W64LEN(k0prcSize)], k0chkSize);
                updateSha512(l_hash512, SHA512_DIGEST_SIZE, l_hmac512_k0, k0chkSize);
            }
            k0remSize -= k0chkSize;
        }
        finishSha512(l_hash512, SHA512_DIGEST_SIZE);
        keycpyHmac512(l_hmac512_k0, l_hash512, SHA512_DIGEST_SIZE);
    }
    dprint_hmac512_blk(l_hmac512_k0, "K0_512");
}

void startHmac256(const uint32_t* key, const size_t keySize, const size_t macSize)
{
    initHmac256_key(key, keySize);

    for(size_t i = 0UL; i < SHA2_BLOCK_NUM; i++)
    {
        l_hmac256_k0[i] ^= HMAC_IPAD_256;
    }
    dprint_hmac256_blk(l_hmac256_k0, "K0_256 ^ ipad");

    startSha256(l_hash256, H0_256, macSize);
    updateSha256(l_hash256, macSize, l_hmac256_k0, sizeof(l_hmac256_k0));
}

void startHmac512(const uint64_t* key, const size_t keySize, const size_t macSize)
{
    initHmac512_key(key, keySize);

    for(size_t i = 0UL; i < SHA2_BLOCK_NUM; i++)
    {
        l_hmac512_k0[i] ^= HMAC_IPAD_512;
    }
    dprint_hmac512_blk(l_hmac512_k0, "K0_512 ^ ipad");

    startSha512(l_hash512, H0_512, macSize);
    updateSha512(l_hash512, macSize, l_hmac512_k0, sizeof(l_hmac512_k0));
}

void updateHmac256(const size_t macSize, const uint32_t* text, const size_t textSize)
{
    updateSha256(l_hash256, macSize, text, textSize);
}

void updateHmac512(const size_t macSize, const uint64_t* text, const size_t textSize)
{
    updateSha512(l_hash512, macSize, text, textSize);
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

void finishHmac512(uint64_t* mac, const size_t macSize)
{
    finishSha512(l_hash512, macSize);
    dprint_hmac512_mac(l_hash512, "Hash((K0_512^ipad)||text)");

    for(size_t i = 0UL; i < SHA2_BLOCK_NUM; i++)
    {
        l_hmac512_k0[i] ^= (HMAC_IPAD_512 ^ HMAC_OPAD_512);
    }
    dprint_hmac512_blk(l_hmac512_k0, "K0_512 ^ opad");

    startSha512(mac, H0_512, macSize);
    updateSha512(mac, macSize, l_hmac512_k0, sizeof(l_hmac512_k0));
    updateSha512(mac, macSize, l_hash512, macSize);
    finishSha512(mac, macSize);
    dprint_hmac512_mac(mac, "Hash((K0^opad)||Hash((K0^ipad)||text))");
}
