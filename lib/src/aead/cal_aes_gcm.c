#include "common/bitwise.h"
#include "common/util.h"
#include "ghash/gf128.h"
#include "aes/aes.h"
#include "aead/cal_aes_gcm.h"
#include <string.h>

#ifdef SELFTEST_AEAD
#include <stdbool.h>
#include <stdio.h>
#endif /* SELFTEST_AEAD */
/* Internal functions */
#ifdef SELFTEST_AEAD
static void printHex(void* data, size_t size, const char* title, size_t lf);
#endif /* SELFTEST_AEAD */
static inline int calJ0_ivNone(uint8_t* const j0);
static inline int calJ0_iv96b(uint8_t* const j0, const uint8_t* const iv);
static inline int calJ0_ivElse(uint8_t* const j0, const uint8_t* const iv, const size_t ivSize, const uint8_t* const H);

int calH(const uint8_t* H, const uint8_t* const key, const size_t keySize)
{
    int fs = 0;

    if((H != NULL) && (key != NULL) && (keySize != 0UL))
    {
        const uint8_t zero[AES_S_SIZE] = { 0U, };
        aesEncV1(H, zero, key, keySize);
    }
    else
    {
        fs = -1;
    }

    return fs;
}

static inline int calGhash(const uint8_t* ghash, const uint8_t* const H, const uint8_t* const data, const size_t size)
{
    return gf128_ghash(ghash, H, data, size);
}

static inline int calJ0_ivNone(uint8_t* const j0)
{
    int fs = 0;

    if(j0 != NULL)
    {
        memset(j0, 0, AES_S_SIZE);
    }
    else
    {
        fs = -1;
    }

    return fs;
}
static inline int calJ0_iv96b(uint8_t* const j0, const uint8_t* const iv)
{
    int fs = 0;

    if((j0 != NULL) && (iv != NULL))
    {
        memcpy(j0, iv, AEAD_IV_SIZE);
        memset((j0 + AEAD_IV_SIZE), 0, (AES_S_SIZE - AEAD_IV_SIZE));
        j0[AES_S_SIZE - 1U] = 0x1U;
    }
    else
    {
        fs = -1;
    }

    return fs;
}
static inline int calJ0_ivElse(uint8_t* const j0, const uint8_t* const iv, const size_t ivSize, const uint8_t* const H)
{
    int fs = 0;

    if((j0 != NULL) && (iv != NULL) && (H != NULL))
    {
        if((ivSize >> (64U - 3U)) == 0U)
        {
            uint8_t ghash[AES_S_SIZE];
            const size_t remSize = (ivSize & (AES_S_SIZE - 1U));
            const size_t remOfs = (ivSize & (~((size_t)(AES_S_SIZE - 1U))));
            const uint64_t ivblen_u64b = BYTE2BITS(ivSize);
            /* s = AES_S_SIZE - remSize */

            memset(ghash, 0, AES_S_SIZE);
            for(size_t prcSize = 0U; prcSize < ivSize; prcSize += AES_S_SIZE)
            {
                fs = calGhash(ghash, H, (iv + prcSize), AES_S_SIZE);
            }
            if(remSize != 0U)
            {
                fs = calGhash(ghash, H, (iv + remOfs), remSize);
            }
            memset(j0, 0, AEAD_J0_IV_BLEN_PAD_SIZE);
#define IV_BLEN_OFS_IN_J0   (j0 + AEAD_J0_IV_BLEN_PAD_SIZE)
#define IV_BLEN_u64b_PTR    (&ivblen_u64b)
            memcpy(IV_BLEN_OFS_IN_J0, IV_BLEN_u64b_PTR, AEAD_J0_IV_BLEN_SIZE);
            byteSwap(IV_BLEN_OFS_IN_J0, IV_BLEN_OFS_IN_J0, AEAD_J0_IV_BLEN_SIZE);
#undef IV_BLEN_OFS_IN_J0
#undef IV_BLEN_u64b_PTR
        }
        else
        {
            /* ivSize is exceed bit length(64bits) */
            fs = -2;
        }
    }
    else
    {
        fs = -1;
    }

    return fs;
}

int calJ0(const uint8_t* j0, const uint8_t* const iv, const size_t ivSize, const uint8_t* const H)
{
    int fs = 0;

    if(ivSize == 0U)
    {
        fs = calJ0_ivNone(j0);
    }
    else if(ivSize == AEAD_IV_SIZE)
    {
        fs = calJ0_iv96b(j0, iv);
    }
    else
    {
        fs = calJ0_ivElse(j0, iv, ivSize, H);
    }

    return fs;
}

static inline int calS_head(const uint8_t* ghash, const uint8_t* const H, const uint8_t* const aad, const size_t size)
{
    return calGhash(ghash, H, aad, size);
}
static inline int calS_body(const uint8_t* ghash, const uint8_t* const H, const uint8_t* const data, const size_t size)
{
    return calGhash(ghash, H, data, size);
}
int calS_tail(const uint8_t* ghash, const uint8_t* const H, const size_t aSize, const size_t cSize)
{
    int fs = 0;

    if((ghash != NULL) && (H != NULL))
    {
        /* !!! Caution: not consider byte size overflow !!! */
        uint64_t bitLen[2U];
#define A_BIT_LEN   (bitLen[0U])
#define C_BIT_LEN   (bitLen[1U])

        A_BIT_LEN = (aSize << 3UL);
        C_BIT_LEN = (cSize << 3UL);
#ifdef DISABLED_TEST /* SELFTEST_AEAD */
        printf("aad    size: %lu bytes\r\n", aSize);
        printf("             0x%016lx\r\n", aSize);
        printf("       bit length: %lu bits\r\n", A_BIT_LEN);
        printf("             0x%016lx\r\n", A_BIT_LEN);
        printf("       stream: ");
        for(size_t i = 0UL; i < sizeof(A_BIT_LEN); i++)
        {
            printf("%02x", ((uint8_t*)(&A_BIT_LEN))[i]);
            if(i != (sizeof(A_BIT_LEN) - 1UL))    printf(":");
        }
        printf("\r\n");
        printf("cipher size: %lu bytes\r\n", cSize);
        printf("             0x%016lx\r\n", cSize);
        printf("       bit length: %lu bits\r\n", C_BIT_LEN);
        printf("             0x%016lx\r\n", C_BIT_LEN);
        printf("       stream: ");
        for(size_t i = 0UL; i < sizeof(C_BIT_LEN); i++)
        {
            printf("%02x", ((uint8_t*)(&C_BIT_LEN))[i]);
            if(i != (sizeof(C_BIT_LEN) - 1UL))    printf(":");
        }
        printf("\r\n");
#endif /* SELFTEST_AEAD */
        byteSwap((uint8_t*)(&A_BIT_LEN), (uint8_t*)(&A_BIT_LEN), sizeof(uint64_t));
        byteSwap((uint8_t*)(&C_BIT_LEN), (uint8_t*)(&C_BIT_LEN), sizeof(uint64_t));
#ifdef DISABLED_TEST /* SELFTEST_AEAD */
        printf("aad    bit length: %lu bits\r\n", A_BIT_LEN);
        printf("             0x%016lx\r\n", A_BIT_LEN);
        printf("       stream: ");
        for(size_t i = 0UL; i < sizeof(A_BIT_LEN); i++)
        {
            printf("%02x", ((uint8_t*)(&A_BIT_LEN))[i]);
            if(i != (sizeof(A_BIT_LEN) - 1UL))    printf(":");
        }
        printf("\r\n");
        printf("cipher bit length: %lu bits\r\n", C_BIT_LEN);
        printf("             0x%016lx\r\n", C_BIT_LEN);
        printf("       stream: ");
        for(size_t i = 0UL; i < sizeof(C_BIT_LEN); i++)
        {
            printf("%02x", ((uint8_t*)(&C_BIT_LEN))[i]);
            if(i != (sizeof(C_BIT_LEN) - 1UL))    printf(":");
        }
        printf("\r\n");
        printf("stream S: ");
        for(size_t i = 0UL; i < sizeof(bitLen); i++)
        {
            printf("%02x", ((uint8_t*)(&bitLen))[i]);
            if(i != (sizeof(bitLen) - 1UL))    printf(":");
        }
        printf("\r\n");
#endif /* SELFTEST_AEAD */
        calGhash(ghash, H, (uint8_t*)bitLen, sizeof(bitLen));

#undef A_BIT_LEN
#undef C_BIT_LEN

    }
    else
    {
        fs = -1;
    }

    return fs;
}

int inc32(const uint8_t* ctrBlk)
{
    int fs = 0;

    if(ctrBlk != NULL)
    {
#define U32_PTR (&ctrBlk[AEAD_IV_SIZE])
#define INC32   ((*((uint32_t*)U32_PTR))++)
        byteSwap(U32_PTR, U32_PTR, sizeof(uint32_t));
        INC32;
        byteSwap(U32_PTR, U32_PTR, sizeof(uint32_t));
#undef U32_PTR
#undef INC32
    }
    else
    {
        fs = -1;
    }
}

inline static int calGCTR_blk(uint8_t* const cipher_blk, const uint8_t* const plain_blk, const size_t size, const uint8_t* const key, const size_t keySize, const uint8_t* const ctrBlk)
{
    int fs = 0;

    if( ((cipher_blk != NULL) && (plain_blk != NULL))
     && ((key != NULL) && (keySize != 0UL))
     && (ctrBlk != NULL)
    )
    {
        uint8_t tmpNd[AES_S_SIZE];// temp node
                                  //
        aesEncV1(tmpNd, ctrBlk, key, keySize);
#ifdef SELFTEST_AEAD
        {
            uint8_t* dgb_u8 = (uint8_t*)tmpNd;
            size_t dbg_max = sizeof(tmpNd);
            printf("tmpNd: ");
            for(size_t i = 0UL; i < dbg_max; i++)
            {
                printf("%02x", dgb_u8[i]);
                if(i != (dbg_max - 1UL))    printf(":");
            }
            printf("\r\n");
        }
        {
            uint8_t* dgb_u8 = (uint8_t*)plain_blk;
            size_t dbg_max = AES_S_SIZE;
            printf("plain_blk: ");
            for(size_t i = 0UL; i < dbg_max; i++)
            {
                printf("%02x", dgb_u8[i]);
                if(i != (dbg_max - 1UL))    printf(":");
            }
            printf("\r\n");
        }
#endif /* SELFTEST_AEAD */
        if(BYTE2U32L_REM(size) == 0U)
        {
            xor_u32((uint32_t*)cipher_blk, (uint32_t*)plain_blk, (uint32_t*)tmpNd, BYTE2U32L_FLOOR(size));
        }
        else
        {
            xor_u8(cipher_blk, plain_blk, tmpNd, BYTE2U32L_REM(size));
        }
#ifdef SELFTEST_AEAD
        {
            uint8_t* dgb_u8 = (uint8_t*)cipher_blk;
            size_t dbg_max = AES_S_SIZE;
            printf("cipher_blk: ");
            for(size_t i = 0UL; i < dbg_max; i++)
            {
                printf("%02x", dgb_u8[i]);
                if(i != (dbg_max - 1UL))    printf(":");
            }
            printf("\r\n");
        }
#endif /* SELFTEST_AEAD */
    }
    else
    {
        fs = -1;
    }

    return fs;
}

int calGCTR(uint8_t* const cipher, const uint8_t* plain, const size_t size, const uint8_t* const key, const size_t keySize, uint8_t* const ctrBlk)
{
    int fs = 0;

    if( ((cipher != NULL) && (plain != NULL))
     && ((key != NULL) && (keySize != 0UL))
     && (ctrBlk != NULL)
    )
    {
        size_t prcSize;
        size_t remSize;
        size_t iterMax;
        uint8_t tmpNd[AES_S_SIZE];// temp node

        prcSize = 0UL;
        remSize = size;
        iterMax = (size >> 4UL); // divide to size of aes blocks
        for(size_t iter = 0UL; iter < iterMax; iter++)
        {
#ifdef SELFTEST_AEAD
            {
                printf("iter[%lu]", iter);
            }
#endif /* SELFTEST_AEAD */
            fs = calGCTR_blk(&cipher[prcSize], &plain[prcSize], AES_S_SIZE, key, keySize, ctrBlk);

            inc32(ctrBlk);
            prcSize += AES_S_SIZE;
            remSize -= AES_S_SIZE;
        }

        if(remSize != 0)
        {
            fs = calGCTR_blk(&cipher[prcSize], &plain[prcSize], remSize, key, keySize, ctrBlk);

            prcSize += remSize;
            remSize -= remSize;
        }

        if((prcSize != size) || (remSize != 0))
        {
            fs = -2; /* processing fail... */
        }
    }
    else
    {
        fs = -1;
    }

    return fs;
}

int calT(const uint8_t* msb, const uint8_t* const ghash, const uint8_t* const key, const size_t keySize, const uint8_t* const j0)
{
    return calGCTR_blk(msb, ghash, AES_S_SIZE, key, keySize, j0);
}

#ifdef SELFTEST_AEAD
#include <stdio.h>
#endif /* SELFTEST_AEAD */
int gcm_ae(uint8_t* const cipher, uint8_t* const tag, \
        const uint8_t* const iv, const size_t ivSize, \
        const uint8_t* const aad, const size_t aadSize, \
        const uint8_t* const key, const size_t keySize, \
        const uint8_t* const plain, const size_t size)
{
    int fs = 0;
    uint8_t H[AES_S_SIZE];
    uint8_t j0[AES_S_SIZE];
    uint8_t ghash[AES_S_SIZE];
    uint8_t ctrBlk[AES_S_SIZE];
    uint8_t msb[AES_S_SIZE];

    memset(ghash, 0, sizeof(ghash));
    fs = calH(H, key, keySize);
#ifdef SELFTEST_AEAD
    printHex(H, sizeof(H), "H", AES_S_SIZE);
#endif /* SELFTEST_AEAD */
    if(fs != 0) return fs;
    calJ0(j0, iv, ivSize, H);
#ifdef SELFTEST_AEAD
    printHex(j0, sizeof(j0), "j0", AES_S_SIZE);
#endif /* SELFTEST_AEAD */
    if(fs != 0) return fs;

    calS_head(ghash, H, aad, aadSize);
#ifdef SELFTEST_AEAD
    printHex(ghash, sizeof(ghash), "ghash(aad)", AES_S_SIZE);
#endif /* SELFTEST_AEAD */
    if(fs != 0) return fs;

    /* Encrypt */
    memcpy(ctrBlk, j0, sizeof(ctrBlk));
    inc32(ctrBlk);
    calGCTR(cipher, plain, size, key, keySize, ctrBlk);
    if(fs != 0) return fs;

    calS_body(ghash, H, cipher, size);
#ifdef SELFTEST_AEAD
    printHex(ghash, sizeof(ghash), "ghash(cipher)", AES_S_SIZE);
#endif /* SELFTEST_AEAD */
    if(fs != 0) return fs;

    calS_tail(ghash, H, aadSize, size);
#ifdef SELFTEST_AEAD
    printHex(ghash, sizeof(ghash), "ghash(H,A,C)", AES_S_SIZE);
#endif /* SELFTEST_AEAD */
    if(fs != 0) return fs;

    memcpy(ctrBlk, j0, sizeof(ctrBlk));
    calT(msb, ghash, key, keySize, ctrBlk);
#ifdef SELFTEST_AEAD
    printHex(msb, sizeof(msb), "msb(ICV)", AES_S_SIZE);
#endif /* SELFTEST_AEAD */
    if(fs != 0) return fs;

    if(fs == 0)
    {
        memcpy(tag, msb, sizeof(msb));
    }

    return fs;
}

#ifdef SELFTEST_AEAD
#include <stdio.h>
#endif /* SELFTEST_AEAD */
int gcm_ad(uint8_t* const plain, const uint8_t* const tag, \
        const uint8_t* const iv, const size_t ivSize, \
        const uint8_t* const aad, const size_t aadSize, \
        const uint8_t* const key, const size_t keySize, \
        const uint8_t* const cipher, const size_t size)
{
    int fs = 0;
    uint8_t H[AES_S_SIZE];
    uint8_t j0[AES_S_SIZE];
    uint8_t ghash[AES_S_SIZE];
    uint8_t ctrBlk[AES_S_SIZE];
    uint8_t msb[AES_S_SIZE];

    memset(ghash, 0, sizeof(ghash));
    fs = calH(H, key, keySize);
#ifdef SELFTEST_AEAD
    printHex(H, sizeof(H), "H", AES_S_SIZE);
#endif /* SELFTEST_AEAD */
    if(fs != 0) return fs;
    calJ0(j0, iv, ivSize, H);
#ifdef SELFTEST_AEAD
    printHex(j0, sizeof(j0), "j0", AES_S_SIZE);
#endif /* SELFTEST_AEAD */
    if(fs != 0) return fs;

    calS_head(ghash, H, aad, aadSize);
#ifdef SELFTEST_AEAD
    printHex(ghash, sizeof(ghash), "ghash(aad)", AES_S_SIZE);
#endif /* SELFTEST_AEAD */
    if(fs != 0) return fs;

    /* Decrypt:Verifying first */

    calS_body(ghash, H, cipher, size);
#ifdef SELFTEST_AEAD
    printHex(ghash, sizeof(ghash), "ghash(cipher)", AES_S_SIZE);
#endif /* SELFTEST_AEAD */
    if(fs != 0) return fs;

    calS_tail(ghash, H, aadSize, size);
#ifdef SELFTEST_AEAD
    printHex(ghash, sizeof(ghash), "ghash(H,A,C)", AES_S_SIZE);
#endif /* SELFTEST_AEAD */
    if(fs != 0) return fs;

    memcpy(ctrBlk, j0, sizeof(ctrBlk));
    calT(msb, ghash, key, keySize, ctrBlk);
#ifdef SELFTEST_AEAD
    printHex(msb, sizeof(msb), "msb(ICV)", AES_S_SIZE);
#endif /* SELFTEST_AEAD */
    if(fs != 0) return fs;

    if(fs == 0)
    {
        if(memcmp(tag, msb, sizeof(msb)) == 0)
        {
            /* VERIFIED: DECRYPT */
            memcpy(ctrBlk, j0, sizeof(ctrBlk));
            inc32(ctrBlk);
            calGCTR(plain, cipher, size, key, keySize, ctrBlk);
            if(fs != 0) return fs;
        }
    }

    return fs;
}
#ifdef SELFTEST_AEAD
#define EXAM_TEST(STATEMENTS, DESCRIPTION)                      \
{                                                               \
    bool examResult = ((STATEMENTS));                           \
    printf("%s:\x1b[33m%s\x1b[0m\r\n", (examResult?"\x1b[32mPASS\x1b[0m":"\x1b[31mFAIL\x1b[0m"), (DESCRIPTION));\
}

static void printHex(void* data, size_t size, const char* title, size_t lf)
{
    if(data != NULL)
    {
        size_t lfe;
        if(lf == 0)
        {
            lf = 32UL;
            lfe = 31UL;
        }
        else
        {
            lfe = lf - 1UL;
        }
        printf("[%s]\r\n", (title!=NULL)?title:"unknown");
        uint8_t* p = (uint8_t*)data;
        for(size_t i = 0UL; i < size; i++)
        {
            if((i % lf) == 0UL) printf("0x%016lx: ", i);
            printf("%02x ", p[i]);
            if((i % lf) == lfe) printf("\r\n");
        }
        if((size-1UL) != lfe)   printf("\r\n");
    }
    else { /* Do Nothing */ }
}

#include <string.h>

static void test_getH(void)
{
    /* 
     * MACsec GCM-AES Test Vectors,  April 11, 2011, 
     * Provided for IEEE P802.1 Security Task Group 
     * consideration by Karen Randall 
     */
    uint8_t ref_key[] = { 
        0xadU, 0x7aU, 0x2bU, 0xd0U, 0x3eU, 0xacU, 0x83U, 0x5aU, 0x6fU, 0x62U, 0x0fU, 0xdcU, 0xb5U, 0x06U, 0xb3U, 0x45U, 
    };
    uint8_t ref_H [] = { 
        0x73U, 0xa2U, 0x3dU, 0x80U, 0x12U, 0x1dU, 0xe2U, 0xd5U, 0xa8U, 0x50U, 0x25U, 0x3fU, 0xcfU, 0x43U, 0x12U, 0x0eU, 
    };

    uint8_t test_H[AES_S_SIZE];

    calH(test_H, ref_key, sizeof(ref_key));
    EXAM_TEST(memcmp(test_H, ref_H, sizeof(ref_H)) == 0, "AES-GCM Const H");
    //printHex(test_H, sizeof(test_H), "2.1.1. GCM, H", AES_S_SIZE);
}

static void test_calS_head(void)
{
    /* 
     * MACsec GCM-AES Test Vectors,  April 11, 2011, 
     * Provided for IEEE P802.1 Security Task Group 
     * consideration by Karen Randall 
     */
    /* 2.1.1 54-byte Packet Authentication Using GCM-AES-128 */
    uint8_t ref_key[] = { 
        0xAD, 0x7A, 0x2B, 0xD0, 0x3E, 0xAC, 0x83, 0x5A, 0x6F, 0x62, 0x0F, 0xDC, 0xB5, 0x06, 0xB3, 0x45, 
    };

    uint8_t ref_aad[] = {
        0xd6U, 0x09U, 0xb1U, 0xf0U, 0x56U, 0x63U, 0x7aU, 0x0dU, 0x46U, 0xdfU, 0x99U, 0x8dU, 0x88U, 0xe5U, 0x22U, 0x2aU, 
        0xb2U, 0xc2U, 0x84U, 0x65U, 0x12U, 0x15U, 0x35U, 0x24U, 0xc0U, 0x89U, 0x5eU, 0x81U, 0x08U, 0x00U, 0x0fU, 0x10U, 
        0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U, 0x18U, 0x19U, 0x1aU, 0x1bU, 0x1cU, 0x1dU, 0x1eU, 0x1fU, 0x20U, 
        0x21U, 0x22U, 0x23U, 0x24U, 0x25U, 0x26U, 0x27U, 0x28U, 0x29U, 0x2aU, 0x2bU, 0x2cU, 0x2dU, 0x2eU, 0x2fU, 0x30U, 
        0x31U, 0x32U, 0x33U, 0x34U, 0x00U, 0x01U, 
    };
    uint8_t ref_X1[] = { 
        0x6bU, 0x0bU, 0xe6U, 0x8dU, 0x67U, 0xc6U, 0xeeU, 0x03U, 0xefU, 0x79U, 0x98U, 0xe3U, 0x99U, 0xc0U, 0x1cU, 0xa4U, 
    };
    uint8_t ref_X2[] = { 
        0x5aU, 0xabU, 0xadU, 0xf6U, 0xd7U, 0x80U, 0x6eU, 0xc0U, 0xccU, 0xcbU, 0x02U, 0x84U, 0x41U, 0x19U, 0x7bU, 0x22U, 
    };
    uint8_t ref_X3[] = { 
        0xfeU, 0x07U, 0x2bU, 0xfeU, 0x28U, 0x11U, 0xa6U, 0x8aU, 0xd7U, 0xfdU, 0xb0U, 0x68U, 0x71U, 0x92U, 0xd2U, 0x93U, 
    };
    uint8_t ref_X4[] = { 
        0xa4U, 0x72U, 0x52U, 0xd1U, 0xa7U, 0xe0U, 0x9bU, 0x49U, 0xfbU, 0x35U, 0x6eU, 0x43U, 0x5dU, 0xbbU, 0x4cU, 0xd0U, 
    };
    uint8_t ref_X5[] = { 
        0x18U, 0xebU, 0xf4U, 0xc6U, 0x5cU, 0xe8U, 0x9bU, 0xf6U, 0x9eU, 0xfbU, 0x49U, 0x81U, 0xceU, 0xe1U, 0x3dU, 0xb9U, 
    };

    uint8_t test_H[AES_S_SIZE];
    uint8_t test_ghash[AES_S_SIZE];

    size_t test_prcSize;
    size_t test_remSize;

    calH(test_H, ref_key, sizeof(ref_key));
    printHex(test_H, sizeof(test_H), "H", AES_S_SIZE);

    memset(test_ghash, 0, sizeof(test_ghash));
    calS_head(test_ghash, test_H, ref_aad, sizeof(ref_aad));
    EXAM_TEST(memcmp(test_ghash, ref_X5, sizeof(ref_X5)) == 0, "AES-GCM AAD GHASH(ONESHOT)");
    //printHex(test_ghash, sizeof(test_ghash), "AAD GHASH", AES_S_SIZE);

    memset(test_ghash, 0, sizeof(test_ghash));
    test_prcSize = 0UL;
    test_remSize = sizeof(ref_aad);
    calS_head(test_ghash, test_H, &ref_aad[test_prcSize], AES_S_SIZE);
    test_prcSize += AES_S_SIZE;
    test_remSize -= AES_S_SIZE;
    EXAM_TEST(memcmp(test_ghash, ref_X1, sizeof(ref_X1)) == 0, "AES-GCM AAD GHASH(X1)");
    calS_head(test_ghash, test_H, &ref_aad[test_prcSize], AES_S_SIZE);
    test_prcSize += AES_S_SIZE;
    test_remSize -= AES_S_SIZE;
    EXAM_TEST(memcmp(test_ghash, ref_X2, sizeof(ref_X2)) == 0, "AES-GCM AAD GHASH(X2)");
    calS_head(test_ghash, test_H, &ref_aad[test_prcSize], AES_S_SIZE);
    test_prcSize += AES_S_SIZE;
    test_remSize -= AES_S_SIZE;
    EXAM_TEST(memcmp(test_ghash, ref_X3, sizeof(ref_X3)) == 0, "AES-GCM AAD GHASH(X3)");
    calS_head(test_ghash, test_H, &ref_aad[test_prcSize], AES_S_SIZE);
    test_prcSize += AES_S_SIZE;
    test_remSize -= AES_S_SIZE;
    EXAM_TEST(memcmp(test_ghash, ref_X4, sizeof(ref_X4)) == 0, "AES-GCM AAD GHASH(X4)");
    calS_head(test_ghash, test_H, &ref_aad[test_prcSize], test_remSize);
    test_prcSize += test_remSize;
    test_remSize -= test_remSize;
    EXAM_TEST(memcmp(test_ghash, ref_X5, sizeof(ref_X5)) == 0, "AES-GCM AAD GHASH(X5)");
}

static void test_calJ0(void)
{
    /* 
     * MACsec GCM-AES Test Vectors,  April 11, 2011, 
     * Provided for IEEE P802.1 Security Task Group 
     * consideration by Karen Randall 
     */
    /* 2.1.1 54-byte Packet Authentication Using GCM-AES-128 */
    uint8_t ref_iv[] = {
        0x12U, 0x15U, 0x35U, 0x24U, 0xc0U, 0x89U, 0x5eU, 0x81U, 0xb2U, 0xc2U, 0x84U, 0x65U, 
    };
    uint8_t ref_j0[] = {
        0x12U, 0x15U, 0x35U, 0x24U, 0xc0U, 0x89U, 0x5eU, 0x81U, 0xb2U, 0xc2U, 0x84U, 0x65U, 0x00U, 0x00U, 0x00U, 0x01, 
    };
    uint8_t ref_H[] = {
        0x73U, 0xA2U, 0x3DU, 0x80U, 0x12U, 0x1DU, 0xE2U, 0xD5U, 0xA8U, 0x50U, 0x25U, 0x3FU, 0xCFU, 0x43U, 0x12U, 0x0EU,
    };

    uint8_t test_j0[GHASH_SIZE];

    calJ0(test_j0, ref_iv, sizeof(ref_iv), ref_H);
    EXAM_TEST(memcmp(test_j0, ref_j0, sizeof(ref_j0)) == 0, "2.1.1 54-byte Packet Authentication Using GCM-AES-128, Y[0]");
    printHex(test_j0, sizeof(test_j0), "Y[0]", sizeof(test_j0));
}

static void test_calS_tail(void)
{
    /* 
     * MACsec GCM-AES Test Vectors,  April 11, 2011, 
     * Provided for IEEE P802.1 Security Task Group 
     * consideration by Karen Randall 
     */
    /* 2.1.1 54-byte Packet Authentication Using GCM-AES-128 */
    uint8_t ref_H[]  = { 
        0x73U, 0xa2U, 0x3dU, 0x80U, 0x12U, 0x1dU, 0xe2U, 0xd5U, 0xa8U, 0x50U, 0x25U, 0x3fU, 0xcfU, 0x43U, 0x12U, 0x0eU, 
    };
    uint8_t ref_X5[] = { 
        0x18U, 0xebU, 0xf4U, 0xc6U, 0x5cU, 0xe8U, 0x9bU, 0xf6U, 0x9eU, 0xfbU, 0x49U, 0x81U, 0xceU, 0xe1U, 0x3dU, 0xb9U, 
    };
    uint8_t ref_ghashHAC[] = { 
        0x1bU, 0xdaU, 0x7dU, 0xb5U, 0x05U, 0xd8U, 0xa1U, 0x65U, 0x26U, 0x49U, 0x86U, 0xa7U, 0x03U, 0xa6U, 0x92U, 0x0dU, 
    };

    uint8_t test_ghash[GHASH_SIZE];

    size_t test_aSize = 560UL >> 3UL;  // bit length to byte size;
    size_t test_cSize = 0UL >> 3UL;    // bit length to byte size;

    memcpy(test_ghash, ref_X5, sizeof(test_ghash));
    calS_tail(test_ghash, ref_H, test_aSize, test_cSize);
    EXAM_TEST(memcmp(test_ghash, ref_ghashHAC, sizeof(ref_ghashHAC)) == 0, "2.1.1 54-byte Packet Authentication Using GCM-AES-128, GHASH(H,A,C)");
    printHex(test_ghash, sizeof(test_ghash), "GHASH(H,A,C)", sizeof(test_ghash));
}

static void test_gctr(void)
{
    /* 
     * MACsec GCM-AES Test Vectors,  April 11, 2011, 
     * Provided for IEEE P802.1 Security Task Group 
     * consideration by Karen Randall 
     */
    /* 2.2.1 60-Byte Packet Encryption Using GCM-AES-128 */
    uint8_t ref_key[] = { 
        0xadU, 0x7aU, 0x2bU, 0xd0U, 0x3eU, 0xacU, 0x83U, 0x5aU, 0x6fU, 0x62U, 0x0fU, 0xdcU, 0xb5U, 0x06U, 0xb3U, 0x45U, 
    };
    uint8_t ref_J0[] = { 
        0x12U, 0x15U, 0x35U, 0x24U, 0xc0U, 0x89U, 0x5eU, 0x81U, 0xb2U, 0xc2U, 0x84U, 0x65U, 0x00U, 0x00U, 0x00U, 0x01U, 
    };
    uint8_t ref_P[] = {
        0x08U, 0x00U, 0x0fU, 0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U, 0x18U, 0x19U, 0x1aU, 0x1bU, 0x1cU, 
        0x1dU, 0x1eU, 0x1fU, 0x20U, 0x21U, 0x22U, 0x23U, 0x24U, 0x25U, 0x26U, 0x27U, 0x28U, 0x29U, 0x2aU, 0x2bU, 0x2cU, 
        0x2dU, 0x2eU, 0x2fU, 0x30U, 0x31U, 0x32U, 0x33U, 0x34U, 0x35U, 0x36U, 0x37U, 0x38U, 0x39U, 0x3aU, 0x00U, 0x02U, 
    };
    uint8_t ref_C[] = {
        0x70U, 0x1aU, 0xfaU, 0x1cU, 0xc0U, 0x39U, 0xc0U, 0xd7U, 0x65U, 0x12U, 0x8aU, 0x66U, 0x5dU, 0xabU, 0x69U, 0x24U, 
        0x38U, 0x99U, 0xbfU, 0x73U, 0x18U, 0xccU, 0xdcU, 0x81U, 0xc9U, 0x93U, 0x1dU, 0xa1U, 0x7fU, 0xbeU, 0x8eU, 0xddU, 
        0x7dU, 0x17U, 0xcbU, 0x8bU, 0x4cU, 0x26U, 0xfcU, 0x81U, 0xe3U, 0x28U, 0x4fU, 0x2bU, 0x7fU, 0xbaU, 0x71U, 0x3dU, 
    };

    uint8_t test_Y[AES_S_SIZE];
    uint8_t test_cipher[AES_S_SIZE * 3U];

    memcpy(test_Y, ref_J0, sizeof(ref_J0));
    inc32(test_Y);
    calGCTR(test_cipher, ref_P, sizeof(ref_P), ref_key, sizeof(ref_key), test_Y);
    EXAM_TEST(memcmp(test_cipher, ref_C, sizeof(ref_C)) == 0, "2.2.1 60-Byte Packet Encryption Using GCM-AES-128, C");
    printHex(test_cipher, sizeof(test_cipher), "C", AES_S_SIZE);
}

static void test_calT(void)
{
    /* 
     * MACsec GCM-AES Test Vectors,  April 11, 2011, 
     * Provided for IEEE P802.1 Security Task Group 
     * consideration by Karen Randall 
     */
    /* 2.2.1 60-Byte Packet Encryption Using GCM-AES-128 */
    uint8_t ref_key[] = { 
        0xadU, 0x7aU, 0x2bU, 0xd0U, 0x3eU, 0xacU, 0x83U, 0x5aU, 0x6fU, 0x62U, 0x0fU, 0xdcU, 0xb5U, 0x06U, 0xb3U, 0x45U, 
    };
    uint8_t ref_J0[] = { 
        0x12U, 0x15U, 0x35U, 0x24U, 0xc0U, 0x89U, 0x5eU, 0x81U, 0xb2U, 0xc2U, 0x84U, 0x65U, 0x00U, 0x00U, 0x00U, 0x01U, 
    };
    uint8_t ref_ghashHAC[] = { 
        0x1bU, 0xdaU, 0x7dU, 0xb5U, 0x05U, 0xd8U, 0xa1U, 0x65U, 0x26U, 0x49U, 0x86U, 0xa7U, 0x03U, 0xa6U, 0x92U, 0x0dU, 
    };
    uint8_t ref_T[] = {
        0xf0U, 0x94U, 0x78U, 0xa9U, 0xb0U, 0x90U, 0x07U, 0xd0U, 0x6fU, 0x46U, 0xe9U, 0xb6U, 0xa1U, 0xdaU, 0x25U, 0xddU,
    };

    uint8_t test_msb[AES_S_SIZE];
    uint8_t test_tag[AES_S_SIZE];

    calT(test_msb, ref_ghashHAC, ref_key, sizeof(ref_key), ref_J0);
    memcpy(test_tag, test_msb, sizeof(test_tag));
    EXAM_TEST(memcmp(test_tag, ref_T, sizeof(ref_T)) == 0, "2.2.1 60-Byte Packet Encryption Using GCM-AES-128, T");
    printHex(test_tag, sizeof(test_tag), "T", AES_S_SIZE);
}

static void test_gcm_ae(void)
{
    /* 
     * MACsec GCM-AES Test Vectors,  April 11, 2011, 
     * Provided for IEEE P802.1 Security Task Group 
     * consideration by Karen Randall 
     */
    /* 2.2.1 60-Byte Packet Encryption Using GCM-AES-128 */
    uint8_t ref_T[] = {
        0x4fU, 0x8dU, 0x55U, 0xe7U, 0xd3U, 0xf0U, 0x6fU, 0xd5U, 0xa1U, 0x3cU, 0x0cU, 0x29U, 0xb9U, 0xd5U, 0xb8U, 0x80U,
    };
    uint8_t ref_iv[] = {
        0x12U, 0x15U, 0x35U, 0x24U, 0xc0U, 0x89U, 0x5eU, 0x81U, 0xb2U, 0xc2U, 0x84U, 0x65U, 
    };
    uint8_t ref_aad[] = {
        0xd6U, 0x09U, 0xb1U, 0xf0U, 0x56U, 0x63U, 0x7aU, 0x0dU, 0x46U, 0xdfU, 0x99U, 0x8dU, 0x88U, 0xe5U, 0x2eU, 0x00U, 
        0xb2U, 0xc2U, 0x84U, 0x65U, 0x12U, 0x15U, 0x35U, 0x24U, 0xc0U, 0x89U, 0x5eU, 0x81U, 
    };
    uint8_t ref_key[] = { 
        0xadU, 0x7aU, 0x2bU, 0xd0U, 0x3eU, 0xacU, 0x83U, 0x5aU, 0x6fU, 0x62U, 0x0fU, 0xdcU, 0xb5U, 0x06U, 0xb3U, 0x45U, 
    };
    uint8_t ref_plain[] = {
        0x08U, 0x00U, 0x0fU, 0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U, 0x18U, 0x19U, 0x1aU, 0x1bU, 0x1cU, 
        0x1dU, 0x1eU, 0x1fU, 0x20U, 0x21U, 0x22U, 0x23U, 0x24U, 0x25U, 0x26U, 0x27U, 0x28U, 0x29U, 0x2aU, 0x2bU, 0x2cU, 
        0x2dU, 0x2eU, 0x2fU, 0x30U, 0x31U, 0x32U, 0x33U, 0x34U, 0x35U, 0x36U, 0x37U, 0x38U, 0x39U, 0x3aU, 0x00U, 0x02U,
    };
    uint8_t ref_cipher[] = {
        0x70U, 0x1aU, 0xfaU, 0x1cU, 0xc0U, 0x39U, 0xc0U, 0xd7U, 0x65U, 0x12U, 0x8aU, 0x66U, 0x5dU, 0xabU, 0x69U, 0x24U, 
        0x38U, 0x99U, 0xbfU, 0x73U, 0x18U, 0xccU, 0xdcU, 0x81U, 0xc9U, 0x93U, 0x1dU, 0xa1U, 0x7fU, 0xbeU, 0x8eU, 0xddU, 
        0x7dU, 0x17U, 0xcbU, 0x8bU, 0x4cU, 0x26U, 0xfcU, 0x81U, 0xe3U, 0x28U, 0x4fU, 0x2bU, 0x7fU, 0xbaU, 0x71U, 0x3dU, 
    };

    uint8_t test_cipher[AES_S_SIZE * 3];
    uint8_t test_tag[AES_S_SIZE];

    printf("Authenticated Encryption\n2.2.1 60-Byte Packet Encryption Using GCM-AES-128\n");
    printHex(ref_T,         sizeof(ref_T),      "T", AES_S_SIZE);
    printHex(ref_iv,        sizeof(ref_iv),     "IV", AES_S_SIZE);
    printHex(ref_aad,       sizeof(ref_aad),    "A", AES_S_SIZE);
    printHex(ref_key,       sizeof(ref_key),    "Key", AES_S_SIZE);
    printHex(ref_plain,     sizeof(ref_plain),  "P", AES_S_SIZE);
    printHex(ref_cipher,    sizeof(ref_cipher), "C", AES_S_SIZE);

    gcm_ae(test_cipher, test_tag, \
            ref_iv, sizeof(ref_iv), \
            ref_aad, sizeof(ref_aad), \
            ref_key, sizeof(ref_key), \
            ref_plain, sizeof(ref_plain));
    EXAM_TEST(memcmp(test_cipher, ref_cipher, sizeof(ref_cipher)) == 0, "2.2.1 60-Byte Packet Encryption Using GCM-AES-128, C");
    printHex(test_cipher, sizeof(test_cipher), "C", AES_S_SIZE);
    EXAM_TEST(memcmp(test_tag, ref_T, sizeof(ref_T)) == 0, "2.2.1 60-Byte Packet Encryption Using GCM-AES-128, T");
    printHex(test_tag, sizeof(test_tag), "T", AES_S_SIZE);
}

static void test_gcm_ad(void)
{
    /* 
     * MACsec GCM-AES Test Vectors,  April 11, 2011, 
     * Provided for IEEE P802.1 Security Task Group 
     * consideration by Karen Randall 
     */
    /* 2.2.1 60-Byte Packet Encryption Using GCM-AES-128 */
    uint8_t ref_T[] = {
        0x4fU, 0x8dU, 0x55U, 0xe7U, 0xd3U, 0xf0U, 0x6fU, 0xd5U, 0xa1U, 0x3cU, 0x0cU, 0x29U, 0xb9U, 0xd5U, 0xb8U, 0x80U,
    };
    uint8_t ref_iv[] = {
        0x12U, 0x15U, 0x35U, 0x24U, 0xc0U, 0x89U, 0x5eU, 0x81U, 0xb2U, 0xc2U, 0x84U, 0x65U, 
    };
    uint8_t ref_aad[] = {
        0xd6U, 0x09U, 0xb1U, 0xf0U, 0x56U, 0x63U, 0x7aU, 0x0dU, 0x46U, 0xdfU, 0x99U, 0x8dU, 0x88U, 0xe5U, 0x2eU, 0x00U, 
        0xb2U, 0xc2U, 0x84U, 0x65U, 0x12U, 0x15U, 0x35U, 0x24U, 0xc0U, 0x89U, 0x5eU, 0x81U, 
    };
    uint8_t ref_key[] = { 
        0xadU, 0x7aU, 0x2bU, 0xd0U, 0x3eU, 0xacU, 0x83U, 0x5aU, 0x6fU, 0x62U, 0x0fU, 0xdcU, 0xb5U, 0x06U, 0xb3U, 0x45U, 
    };
    uint8_t ref_plain[] = {
        0x08U, 0x00U, 0x0fU, 0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U, 0x18U, 0x19U, 0x1aU, 0x1bU, 0x1cU, 
        0x1dU, 0x1eU, 0x1fU, 0x20U, 0x21U, 0x22U, 0x23U, 0x24U, 0x25U, 0x26U, 0x27U, 0x28U, 0x29U, 0x2aU, 0x2bU, 0x2cU, 
        0x2dU, 0x2eU, 0x2fU, 0x30U, 0x31U, 0x32U, 0x33U, 0x34U, 0x35U, 0x36U, 0x37U, 0x38U, 0x39U, 0x3aU, 0x00U, 0x02U,
    };
    uint8_t ref_cipher[] = {
        0x70U, 0x1aU, 0xfaU, 0x1cU, 0xc0U, 0x39U, 0xc0U, 0xd7U, 0x65U, 0x12U, 0x8aU, 0x66U, 0x5dU, 0xabU, 0x69U, 0x24U, 
        0x38U, 0x99U, 0xbfU, 0x73U, 0x18U, 0xccU, 0xdcU, 0x81U, 0xc9U, 0x93U, 0x1dU, 0xa1U, 0x7fU, 0xbeU, 0x8eU, 0xddU, 
        0x7dU, 0x17U, 0xcbU, 0x8bU, 0x4cU, 0x26U, 0xfcU, 0x81U, 0xe3U, 0x28U, 0x4fU, 0x2bU, 0x7fU, 0xbaU, 0x71U, 0x3dU, 
    };

    uint8_t test_plain[AES_S_SIZE * 3];
    uint8_t test_tag[AES_S_SIZE];

    printf("Authenticated Decryption\n2.2.1 60-Byte Packet Encryption Using GCM-AES-128]\n");
    printHex(ref_T,         sizeof(ref_T),      "T", AES_S_SIZE);
    printHex(ref_iv,        sizeof(ref_iv),     "IV", AES_S_SIZE);
    printHex(ref_aad,       sizeof(ref_aad),    "A", AES_S_SIZE);
    printHex(ref_key,       sizeof(ref_key),    "Key", AES_S_SIZE);
    printHex(ref_plain,     sizeof(ref_plain),  "P", AES_S_SIZE);
    printHex(ref_cipher,    sizeof(ref_cipher), "C", AES_S_SIZE);

    gcm_ad(test_plain, ref_T, \
            ref_iv, sizeof(ref_iv), \
            ref_aad, sizeof(ref_aad), \
            ref_key, sizeof(ref_key), \
            ref_cipher, sizeof(ref_cipher));
    EXAM_TEST(memcmp(test_plain, ref_plain, sizeof(ref_plain)) == 0, "2.2.1 60-Byte Packet Encryption Using GCM-AES-128, P");
    printHex(test_plain, sizeof(test_plain), "P", AES_S_SIZE);
}

int main(int argc, char* argv[])
{
    test_getH();

    test_calS_head();

    test_calJ0();

    test_calS_tail();

    test_gctr();

    test_calT();

    test_gcm_ae();

    test_gcm_ad();

    return 0;
}
#endif /* SELFTEST_AEAD */
