#ifdef DEBUG
#include <stdio.h>
#define dprintf(...)    printf(__VA_ARGS__)
#else
#define dprintf(...)
#endif /* DEBUG */
#include <stdlib.h> // defines 'LITTLE_ENDIAN'
#include <stdint.h>
#include <string.h>

#include "hash/sha2.h"

/* SHA2(SHA256, SHA512) Commons */
#define SHA2_BLEN_NUM       2U  // length of symbol

#define SHA256_BLEN_SIZE    8U  // bytes
#define SHA512_BLEN_SIZE    16U // bytes

#define SHA_END_SIZE        1U
#define SHA_END_BYTE        0x80U

/* SHA2 Operations */
#define ROTL(wBit, nBit, X) (((X)<<(nBit)) | (X)>>(wBit-nBit))
#define ROTR(wBit, nBit, X) (((X)>>(nBit)) | (X)<<(wBit-nBit))
#define SHR(nBit, X)        ((X)>>(nBit))
#define SHL(nBit, X)        ((X)<<(nBit))

/* SHA1, SHA2 used */
#define Ch(X,Y,Z)           (((X)&(Y))^((~(X))&(Z)))
#define Maj(X,Y,Z)          (((X)&(Y))^((X)&(Z))^((Y)&(Z)))

/* SHA256, SUM, SGM(SIGMA) used */
#define SUM0_256(X)         (ROTR(32U,  2U, X) ^ ROTR(32U, 13U, X) ^ ROTR(32U, 22U, X))
#define SUM1_256(X)         (ROTR(32U,  6U, X) ^ ROTR(32U, 11U, X) ^ ROTR(32U, 25U, X))
#define SGM0_256(X)         (ROTR(32U,  7U, X) ^ ROTR(32U, 18U, X) ^  SHR(      3U, X))
#define SGM1_256(X)         (ROTR(32U, 17U, X) ^ ROTR(32U, 19U, X) ^  SHR(     10U, X))

/* SHA512, SUM, SGM(SIGMA) used */
#define SUM0_512(X)         (ROTR(64U, 28U, X) ^ ROTR(64U, 34U, X) ^ ROTR(64U, 39U, X))
#define SUM1_512(X)         (ROTR(64U, 14U, X) ^ ROTR(64U, 18U, X) ^ ROTR(64U, 41U, X))
#define SGM0_512(X)         (ROTR(64U,  1U, X) ^ ROTR(64U,  8U, X) ^  SHR(      7U, X))
#define SGM1_512(X)         (ROTR(64U, 19U, X) ^ ROTR(64U, 61U, X) ^  SHR(      6U, X))

#define MOD16(X)            ((X)&0xfU)

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

/* SHA2 constant values */
const uint32_t H0_224[SHA2_DIGEST_NUM] = {
    0xc1059ed8U, 0x367cd507U, 0x3070dd17U, 0xf70e5939U, 
    0xffc00b31U, 0x68581511U, 0x64f98fa7U, 0xbefa4fa4U, 
};

const uint32_t H0_256[SHA2_DIGEST_NUM] = {
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU, 
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U, 
};

const uint32_t K256[SHA256_ROUND_NUM] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U, 
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U, 
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U, 
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U, 
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U, 
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U, 
};

const uint64_t H0_384[SHA2_DIGEST_NUM] = {
    0xcbbb9d5dc1059ed8U, 0x629a292a367cd507U, 0x9159015a3070dd17U, 0x152fecd8f70e5939U, 
    0x67332667ffc00b31U, 0x8eb44a8768581511U, 0xdb0c2e0d64f98fa7U, 0x47b5481dbefa4fa4U, 
};

const uint64_t H0_512[SHA2_DIGEST_NUM] = {
    0x6a09e667f3bcc908U, 0xbb67ae8584caa73bU, 0x3c6ef372fe94f82bU, 0xa54ff53a5f1d36f1U, 
    0x510e527fade682d1U, 0x9b05688c2b3e6c1fU, 0x1f83d9abfb41bd6bU, 0x5be0cd19137e2179U, 
};

const uint64_t H0_512_224[SHA2_DIGEST_NUM] = {
    0x8c3d37c819544da2U, 0x73e1996689dcd4d6U, 0x1dfab7ae32ff9c82U, 0x679dd514582f9fcfU, 
    0x0f6d2b697bd44da8U, 0x77e36f7304c48942U, 0x3f9d85a86a1d36c8U, 0x1112e6ad91d692a1U, 
};

const uint64_t H0_512_256[SHA2_DIGEST_NUM] = {
    0x22312194fc2bf72cU, 0x9f555fa3c84c64c2U, 0x2393b86b6f53b151U, 0x963877195940eabdU, 
    0x96283ee2a88effe3U, 0xbe5e1e2553863992U, 0x2b0199fc2c85b8aaU, 0x0eb72ddc81c52ca2U, 
};

const uint64_t K512[SHA512_ROUND_NUM] = {
    0x428a2f98d728ae22U, 0x7137449123ef65cdU, 0xb5c0fbcfec4d3b2fU, 0xe9b5dba58189dbbcU, 
    0x3956c25bf348b538U, 0x59f111f1b605d019U, 0x923f82a4af194f9bU, 0xab1c5ed5da6d8118U, 
    0xd807aa98a3030242U, 0x12835b0145706fbeU, 0x243185be4ee4b28cU, 0x550c7dc3d5ffb4e2U, 
    0x72be5d74f27b896fU, 0x80deb1fe3b1696b1U, 0x9bdc06a725c71235U, 0xc19bf174cf692694U, 
    0xe49b69c19ef14ad2U, 0xefbe4786384f25e3U, 0x0fc19dc68b8cd5b5U, 0x240ca1cc77ac9c65U, 
    0x2de92c6f592b0275U, 0x4a7484aa6ea6e483U, 0x5cb0a9dcbd41fbd4U, 0x76f988da831153b5U, 
    0x983e5152ee66dfabU, 0xa831c66d2db43210U, 0xb00327c898fb213fU, 0xbf597fc7beef0ee4U, 
    0xc6e00bf33da88fc2U, 0xd5a79147930aa725U, 0x06ca6351e003826fU, 0x142929670a0e6e70U, 
    0x27b70a8546d22ffcU, 0x2e1b21385c26c926U, 0x4d2c6dfc5ac42aedU, 0x53380d139d95b3dfU, 
    0x650a73548baf63deU, 0x766a0abb3c77b2a8U, 0x81c2c92e47edaee6U, 0x92722c851482353bU, 
    0xa2bfe8a14cf10364U, 0xa81a664bbc423001U, 0xc24b8b70d0f89791U, 0xc76c51a30654be30U, 
    0xd192e819d6ef5218U, 0xd69906245565a910U, 0xf40e35855771202aU, 0x106aa07032bbd1b8U, 
    0x19a4c116b8d2d0c8U, 0x1e376c085141ab53U, 0x2748774cdf8eeb99U, 0x34b0bcb5e19b48a8U, 
    0x391c0cb3c5c95a63U, 0x4ed8aa4ae3418acbU, 0x5b9cca4f7763e373U, 0x682e6ff3d6b2b8a3U, 
    0x748f82ee5defb2fcU, 0x78a5636f43172f60U, 0x84c87814a1f0ab72U, 0x8cc702081a6439ecU, 
    0x90befffa23631e28U, 0xa4506cebde82bde9U, 0xbef9a3f7b2c67915U, 0xc67178f2e372532bU, 
    0xca273eceea26619cU, 0xd186b8c721c0c207U, 0xeada7dd6cde0eb1eU, 0xf57d4f7fee6ed178U, 
    0x06f067aa72176fbaU, 0x0a637dc5a2c898a6U, 0x113f9804bef90daeU, 0x1b710b35131c471bU, 
    0x28db77f523047d84U, 0x32caab7b40c72493U, 0x3c9ebe0a15c9bebcU, 0x431d67c49c100d4cU, 
    0x4cc5d4becb3e42b6U, 0x597f299cfc657e2aU, 0x5fcb6fab3ad6faecU, 0x6c44198c4a475817U, 
};

/* Internal Variavbles */
typedef struct {
    uint64_t Wmod[SHA2_BLOCK_NUM];  // message schedule(128Bytes), length was modulo 16
    uint64_t Node[SHA2_DIGEST_NUM]; // Nd[0]:a, Nd[1]:b, ... Nd[7]:h
    uint64_t BtSz[SHA2_BLEN_NUM];   // Accumulated Byte Size
} sha512_ctx_t;
typedef struct {
    uint32_t Wmod[SHA2_BLOCK_NUM];  // message schedule(32Bytes), length was modulo 16
    uint32_t Node[SHA2_DIGEST_NUM]; // Nd[0]:a, Nd[1]:b, ... Nd[7]:h
    uint32_t BtSz[SHA2_BLEN_NUM];   // Accumulated Byte Size
} sha256_ctx_t;
typedef union {
    sha256_ctx_t sha256;
    sha512_ctx_t sha512;
} sha2_ctx_t;

/* SHA2 Common */
static sha2_ctx_t l_ctx;

/* SHA256 */
#define l_W256mod16 (l_ctx.sha256.Wmod)
#define l_Nd256     (l_ctx.sha256.Node)
#define l_Bsz256    (l_ctx.sha256.BtSz)

/* SHA512 */
#define l_W512mod16 (l_ctx.sha512.Wmod)
#define l_Nd512     (l_ctx.sha512.Node)
#define l_Bsz512    (l_ctx.sha512.BtSz)

/* Internal Functions */
static size_t addSize256(const size_t mesSize);
static size_t addSize512(const size_t mesSize);
static uint32_t convSize2blen256(const uint32_t in);
static uint64_t convSize2blen512(const uint64_t in);

static void preProcessingHash256_0_pad(const size_t mesSize);
static void preProcessingHash512_0_pad(const size_t mesSize);
static size_t preProcessingHash256_endBit(const size_t loc);
static size_t preProcessingHash512_endBit(const size_t loc);
static size_t preProcessingHash256_bitLen(const size_t loc);
static size_t preProcessingHash512_bitLen(const size_t loc);
static size_t preProcessHash256(uint32_t* hash);
static size_t preProcessHash512(uint64_t* hash);

static void init_W_mod16_256(const uint32_t* mes);
static void init_W_mod16_512(const uint64_t* mes);
static void update_W_mod16_256(const size_t t);
static void update_W_mod16_512(const size_t t);

static void compSha256_W_mod16(uint32_t* hash);
static void compSha512_W_mod16(uint64_t* hash);

/* Implements Functions */
void conv32bitEndian(uint32_t* dst, const uint32_t* src, const size_t size)
{
#define _MEM_ALIGN_MSK_ 0x3UL   // Bytes
    if((size & _MEM_ALIGN_MSK_) == 0UL)
    {
        for(size_t i = 0UL; i < SIZE2UI32LEN(size); i++)
        {
            dst[i] = EDCVAL32(src[i]);
        }
    }
    else
    {
        // align error
    }
#undef _MEM_ALIGN_MSK_
}

void conv64bitEndian(uint64_t* dst, const uint64_t* src, const size_t size)
{
#define _MEM_ALIGN_MSK_ 0x7UL   // Bytes
    if((size & _MEM_ALIGN_MSK_) == 0UL)
    {
        for(size_t i = 0UL; i < SIZE2UI64LEN(size); i++)
        {
            dst[i] = EDCVAL64(src[i]);
        }
    }
    else
    {
        // align error
    }
#undef _MEM_ALIGN_MSK_
}

static size_t addSize256(const size_t mesSize)
{
#define _shrLEN_    32UL
    size_t c_i, c_o;
    uint32_t tmp;
    size_t t_msz;

    c_i = 0UL, c_o = 0UL;
    t_msz = mesSize;

    for(size_t i = 0UL; i < SIZE2UI32LEN(sizeof(mesSize)); i++)
    {
        c_i = c_o;
        c_o = 0UL;
        tmp = l_Bsz256[i];           /* to check carry */
        l_Bsz256[0] += ((uint32_t)c_i); /* CARRY */
        if(tmp > l_Bsz256[i])        /* to detect carry */
        {
            c_o += 1UL;
        }
        tmp = l_Bsz256[i];           /* to check carry */
        l_Bsz256[0] += ((uint32_t)t_msz); /* LO_BSZ */
        t_msz = (t_msz >> _shrLEN_);
        if(tmp > l_Bsz256[i])        /* to detect carry */
        {
            c_o += 1UL;
        }
    }

    return c_o;
#undef  _shrLEN_
}

static size_t addSize512(const size_t mesSize)
{
#define _shrLEN_    64UL
    size_t c_i, c_o;
    uint64_t tmp;
    size_t t_msz;

    c_i = 0UL, c_o = 0UL;
    t_msz = mesSize;

    for(size_t i = 0UL; i < SIZE2UI64LEN(sizeof(mesSize)); i++)
    {
        c_i = c_o;
        c_o = 0UL;
        tmp = l_Bsz512[i];           /* to check carry */
        l_Bsz512[0] += ((uint64_t)c_i); /* CARRY */
        if(tmp > l_Bsz512[i])        /* to detect carry */
        {
            c_o += 1UL;
        }
        tmp = l_Bsz512[i];           /* to check carry */
        l_Bsz512[0] += ((uint64_t)t_msz); /* LO_BSZ */
        t_msz = (t_msz >> _shrLEN_);
        if(tmp > l_Bsz512[i])        /* to detect carry */
        {
            c_o += 1UL;
        }
    }

    return c_o;
#undef  _shrLEN_
}

static uint32_t convSize2blen256(const uint32_t in)
{
#define _bLEN_  32U
#define _sLEN_  3U
    uint32_t   o_shl, i_shl;
    size_t sidx;

    o_shl = in;
    for(sidx = 0UL; sidx < (SHA2_BLEN_NUM); sidx++)
    {
        i_shl = o_shl;
        o_shl = SHR(((_bLEN_)-(_sLEN_)), l_Bsz256[sidx]);
        l_Bsz256[sidx] = (SHL(_sLEN_, l_Bsz256[sidx]) | i_shl);
    }

    return o_shl;
#undef _bLEN_
#undef _sLEN_
}

static uint64_t convSize2blen512(const uint64_t in)
{
#define _bLEN_  64U
#define _sLEN_  3U
    uint64_t   o_shl, i_shl;
    size_t sidx;

    o_shl = in;
    for(sidx = 0UL; sidx < (SHA2_BLEN_NUM); sidx++)
    {
        i_shl = o_shl;
        o_shl = SHR(((_bLEN_)-(_sLEN_)), l_Bsz512[sidx]);
        l_Bsz512[sidx] = (SHL(_sLEN_, l_Bsz512[sidx]) | i_shl);
    }

    return o_shl;
#undef _bLEN_
#undef _sLEN_
}

static void preProcessingHash256_0_pad(const size_t mesSize)
{
    uint8_t* blkBuf_8b = (uint8_t*)(l_W256mod16);

    for(size_t l = (mesSize); l < SHA256_BLOCK_SIZE; l++)
    {
        blkBuf_8b[EDCIDX32(size_t, l)] = 0x00U;
    }
}

static void preProcessingHash512_0_pad(const size_t mesSize)
{
    uint8_t* blkBuf_8b = (uint8_t*)(l_W512mod16);

    for(size_t l = (mesSize); l < SHA512_BLOCK_SIZE; l++)
    {
        blkBuf_8b[EDCIDX64(size_t, l)] = 0x00U;
    }
}

static size_t preProcessingHash256_endBit(const size_t loc)
{
    size_t nextLoc;
    uint8_t* blkBuf_8b = (uint8_t*)(l_W256mod16);

    /* examine that able to attach 0x80 */
    if(loc < (SHA256_BLOCK_SIZE))
    {
        blkBuf_8b[EDCIDX32(size_t, loc)] = SHA_END_BYTE;
        nextLoc = loc + 1U;
        /* Condition1: loc <= SHA2_BLOCK_SIZE */
        /* Condition2: loc == SHA2_BLOCK_SIZE */
    }
    else
    {
        /* Condition1: loc >= SHA2_BLOCK_SIZE */
        /* Condition2: loc == SHA2_BLOCK_SIZE */
        nextLoc = loc;
    }

    return nextLoc;
}

static size_t preProcessingHash512_endBit(const size_t loc)
{
    size_t nextLoc;
    uint8_t* blkBuf_8b = (uint8_t*)(l_W512mod16);

    /* examine that able to attach 0x80 */
    if(loc < (SHA512_BLOCK_SIZE))
    {
        blkBuf_8b[EDCIDX64(size_t, loc)] = SHA_END_BYTE;
        nextLoc = loc + 1U;
        /* Condition1: loc <= SHA2_BLOCK_SIZE */
        /* Condition2: loc == SHA2_BLOCK_SIZE */
    }
    else
    {
        /* Condition1: loc >= SHA2_BLOCK_SIZE */
        /* Condition2: loc == SHA2_BLOCK_SIZE */
        nextLoc = loc;
    }

    return nextLoc;
}

static size_t preProcessingHash256_bitLen(const size_t loc)
{
    size_t nextLoc;
    uint32_t* blkBuf_32b = (l_W256mod16);

    /* examine that able to attach length bytes */
    if(((loc) + (SHA256_BLEN_SIZE)) <= (SHA256_BLOCK_SIZE))
    {
        convSize2blen256(0U); /* bytes to bit length */
        blkBuf_32b[SHA2_BLOCK_NUM-2U] = (l_Bsz256)[1];
        blkBuf_32b[SHA2_BLOCK_NUM-1U] = (l_Bsz256)[0];

        nextLoc = (SHA256_BLOCK_SIZE);
    }
    else
    {
        nextLoc = 0UL;
    }

    return nextLoc;
}

static size_t preProcessingHash512_bitLen(const size_t loc)
{
    size_t nextLoc;
    uint64_t* blkBuf_64b = (l_W512mod16);

    /* examine that able to attach length bytes */
    if(((loc) + (SHA512_BLEN_SIZE)) <= (SHA512_BLOCK_SIZE))
    {
        convSize2blen512(0UL); /* bytes to bit length */
        blkBuf_64b[SHA2_BLOCK_NUM-2U] = (l_Bsz512)[1];
        blkBuf_64b[SHA2_BLOCK_NUM-1U] = (l_Bsz512)[0];

        nextLoc = (SHA512_BLOCK_SIZE);
    }
    else
    {
        nextLoc = 0UL;
    }

    return nextLoc;
}

static size_t preProcessHash256(uint32_t* hash)
{
    const size_t lstBlkSize = ((l_Bsz256[0U])&((size_t)(SHA256_BLOCK_SIZE-1U)));
    size_t pploc;   /* Pre-Processing Location(is used size) */

    /* init_W_mod16_256(...);*/ /* Already init 'mes' into 'l_W256mod16' */

    preProcessingHash256_0_pad(lstBlkSize);

    if((lstBlkSize + (SHA_END_SIZE + SHA256_BLEN_SIZE)) <= SHA256_BLOCK_SIZE)
    {
        /* Able to attach the end bit and the bit length */
        pploc = preProcessingHash256_endBit(lstBlkSize);
        pploc = preProcessingHash256_bitLen(pploc);
        // Condition(pploc == SHA256_BLOCK_SIZE)
    }
    else if((lstBlkSize + (SHA_END_SIZE)) <= SHA256_BLOCK_SIZE)
    {
        /* Able to attach end bit */
        pploc = preProcessingHash256_endBit(lstBlkSize);
        /* Condition(0 <= SHA256_BLOCK_SIZE - pploc < SHA256_BLEN_SIZE) */
        compSha256_W_mod16(hash);

        preProcessingHash256_0_pad(0UL);
        pploc = preProcessingHash256_bitLen(0UL);
        /* Condition(pploc == SHA256_BLOCK_SIZE) */
    }
    else
    {
        /*
         * A condtion of the else is (lstBlkSize > SHA256_BLOCK_SIZE)
         */
        /* Unreachable Case? */
        pploc = SIZE_MAX;
    }

    return pploc;
}

static size_t preProcessHash512(uint64_t* hash)
{
    const size_t lstBlkSize = ((l_Bsz512[0U])&((size_t)(SHA512_BLOCK_SIZE-1U)));
    size_t pploc;   /* Pre-Processing Location(is used size) */

    /* init_W_mod16_512(...);*/ /* Already init 'mes' into 'l_W512mod16' */

    preProcessingHash512_0_pad(lstBlkSize);

    if((lstBlkSize + (SHA_END_SIZE + SHA512_BLEN_SIZE)) <= SHA512_BLOCK_SIZE)
    {
        /* Able to attach the end bit and the bit length */
        pploc = preProcessingHash512_endBit(lstBlkSize);
        pploc = preProcessingHash512_bitLen(pploc);
        // Condition(pploc == SHA512_BLOCK_SIZE)
    }
    else if((lstBlkSize + (SHA_END_SIZE)) <= SHA512_BLOCK_SIZE)
    {
        /* Able to attach end bit */
        pploc = preProcessingHash512_endBit(lstBlkSize);
        /* Condition(0 <= SHA512_BLOCK_SIZE - pploc < SHA512_BLEN_SIZE) */
        compSha512_W_mod16(hash);

        preProcessingHash512_0_pad(0UL);
        pploc = preProcessingHash512_bitLen(0UL);
        /* Condition(pploc == SHA512_BLOCK_SIZE) */
    }
    else
    {
        /*
         * A condtion of the else is (lstBlkSize > SHA512_BLOCK_SIZE)
         */
        /* Unreachable Case? */
        pploc = SIZE_MAX;
    }

    return pploc;
}

static void init_W_mod16_256(const uint32_t* mes)
{
    /* Pre-Processing: Copy to 'mes' to 'l_W256mod16' */
    const size_t t0 = 0UL;
    size_t tp;  // t'(t prime = tp)

    dprintf("init W_mod16, t0 = %lu(0x%lx)\n", t0, t0);
#if 0 /* COPY_MES_TO_Wt */
    memcpy(l_W256mod16, mes, SHA256_BLOCK_SIZE);
#else
    for(tp = t0; tp < t0 + SHA2_BLOCK_NUM; tp++)
    {
        l_W256mod16[tp] = mes[tp];
    }
    for(tp = t0; tp < t0 + SHA2_BLOCK_NUM; tp++)
    {
        dprintf("[%2lu]0x%08x ", tp, l_W256mod16[MOD16(tp)]);
        if((tp != 0U) && ((tp&0x3U) == 0x03)) dprintf("\n");
    }
    dprintf("\n");
#endif/* COPY_MES_TO_Wt */
}

static void init_W_mod16_512(const uint64_t* mes)
{
    /* Pre-Processing: Copy to 'mes' to 'l_W512mod16' */
    const size_t t0 = 0UL;
    size_t tp;  // t'(t prime = tp)

    dprintf("init W_mod16, t0 = %lu(0x%lx)\n", t0, t0);
#if 0 /* COPY_MES_TO_Wt */
    memcpy(l_W512mod16, mes, SHA512_BLOCK_SIZE);
#else
    for(tp = t0; tp < t0 + SHA2_BLOCK_NUM; tp++)
    {
        l_W512mod16[tp] = mes[tp];
    }
    for(tp = t0; tp < t0 + SHA2_BLOCK_NUM; tp++)
    {
        dprintf("[%2lu]0x%016lx ", tp, l_W512mod16[MOD16(tp)]);
        if((tp != 0U) && ((tp&0x3U) == 0x03)) dprintf("\n");
    }
    dprintf("\n");
#endif/* COPY_MES_TO_Wt */
}

static void update_W_mod16_256(const size_t t)   // W_mod16(message schedule) update in t(is 0, 16, 32, 48, ...)
{
    size_t tp;  // t'(t prime = tp)

    if(((t&0xful) == 0x0ul)) // 't' >= 16U and 't' is multiple of 16U
    {
        if((t>>4ul) == 0x0ul)
        {
            /* init_W_mod16_256() already initialize 'l_W256mod16' to 'mes' */
        }
        else // if((t>>4ul) != 0x0ul)
        {
            dprintf("updates W_mod16, t = %lu(0x%lx)\n", t, t);
            for(tp = t; tp < t + SHA2_BLOCK_NUM; tp++)
            {
                l_W256mod16[MOD16(tp)] = SGM1_256(l_W256mod16[MOD16(tp -  2U)]) + l_W256mod16[MOD16(tp -  7U)] \
                                     + SGM0_256(l_W256mod16[MOD16(tp - 15U)]) + l_W256mod16[MOD16(tp - 16U)];
            }
        }
        for(tp = t; tp < t + SHA2_BLOCK_NUM; tp++)
        {
            dprintf("[%2lu]0x%08x ", tp, l_W256mod16[MOD16(tp)]);
            if((tp != 0U) && ((tp&0x3U) == 0x03)) dprintf("\n");
        }
        dprintf("\n");
    }
    else
    {
        /* Not Updates */
    }
}

static void update_W_mod16_512(const size_t t)   // W_mod16(message schedule) update in t(is 0, 16, 32, 48, ...)
{
    size_t tp;  // t'(t prime = tp)

    if(((t&0xful) == 0x0ul)) // 't' >= 16U and 't' is multiple of 16U
    {
        if((t>>4ul) == 0x0ul)
        {
            /* init_W_mod16_512() already initialize 'l_W512mod16' to 'mes' */
        }
        else // if((t>>4ul) != 0x0ul)
        {
            dprintf("updates W_mod16, t = %lu(0x%lx)\n", t, t);
            for(tp = t; tp < t + SHA2_BLOCK_NUM; tp++)
            {
                l_W512mod16[MOD16(tp)] = SGM1_512(l_W512mod16[MOD16(tp -  2U)]) + l_W512mod16[MOD16(tp -  7U)] \
                                     + SGM0_512(l_W512mod16[MOD16(tp - 15U)]) + l_W512mod16[MOD16(tp - 16U)];
            }
        }
        for(tp = t; tp < t + SHA2_BLOCK_NUM; tp++)
        {
            dprintf("[%2lu]0x%016lx ", tp, l_W512mod16[MOD16(tp)]);
            if((tp != 0U) && ((tp&0x3U) == 0x03)) dprintf("\n");
        }
        dprintf("\n");
    }
    else
    {
        /* Not Updates */
    }
}

static void compSha256_W_mod16(uint32_t* hash)
{
    uint32_t t1, t2;

    memcpy(l_Nd256, hash, sizeof(l_Nd256));
    dprintf("t=-1 %08x %08x %08x %08x %08x %08x %08x %08x \n", 
            l_Nd256[0], l_Nd256[1], l_Nd256[2], l_Nd256[3], l_Nd256[4], l_Nd256[5], l_Nd256[6], l_Nd256[7]);

    for(size_t t = 0UL; t < SHA256_ROUND_NUM; t++)
    {
        update_W_mod16_256(t);

        t1 = l_Nd256[7] + SUM1_256(l_Nd256[4]) + Ch(l_Nd256[4], l_Nd256[5], l_Nd256[6]) + ((uint32_t*)K256)[t] + l_W256mod16[MOD16(t)];
        t2 = SUM0_256(l_Nd256[0]) + Maj(l_Nd256[0], l_Nd256[1], l_Nd256[2]);
        l_Nd256[7] = l_Nd256[6];
        l_Nd256[6] = l_Nd256[5];
        l_Nd256[5] = l_Nd256[4];
        l_Nd256[4] = l_Nd256[3] + t1;
        l_Nd256[3] = l_Nd256[2];
        l_Nd256[2] = l_Nd256[1];
        l_Nd256[1] = l_Nd256[0];
        l_Nd256[0] = t1 + t2;
        dprintf("t=%2lu %08x %08x %08x %08x %08x %08x %08x %08x \n", 
                t, l_Nd256[0], l_Nd256[1], l_Nd256[2], l_Nd256[3], l_Nd256[4], l_Nd256[5], l_Nd256[6], l_Nd256[7]);
    }

    for(size_t idx = 0UL; idx < SHA2_DIGEST_NUM; idx++)
    {
        dprintf("H[%2lu]: %08x + %08x", idx, hash[idx], l_Nd256[idx]);
        hash[idx] += l_Nd256[idx];
        dprintf(" = %08x\n", hash[idx]);
    }
}

static void compSha512_W_mod16(uint64_t* hash)
{
    uint64_t t1, t2;

    memcpy(l_Nd512, hash, sizeof(l_Nd512));
    dprintf("t=-1 %016lx %016lx %016lx %016lx %016lx %016lx %016lx %016lx \n", 
            l_Nd512[0], l_Nd512[1], l_Nd512[2], l_Nd512[3], l_Nd512[4], l_Nd512[5], l_Nd512[6], l_Nd512[7]);

    for(size_t t = 0UL; t < SHA512_ROUND_NUM; t++)
    {
        update_W_mod16_512(t);

        t1 = l_Nd512[7] + SUM1_512(l_Nd512[4]) + Ch(l_Nd512[4], l_Nd512[5], l_Nd512[6]) + ((uint64_t*)K512)[t] + l_W512mod16[MOD16(t)];
        t2 = SUM0_512(l_Nd512[0]) + Maj(l_Nd512[0], l_Nd512[1], l_Nd512[2]);
        l_Nd512[7] = l_Nd512[6];
        l_Nd512[6] = l_Nd512[5];
        l_Nd512[5] = l_Nd512[4];
        l_Nd512[4] = l_Nd512[3] + t1;
        l_Nd512[3] = l_Nd512[2];
        l_Nd512[2] = l_Nd512[1];
        l_Nd512[1] = l_Nd512[0];
        l_Nd512[0] = t1 + t2;
        dprintf("t=%2lu %016lx %016lx %016lx %016lx %016lx %016lx %016lx %016lx \n", 
                t, l_Nd512[0], l_Nd512[1], l_Nd512[2], l_Nd512[3], l_Nd512[4], l_Nd512[5], l_Nd512[6], l_Nd512[7]);
    }

    for(size_t idx = 0UL; idx < SHA2_DIGEST_NUM; idx++)
    {
        dprintf("H[%2lu]: %016lx + %016lx", idx, hash[idx], l_Nd512[idx]);
        hash[idx] += l_Nd512[idx];
        dprintf(" = %016lx\n", hash[idx]);
    }
}

void startSha256(uint32_t* hash, const uint32_t* iHash, const size_t hashSize)
{
    if(hashSize == SHA256_DIGEST_SIZE)
    {
        (void)memcpy(hash, iHash, hashSize);
        (void)memset(l_Bsz256, 0x0, sizeof(l_Bsz256));
    }
}

void startSha512(uint64_t* hash, const uint64_t* iHash, const size_t hashSize)
{
    if(hashSize == SHA512_DIGEST_SIZE)
    {
        (void)memcpy(hash, iHash, hashSize);
        (void)memset(l_Bsz512, 0x0, sizeof(l_Bsz512));
    }
}

void updateSha256(uint32_t* hash, const size_t hashSize, const uint32_t* mes, const size_t mesSize)
{
    if(hashSize == SHA256_DIGEST_SIZE)
    {
        init_W_mod16_256(mes);

        /* Accumulate size of message(Bytes) */
        if(addSize256(mesSize) != 0UL)
        {
            /* Accumulated message size is overflow */
        }

        if(mesSize == SHA256_BLOCK_SIZE)
        {
            compSha256_W_mod16(hash);
        }
        else
        {
            /* init 'l_W256mod16' but not compute */
        }
    }
}

void updateSha512(uint64_t* hash, const size_t hashSize, const uint64_t* mes, const size_t mesSize)
{
    if(hashSize == SHA512_DIGEST_SIZE)
    {
        init_W_mod16_512(mes);

        /* Accumulate size of message(Bytes) */
        if(addSize512(mesSize) != 0UL)
        {
            /* Accumulated message size is overflow */
        }

        if(mesSize == SHA512_BLOCK_SIZE)
        {
            compSha512_W_mod16(hash);
        }
        else
        {
            /* init 'l_W512mod16' but not compute */
        }
    }
}

void finishSha256(uint32_t* hash, const size_t hashSize)
{
    size_t pploc;

    if(hashSize == SHA256_DIGEST_SIZE)
    {
        pploc = preProcessHash256(hash);
        if(pploc == SHA256_BLOCK_SIZE)
        {
            compSha256_W_mod16(hash);
        }
        else
        {
            /* Error Cases */
        }
    }
}

void finishSha512(uint64_t* hash, const size_t hashSize)
{
    size_t pploc;

    if(hashSize == SHA512_DIGEST_SIZE)
    {
        pploc = preProcessHash512(hash);
        if(pploc == SHA512_BLOCK_SIZE)
        {
            compSha512_W_mod16(hash);
        }
        else
        {
            /* Error Cases */
        }
    }
}

#ifdef DEBUG
void test_sha2_environments(void)
{
    /* Rotation Right Test */
    {
        dprintf("--------------------------------------------------------------------------------\n");

        uint32_t rotr = 0x00000001U;
        uint32_t rotl = 0x00000001U;

        for(size_t i = 0U; i <= 32U; i++)
        {
            dprintf("rotr(%02lu, 0x%08x) = 0x%08x\n", i, rotr, ROTR(32U, i, rotr));
        }
        dprintf("\n");
        for(size_t i = 0U; i <= 32U; i++)
        {
            dprintf("rotl(%02lu, 0x%08x) = 0x%08x\n", i, rotl, ROTL(32U, i, rotl));
        }
        dprintf("\n");

        dprintf("================================================================================\n");
    }
    /* Endian Value Convert Test */
    {
        dprintf("--------------------------------------------------------------------------------\n");

        uint32_t ui32_symbol = 0x428a2f98u;
        uint8_t ui8_arr_4B[] = { 0x42u, 0x8au, 0x2fu, 0x98u };
        uint32_t ui32_endian = EDCVAL32(*((uint32_t*)ui8_arr_4B));

        dprintf("32bit symbol = 0x%08x\n", ui32_symbol);
        dprintf("4 Byte Array = 0x%02x%02x%02x%02x\n", 
                ui8_arr_4B[0], ui8_arr_4B[1], 
                ui8_arr_4B[2], ui8_arr_4B[3]
        );
        dprintf("4Byte->32bit = 0x%08x\n", *((uint32_t*)ui8_arr_4B));
        dprintf("4Byte->BigEd = 0x%08x\n", ui32_endian);
        dprintf("\n");

        dprintf("================================================================================\n");
    }
    /* Endian Index Convert Test */
    {
        dprintf("--------------------------------------------------------------------------------\n");

        dprintf("MACRO EDCIDX32() TEST\n");
        for(size_t idx = 0UL; idx < SHA256_BLOCK_SIZE; idx++)
        {
            dprintf("%2lu -> %2lu, ", idx, EDCIDX32(size_t, idx));
            if((idx != 0U) && ((idx&0x3U) == 0x03)) dprintf("\n");
        }
        dprintf("\n");

        dprintf("================================================================================\n");
    }

    /* Endian Value Convert Test */
    {
        dprintf("--------------------------------------------------------------------------------\n");

        uint64_t ui64_symbol = 0x428a2f981234abcdu;
        uint8_t ui8_arr_8B[] = { 0x42u, 0x8au, 0x2fu, 0x98u, 0x12u, 0x34u, 0xabu, 0xcdu, };
        uint64_t ui64_endian = EDCVAL64(*((uint64_t*)ui8_arr_8B));

        dprintf("64bit symbol = 0x%016lx\n", ui64_symbol);
        dprintf("8 Byte Array = 0x%02x%02x%02x%02x%02x%02x%02x%02x\n", 
                ui8_arr_8B[0], ui8_arr_8B[1], ui8_arr_8B[2], ui8_arr_8B[3], 
                ui8_arr_8B[4], ui8_arr_8B[5], ui8_arr_8B[6], ui8_arr_8B[7]
        );
        dprintf("8Byte->64bit = 0x%016lx\n", *((uint64_t*)ui8_arr_8B));
        dprintf("8Byte->BigEd = 0x%016lx\n", ui64_endian);
        dprintf("\n");

        dprintf("================================================================================\n");
    }
    /* Endian Index Convert Test */
    {
        dprintf("--------------------------------------------------------------------------------\n");

        dprintf("MACRO EDCIDX64() TEST\n");
        for(size_t idx = 0UL; idx < SHA512_BLOCK_SIZE; idx++)
        {
            dprintf("%2lu -> %2lu, ", idx, EDCIDX64(size_t, idx));
            if((idx != 0U) && ((idx&0x7U) == 0x07)) dprintf("\n");
        }
        dprintf("\n");

        dprintf("================================================================================\n");
    }
    /* Print init Hash and Const Value for SHA256 */
    {
        printf("--------------------------------------------------------------------------------\n");

        for(size_t i = 0; i < sizeof(H0_224)/sizeof(uint32_t); i++)
        {
            printf("H0_224[%2lu] = 0x%08x ", i, ((uint32_t*)H0_224)[i]);
            if((i != 0U) && ((i&0x3U) == 0x03)) printf("\n");
        }
        printf("\n");
        for(size_t i = 0; i < sizeof(H0_256)/sizeof(uint32_t); i++)
        {
            printf("H0_256[%2lu] = 0x%08x ", i, ((uint32_t*)H0_256)[i]);
            if((i != 0U) && ((i&0x3U) == 0x03)) printf("\n");
        }
        printf("\n");

        for(size_t i = 0; i < sizeof(K256)/sizeof(uint32_t); i++)
        {
            printf("K[%2lu] = 0x%08x ", i, ((uint32_t*)K256)[i]);
            if((i != 0U) && ((i&0x3U) == 0x03)) printf("\n");
        }
        printf("\n");

        printf("================================================================================\n");
    }
    /* Print init Hash and Const Value for SHA512 */
    {
        printf("--------------------------------------------------------------------------------\n");

        for(size_t i = 0; i < sizeof(H0_384)/sizeof(uint64_t); i++)
        {
            printf("H0_384[%2lu] = 0x%016lx ", i, ((uint64_t*)H0_384)[i]);
            if((i != 0U) && ((i&0x3U) == 0x03)) printf("\n");
        }
        printf("\n");
        for(size_t i = 0; i < sizeof(H0_512)/sizeof(uint64_t); i++)
        {
            printf("H0_512[%2lu] = 0x%016lx ", i, ((uint64_t*)H0_512)[i]);
            if((i != 0U) && ((i&0x3U) == 0x03)) printf("\n");
        }
        printf("\n");
        for(size_t i = 0; i < sizeof(H0_512_224)/sizeof(uint64_t); i++)
        {
            printf("H0_512_224[%2lu] = 0x%016lx ", i, ((uint64_t*)H0_512_224)[i]);
            if((i != 0U) && ((i&0x3U) == 0x03)) printf("\n");
        }
        printf("\n");
        for(size_t i = 0; i < sizeof(H0_512_256)/sizeof(uint64_t); i++)
        {
            printf("H0_512_256[%2lu] = 0x%016lx ", i, ((uint64_t*)H0_512_256)[i]);
            if((i != 0U) && ((i&0x3U) == 0x03)) printf("\n");
        }
        printf("\n");

        for(size_t i = 0; i < sizeof(K512)/sizeof(uint64_t); i++)
        {
            printf("K[%2lu] = 0x%016lx ", i, ((uint64_t*)K512)[i]);
            if((i != 0U) && ((i&0x3U) == 0x03)) printf("\n");
        }
        printf("\n");

        printf("================================================================================\n");
    }
}
#endif /* DEBUG */
