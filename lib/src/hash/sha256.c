#ifdef DEBUG
#include <stdio.h>
#define dprintf(...)    printf(__VA_ARGS__)
#else
#define dprintf(...)
#endif /* DEBUG */
#include <stdlib.h> // defines 'LITTLE_ENDIAN'
#include <stdint.h>
#include <string.h>

#include "hash/sha256.h"

#define SHA256_BLEN_SIZE    8U  // bytes
#define SHA_END_SIZE        1U
#define SHA_END_BYTE        0x80U

#define ROTL(wBit, nBit, X) (((X)<<(nBit)) | (X)>>(wBit-nBit))
#define ROTR(wBit, nBit, X) (((X)>>(nBit)) | (X)<<(wBit-nBit))
#define SHR(nBit, X)        ((X)>>(nBit))

/* SHA1, SHA2 used */
#define Ch(X,Y,Z)           (((X)&(Y))^((~(X))&(Z)))
#define Maj(X,Y,Z)          (((X)&(Y))^((X)&(Z))^((Y)&(Z)))

/* SHA256, SUM, SGM(SIGMA) used */
#define SUM0_256(X)         (ROTR(32U,  2U, X) ^ ROTR(32U, 13U, X) ^ ROTR(32U, 22U, X))
#define SUM1_256(X)         (ROTR(32U,  6U, X) ^ ROTR(32U, 11U, X) ^ ROTR(32U, 25U, X))
#define SGM0_256(X)         (ROTR(32U,  7U, X) ^ ROTR(32U, 18U, X) ^  SHR(      3U, X))
#define SGM1_256(X)         (ROTR(32U, 17U, X) ^ ROTR(32U, 19U, X) ^  SHR(     10U, X))

#define MOD16(X)            ((X)&0xfU)

#if defined(LITTLE_ENDIAN)
#define EDCVAL32(X32) \
    ( (((X32)&0x000000ffU)<<24U)|(((X32)&0xff000000U)>>24U) \
     |(((X32)&0x0000ff00U)<< 8U)|(((X32)&0x00ff0000U)>> 8U) )
#define EDCIDX32(TYPE, IDX) (((IDX)&(~((TYPE)0x3U)))|(((TYPE)0x3U)-((IDX)&((TYPE)0x3U))))
#define EDCVAL64(X64) \
    ( (((X64)&0x00000000000000ffUL)<<56UL)|(((X64)&0xff00000000000000UL)>>56UL) \
     |(((X64)&0x000000000000ff00UL)<<40UL)|(((X64)&0x00ff000000000000UL)>>40UL) \
     |(((X64)&0x0000000000ff0000UL)<<24UL)|(((X64)&0x0000ff0000000000UL)>>24UL) \
     |(((X64)&0x00000000ff000000UL)<< 8UL)|(((X64)&0x000000ff00000000UL)>> 8UL))
#define EDCIDX64(TYPE, IDX) (((IDX)&(~((TYPE)0x7U)))|(((TYPE)0x7U)-((IDX)&((TYPE)0x7U))))
#define EDCBLEN64(L64)      ((((L64)&0x00000000ffffffffUL)<<32UL)|(((L64)&0xffffffff00000000UL)>>32UL))
#else
#define EDCVAL32(X32)
#define EDCIDX32(TYPE, IDX) (IDX)
#define EDCVAL64(X64)
#define EDCIDX64(TYPE, IDX) (IDX)
#define EDCBLEN64(L64)
#endif

const uint32_t H0_256[SHA256_DIGEST_NUM] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au, 
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u, 
};

const uint32_t K256[SHA256_ROUND_NUM] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u, 
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u, 
};

/* Internal Variavbles */
static uint32_t l_Wmod16[SHA256_BLOCK_NUM]; // message schedule(64Bytes), length was modulo 16
static uint32_t l_Nd[SHA256_DIGEST_NUM];    // Nd[0]:a, Nd[1]:b, ... Nd[7]:h
static uint64_t l_Bsz;                      // Accumulated Byte Length

/* Internal Functions */
static void preProcessingHash256_0_pad(const size_t mesSize);
static size_t preProcessingHash256_endBit(const size_t loc);
static size_t preProcessingHash256_bitLen(const size_t loc);
static size_t preProcessHash256(uint32_t* hash);

static void init_W_mod16_256(const uint32_t* mes);
static void update_W_mod16_256(const size_t t);

static void compSha256_W_mod16(uint32_t* hash);

/* Implements Functions */
void conv32bitEndian(uint32_t* dst, const uint32_t* src, const size_t size)
{
    if((size & 0x7UL) == 0UL)
    {
        for(size_t i = 0UL; i < SIZE2LEN256(size); i++)
        {
            dst[i] = EDCVAL32(src[i]);
        }
    }
    else
    {
        // align error
    }
}

static void preProcessingHash256_0_pad(const size_t mesSize)
{
    uint8_t* blkBuf_8b = (uint8_t*)l_Wmod16;

    for(size_t l = mesSize; l < SHA256_BLOCK_SIZE; l++)
    {
        blkBuf_8b[EDCIDX32(size_t, l)] = 0x00U;
    }
}

static size_t preProcessingHash256_endBit(const size_t loc)
{
    size_t nextLoc;
    uint8_t* blkBuf_8b = (uint8_t*)l_Wmod16;

    // examine that able to attach 0x80
    if(loc < SHA256_BLOCK_SIZE)
    {

#if 0 /* BIG_ENDIAN */
        blkBuf_32b[loc] = SHA_END_BYTE;
#endif/* BIG_ENDIAN */
        blkBuf_8b[EDCIDX32(size_t, loc)] = SHA_END_BYTE;
        nextLoc = loc + 1UL;
        /* Condition1: loc <= SHA256_BLOCK_SIZE */
        /* Condition2: loc == SHA256_BLOCK_SIZE */
    }
    else
    {
        /* Condition1: loc >= SHA256_BLOCK_SIZE */
        /* Condition2: loc == SHA256_BLOCK_SIZE */
        nextLoc = loc;
    }

    return nextLoc;
}

static size_t preProcessingHash256_bitLen(const size_t loc)
{
    size_t nextLoc;
    uint64_t blen;
    uint8_t* blkBuf_8b = (uint8_t*)l_Wmod16;

    // examine that able to attach length bytes
    if((loc + SHA256_BLEN_SIZE) <= SHA256_BLOCK_SIZE)
    {
        blen = ((uint64_t)l_Bsz << 3UL);  // bytes to bit length
        dprintf("(64b)blen=0x%016lx\n", blen);
        blen = EDCBLEN64(blen);
        dprintf("(64b)EDCBLEN64(blen)=0x%016lx\n", blen);
        memcpy((&blkBuf_8b[SHA256_BLOCK_SIZE-SHA256_BLEN_SIZE]), (&blen), SHA256_BLEN_SIZE);

        nextLoc = SHA256_BLOCK_SIZE;
    }
    else
    {
        nextLoc = 0UL;
    }

    return nextLoc;
}

static size_t preProcessHash256(uint32_t* hash)
{
#define __SHA256_BYTE_SIZE_MASK__           ((uint64_t)(SHA256_BLOCK_SIZE-1U))
#define __SHA256_ABSTRACT_LAST_SIZE__(SIZE) ((SIZE)&__SHA256_BYTE_SIZE_MASK__)
    const uint64_t lstBlkSize = __SHA256_ABSTRACT_LAST_SIZE__(l_Bsz);
    size_t pploc;   // Pre-Processing Location(is used size)

    //init_W_mod16_256(...); // Already init 'mes' into 'l_Wmod16'

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
        // Condition(0 <= SHA256_BLOCK_SIZE - pploc < SHA256_BLEN_SIZE)
        compSha256_W_mod16(hash);

        preProcessingHash256_0_pad(0UL);
        pploc = preProcessingHash256_bitLen(0UL);
        // Condition(pploc == SHA256_BLOCK_SIZE)
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
#undef __SHA256_ABSTRACT_LAST_SIZE__
#undef __SHA256_BYTE_SIZE_MASK__
}

static void init_W_mod16_256(const uint32_t* mes)
{
    /* Pre-Processing: Copy to 'mes' to 'l_Wmod16' */
    const size_t t0 = 0UL;
    size_t tp;  // t'(t prime = tp)

    dprintf("init W_mod16, t0 = %lu(0x%lx)\n", t0, t0);
#if 0 /* COPY_MES_TO_Wt */
    memcpy(l_Wmod16, mes, SHA256_BLOCK_SIZE);
#else
    for(tp = t0; tp < t0 + SHA256_BLOCK_NUM; tp++)
    {
        l_Wmod16[tp] = mes[tp];
    }
    for(tp = t0; tp < t0 + SHA256_BLOCK_NUM; tp++)
    {
        dprintf("[%2lu]0x%08x ", tp, l_Wmod16[MOD16(tp)]);
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
            /* init_W_mod16_256() already initialize 'l_Wmod16' to 'mes' */
        }
        else // if((t>>4ul) != 0x0ul)
        {
            dprintf("updates W_mod16, t = %lu(0x%lx)\n", t, t);
            for(tp = t; tp < t + SHA256_BLOCK_NUM; tp++)
            {
                l_Wmod16[MOD16(tp)] = SGM1_256(l_Wmod16[MOD16(tp -  2U)]) + l_Wmod16[MOD16(tp -  7U)] \
                                     + SGM0_256(l_Wmod16[MOD16(tp - 15U)]) + l_Wmod16[MOD16(tp - 16U)];
            }
        }
        for(tp = t; tp < t + SHA256_BLOCK_NUM; tp++)
        {
            dprintf("[%2lu]0x%08x ", tp, l_Wmod16[MOD16(tp)]);
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

    memcpy(l_Nd, hash, sizeof(l_Nd));
    dprintf("t=-1 %08x %08x %08x %08x %08x %08x %08x %08x \n", 
            l_Nd[0], l_Nd[1], l_Nd[2], l_Nd[3], l_Nd[4], l_Nd[5], l_Nd[6], l_Nd[7]);

    for(size_t t = 0UL; t < SHA256_ROUND_NUM; t++)
    {
        update_W_mod16_256(t);

        t1 = l_Nd[7] + SUM1_256(l_Nd[4]) + Ch(l_Nd[4], l_Nd[5], l_Nd[6]) + ((uint32_t*)K256)[t] + l_Wmod16[MOD16(t)];
        t2 = SUM0_256(l_Nd[0]) + Maj(l_Nd[0], l_Nd[1], l_Nd[2]);
        l_Nd[7] = l_Nd[6];
        l_Nd[6] = l_Nd[5];
        l_Nd[5] = l_Nd[4];
        l_Nd[4] = l_Nd[3] + t1;
        l_Nd[3] = l_Nd[2];
        l_Nd[2] = l_Nd[1];
        l_Nd[1] = l_Nd[0];
        l_Nd[0] = t1 + t2;
        dprintf("t=%2lu %08x %08x %08x %08x %08x %08x %08x %08x \n", 
                t, l_Nd[0], l_Nd[1], l_Nd[2], l_Nd[3], l_Nd[4], l_Nd[5], l_Nd[6], l_Nd[7]);
    }

    for(size_t idx = 0UL; idx < SHA256_DIGEST_NUM; idx++)
    {
        dprintf("H[%2lu]: %08x + %08x", idx, hash[idx], l_Nd[idx]);
        hash[idx] += l_Nd[idx];
        dprintf(" = %08x\n", hash[idx]);
    }
}

void startSha256(uint32_t* hash, const uint32_t* iHash, const size_t hashSize)
{
    if(hashSize == SHA256_DIGEST_SIZE)
    {
        (void)memcpy(hash, iHash, hashSize);
        l_Bsz = 0UL;
    }
}

void updateSha256(uint32_t* hash, const size_t hashSize, const uint32_t* mes, const size_t mesSize)
{
    if(hashSize == SHA256_DIGEST_SIZE)
    {
        init_W_mod16_256(mes);

        /* Accumulate size of message(Bytes) */
        l_Bsz += mesSize;

        if(mesSize == SHA256_BLOCK_SIZE)
        {
            compSha256_W_mod16(hash);
        }
        else
        {
            /* init 'l_Wmod16' but not compute */
        }
    }
}

void finishSha256(uint32_t* hash, const uint32_t hashSize)
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

#ifdef DEBUG
void testSha256_environments(void)
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
        dprintf("4 Byte Array = 0x%02x%02x%02x%02x\n", ui8_arr_4B[0], ui8_arr_4B[1], ui8_arr_4B[2], ui8_arr_4B[3]);
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
}
#endif /* DEBUG */
