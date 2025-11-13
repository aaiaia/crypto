#include <stdint.h>
#include <stdbool.h>

#include "test/test_tool.h"

void test_print_bignum_ext(const bignum_s* p, const char* title, \
        const char* funcName, const int lineNum, \
        const bool linefeed, const size_t lfn, const bool details, const bool prefix, const bool space)
{
    if(title != NULL)   printf("[%s]\r\n", title);
    if(funcName != NULL)
    {
        printf("@%s():%d\r\n", funcName, lineNum);
    }
    if(details)
    {
        printf("addr:0x%p, bignum_t size:%lu\r\n", p, sizeof(bignum_t));
        printf("p->nums:0x%p, p->lmsk:0x%x\r\np->bits=%ld, p->nlen=%ld, p->size=%ld\r\n", \
                p->nums, p->lmsk, p->bits, p->nlen, p->size);
        printf("[HEX]\r\n");
    }
    test_print_bignum_array_ext(p->nums, p->nlen, linefeed, lfn, prefix, space);
}

void test_print_bignum_sign_ext(const bignum_sign_e sign, const bool lf)
{
    printf("bignum sign: ");
    switch(sign)
    {
        case BIGNUM_SIGN_NU:    // Not Used(Reserved)
            printf("BIGNUM_SIGN_NU");
            break;
        case BIGNUM_SIGN_POS:   // POSitive
            printf("BIGNUM_SIGN_POS");
            break;
        case BIGNUM_SIGN_NEG:   // NEGative
            printf("BIGNUM_SIGN_NEG");
            break;
        case BIGNUM_SIGN_ERR:   // ERRor
            printf("BIGNUM_SIGN_ERR");
            break;

        default:
            printf("enum case is wrong!!!");
            break;
    }
    if(lf)  printf("\n");
}

void test_print_bignum_cmp_ext(const bignum_cmp_e cmp, const bool lf)
{
    printf("bignum cmp: ");
    switch(cmp)
    {
        case BIGNUM_CMP_NU: // Not Used(Reserved)
            printf("BIGNUM_CMP_NU");
            break;
        case BIGNUM_CMP_NZ: // Not Zero
            printf("BIGNUM_CMP_NZ");
            break;
        case BIGNUM_CMP_ZO: // ZerO
            printf("BIGNUM_CMP_ZO");
            break;
        case BIGNUM_CMP_EQ: // EQual
            printf("BIGNUM_CMP_EQ");
            break;
        case BIGNUM_CMP_GT: // Greater Than
            printf("BIGNUM_CMP_GT");
            break;
        case BIGNUM_CMP_LT: // Less Than
            printf("BIGNUM_CMP_LT");
            break;
        case BIGNUM_CMP_ER: // ERror
            printf("BIGNUM_CMP_ER");
            break;

        default:
            printf("enum case is wrong!!!");
            break;
    }
    if(lf)  printf("\n");
}

void test_print_wNAF_ext(const wnaf_s* p, const char* title, const bool linefeed, const bool detail) {
    if(!(p != NULL))    return; // NULL

    if(title != NULL)   printf("[%s]\r\n", title);
    if(detail) {
        printf("uwnaf: %lu Bytes (%lu bits), swnaf: %lu Bytes (%lu bits)\r\n", \
                sizeof(uwnaf), (sizeof(uwnaf)*8UL), sizeof(swnaf), (sizeof(swnaf)*8UL));
        printf("window length = %u\r\n",    p->window);
        printf("signMsk:0x%02x, ",          p->signMsk);
        printf("signExt:0x%02x, ",          p->signExt);
        printf("wNafMsk:0x%02x\r\n",        p->wNafMsk);
    }

    printf("{");
    for(size_t i = (p->bits-1U); i < SIZE_MAX; i--)
    {
        printf("%d,", p->wnaf.si[i]);
    }
    printf("}[%lu bits][valid bit length: %lu]", p->bits, p->vLen);
    if(linefeed)    printf("\r\n");
}

void test_print_wNAF_PreCompute_ext(const wnaf_pre_compute_ec_s* p, const char* title, const bool linefeed, const bool detail) {
    if(title != NULL)   printf("[%s]\r\n", title);
    if(detail) {
        printf("window = %u\r\n", p->w);
        printf("length = %u\r\n", p->l);
    }
    for(uwnaf i = 0U; i < p->l; i++)
    {
        printf("[%uP]\r\n", ((i<<1U)+1U));
        test_print_bignum(p->x[i], NULL);
        test_print_bignum(p->y[i], NULL);
    }
}
