#include <stdio.h>
#include <stdint.h>

#include "common/returnType.h"

static char* const ReturnName0 = "E_OK";
static char* const ReturnName1 = "E_NOT_OK";
static char* const ReturnName2 = "E_ERROR_ARGS";
static char* const ReturnName3 = "E_ERROR_NULL";
static char* const ReturnName4 = "E_ERROR_RUNTIME";
static char* const ReturnName5 = "E_ERROR_DIVIDE_ZERO";
static char* const ReturnName6 = "E_ERROR_BIGNUM_SIGN";
static char* const ReturnName7 = "E_ERROR_BIGNUM_LOSS";
static char* const ReturnName8 = "E_NOT_IMPL";

static const const char* ReturnName[] = {
    ReturnName0,
    ReturnName1,
    ReturnName2,
    ReturnName3,
    ReturnName4,
    ReturnName5,
    ReturnName6,
    ReturnName7,
    ReturnName8,
    NULL,
};

void printReturnType(ReturnType T) {
    printf("Code: %d, Error:%s\r\n", T, ReturnName[(unsigned int)T]);
}
