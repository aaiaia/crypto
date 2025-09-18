#include <stdio.h>
#include <stdint.h>

#include "common/returnType.h"

static const const char* ReturnName[] = {
    "E_OK",
    "E_NOT_OK",
    "E_ERROR_ARGS",
    "E_ERROR_NULL",
    "E_ERROR_RUNTIME",
    "E_ERROR_DIVIDE_ZERO",
    "E_ERROR_BIGNUM_LENGTH",
    "E_ERROR_BIGNUM_SIGN",
    "E_ERROR_BIGNUM_LOSS",
    "E_HAS_NO_VALUE",
    "E_NOT_IMPL",
    NULL,
};

void printReturnType(ReturnType T) {
    printf("Code: %d, Error:%s\r\n", T, ReturnName[(unsigned int)T]);
}
