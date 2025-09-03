#ifndef RETURN_TYPE_H
#define RETURN_TYPE_H
typedef enum {
    E_OK,
    E_NOT_OK,
    E_ERROR_ARGS,
    E_ERROR_NULL,
    E_ERROR_RUNTIME,
    E_ERROR_DIVIDE_ZERO,
    E_ERROR_BIGNUM_SIGN,
    E_ERROR_BIGNUM_LOSS,
    E_NOT_IMPL,
} ReturnType;

void printReturnType(ReturnType T);
#endif
