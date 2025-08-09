#ifndef RETURN_TYPE_H
#define RETURN_TYPE_H
typedef enum {
    E_OK,
    E_NOT_OK,
    E_ERROR_ARGS,
    E_ERROR_NULL,
    E_ERROR_RUNTIME,
    E_NOT_IMPL,
} ReturnType;

void printReturnType(ReturnType T);
#endif
