/*
 * $gcc test_mont_with_omp.c -lm -Wall -fopenmp
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h> // rand

#include <time.h>

#include <omp.h>

#define MONT_BASE_BITS  6
#define MONT_BASE_MASK  0x3F
#define MONT_BASE_NUM   4
#define MONT_REDU_BITS  24
#define MONT_MOULUS     0xFFFFFF
#define MONT_OP_X_MAX   0xFFFFFF
#define MONT_OP_Y_MAX   0xFFFFFF
void main(void)
{
    const uint8_t n = MONT_BASE_NUM;
    const uint64_t M = MONT_MOULUS;
    uint32_t x;
    uint32_t y;
    uint64_t A;
    uint8_t ui;
    uint64_t nD;
    uint64_t mD;
    uint64_t T;

    nD = 0;
    srand(time(NULL));
    uint64_t sum = 0;
    uint32_t rcnt = 0;

    int tid;
#pragma omp parallel private(tid) firstprivate(x) private(y, T, nD, ui, A, mD, rcnt)
{
    tid = omp_get_thread_num();
    //printf("thread#%d is work\r\n", tid);
    #pragma omp for reduction(+:sum)
    for(x = 0; x != MONT_OP_X_MAX; x++)
    {
        //#pragma omp critical
        //printf("thread#%d start x:0x%x\r\n", tid, x);

        rcnt = 0;
        for(y = 0; y != MONT_OP_Y_MAX; y++)
        {
            T = (uint64_t)x * (uint64_t)y;
            nD = (T % M);

            A = T;
            for(uint8_t i = 0; i < n; i++)
            {
                ui = (uint8_t)(MONT_BASE_MASK& A);
                A += ((uint64_t)ui * M);
                A = (A >> MONT_BASE_BITS);
            }
            if(A >= M)    A -= M;

            mD = (A << MONT_REDU_BITS) % M;
            if(nD == mD)
            {
#if 0
                printf("T:0x %016lx mod 0x %08lx = 0x %08lx", T, M, nD);
                printf(" == ");
                printf("A:0x %016lx mod 0x %08lx = 0x %08lx", A, M, mD);
                printf(" : PASS\r\n");
#endif
            }
            else
            {
                printf("T:0x %016lx mod 0x %08lx = 0x %08lx", T, M, nD);
                printf(" != ");
                printf("A:0x %016lx mod 0x %08lx = 0x %08lx", A, M, mD);
                printf(" : FAIL\r\n"); break;
            }
            rcnt++;
        }
        sum+=rcnt;
        for(uint8_t tab = 0; tab < tid; tab++)
            printf("\t\t");
        printf("#%d: %lx\r\n", tid, sum);

    }
}
    if(sum%(MONT_OP_Y_MAX-1))  printf("##: %lx\r\n", sum);

}