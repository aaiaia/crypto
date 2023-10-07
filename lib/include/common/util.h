#define UIN_CEIL(n, m)    ((n/m)+(((n%m)!=0u)?(1u):(0u)))
#define INT_CEIL(n, m)    ((n/m)+(((n%m)!=0)?(1):(0)))
#define BIN_CEIL(n, m)    ((n>>(m>>1u))+(((n&(m-1u))!=0u)?(1u):(0u)))
