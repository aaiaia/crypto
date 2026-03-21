#!/bin/bash
ROOT=..
OUTFILE="aead_cal_aes_gcm"
rm ./$OUTFILE
gcc $ROOT/lib/src/common/bitwise.c     \
    $ROOT/lib/src/ghash/gf128.c        \
    $ROOT/lib/src/aes/aes.c            \
    $ROOT/lib/src/aead/cal_aes_gcm.c   \
    -o $OUTFILE -I$ROOT/lib/include/ -DSELFTEST_AEAD
