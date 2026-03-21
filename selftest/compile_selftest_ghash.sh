#!/bin/bash
ROOT=..
OUTFILE="gf128"
rm ./$OUTFILE
gcc $ROOT/lib/src/ghash/gf128.c \
    $ROOT/lib/src/common/bitwise.c \
    -o $OUTFILE -I$ROOT/lib/include/ -DSELFTEST
