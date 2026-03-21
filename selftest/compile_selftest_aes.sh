#!/bin/bash
ROOT=..
OUTFILE="aes"
rm ./$OUTFILE
gcc $ROOT/lib/src/aes/aes.c \
    -o $OUTFILE -I$ROOT/lib/include/ -DSELFTEST
