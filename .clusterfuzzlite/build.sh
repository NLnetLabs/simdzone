#!/bin/bash -eu
mkdir build
cd build
cmake ..
make

# Copy all fuzzer executables to $OUT/
$CC $CFLAGS $LIB_FUZZING_ENGINE \
  $SRC/simdzone/.clusterfuzzlite/zone_parse_string_fuzzer.c \
  -o $OUT/zone_parse_string_fuzzer \
  -I$SRC/simdzone/include \
  -I$SRC/simdzone/build/include \
  $SRC/simdzone/build/libzone.a
