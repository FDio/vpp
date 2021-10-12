#!/usr/bin/env bash

FLAGS="-g -O3 -Isrc"

gcc-11 ${FLAGS} -march=haswell -DVER=hsw  -c -o memcpy_bench_hsw.o  memcpy_bench.c
gcc-11 ${FLAGS} -march=tremont -DVER=trm  -c -o memcpy_bench_trm.o  memcpy_bench.c
gcc-11 ${FLAGS} -march=skylake-avx512 -mprefer-vector-width=256 -DVER=skx -c -o memcpy_bench_skx.o  memcpy_bench.c
gcc-11 ${FLAGS} -march=icelake-server -mprefer-vector-width=512 -DVER=icx -c -o memcpy_bench_icx.o  memcpy_bench.c

gcc-11 ${FLAGS} \
  -march=icelake-server \
  -o memcpy_bench \
  memcpy_bench.c \
  memcpy_bench_hsw.o \
  memcpy_bench_skx.o \
  memcpy_bench_icx.o \
  memcpy_bench_trm.o

