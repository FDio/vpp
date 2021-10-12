#!/usr/bin/env bash

FLAGS="-g -O3 -Isrc -fPIE"

gcc-11 ${FLAGS} -march=haswell -DVER=hsw_gcc  -c -o memcpy_bench_hsw_gcc.o  memcpy_bench.c
gcc-11 ${FLAGS} -march=tremont -DVER=trm_gcc  -c -o memcpy_bench_trm_gcc.o  memcpy_bench.c
gcc-11 ${FLAGS} -march=skylake-avx512 -mprefer-vector-width=256 -DVER=skx_gcc -c -o memcpy_bench_skx_gcc.o  memcpy_bench.c
gcc-11 ${FLAGS} -march=icelake-server -mprefer-vector-width=512 -DVER=icx_gcc -c -o memcpy_bench_icx_gcc.o  memcpy_bench.c

clang-13 ${FLAGS} -march=haswell -DVER=hsw_clang  -c -o memcpy_bench_hsw_clang.o  memcpy_bench.c
clang-13 ${FLAGS} -march=tremont -DVER=trm_clang  -c -o memcpy_bench_trm_clang.o  memcpy_bench.c
clang-13 ${FLAGS} -march=skylake-avx512 -mprefer-vector-width=256 -DVER=skx_clang -c -o memcpy_bench_skx_clang.o  memcpy_bench.c
clang-13 ${FLAGS} -march=icelake-server -mprefer-vector-width=512 -DVER=icx_clang -c -o memcpy_bench_icx_clang.o  memcpy_bench.c

gcc-11 ${FLAGS} \
  -march=icelake-server \
  -o memcpy_bench \
  memcpy_bench.c \
  memcpy_bench_hsw_clang.o \
  memcpy_bench_skx_clang.o \
  memcpy_bench_icx_clang.o \
  memcpy_bench_trm_clang.o \
  memcpy_bench_hsw_gcc.o \
  memcpy_bench_skx_gcc.o \
  memcpy_bench_icx_gcc.o \
  memcpy_bench_trm_gcc.o

