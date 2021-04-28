#/bin/env bash

src=$(realpath $(dirname $0)/../..)/src

${CC:-cc} \
 -O2 \
 -flto \
 -static \
 -I ${src} \
 ${src}/vppinfra/backtrace.c \
 ${src}/vppinfra/dlmalloc.c \
 ${src}/vppinfra/elf.c \
 ${src}/vppinfra/elf_clib.c \
 ${src}/vppinfra/error.c \
 ${src}/vppinfra/format.c \
 ${src}/vppinfra/hash.c \
 ${src}/vppinfra/mem.c \
 ${src}/vppinfra/mem_dlmalloc.c \
 ${src}/vppinfra/std-formats.c \
 ${src}/vppinfra/string.c \
 ${src}/vppinfra/socket.c \
 ${src}/vppinfra/vec.c \
 ${src}/vppinfra/unformat.c \
 ${src}/vppinfra/unix-misc.c \
 ${src}/vppinfra/linux/mem.c \
 ${src}/vpp/app/vppctl.c \
 -o vppctl
