#/bin/env bash
set -eu

src=$(realpath $(dirname $0)/../..)/src

${CC:-cc} \
 -Wall \
 -Werror \
 -O2 \
 -flto \
 -static \
 -D STATIC_VPPCTL \
 -I ${src} \
 -g \
 ${src}/vpp/app/vppctl.c \
 -o vppctl

