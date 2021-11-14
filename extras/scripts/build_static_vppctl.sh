#/bin/env bash

src=$(realpath $(dirname $0)/../..)/src

${CC:-cc} \
 -O2 \
 -flto \
 -static \
 -I ${src} \
 -g \
 ${src}/vpp/app/vppctl.c \
 -o vppctl

