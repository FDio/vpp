#/bin/env bash
set -eu

src=$(realpath $(dirname $0)/../..)/src

mkdir -p "${TMP_DIR}"
touch "${EMPTY_CFG}"

${CC:-cc} \
 -Wall \
 -Werror \
 -O2 \
 -flto \
 -static \
 -D STATIC_VPPCTL \
 -I ${src} \
 -I "${TMP_DIR_ROOT}" \
 -g \
 ${src}/vpp/app/vppctl.c \
 -o vppctl

