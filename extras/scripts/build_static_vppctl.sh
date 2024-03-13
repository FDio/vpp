#/bin/env bash
set -eu

src=$(realpath $(dirname $0)/../..)/src


# Change-id I58e1ae1c91f4a62e80eaf4e16e9932d8bab17c74 introduced the usage of config.h
# which we do not have here. Make an empty one.
TMP_DIR_ROOT="/tmp/static_vppctl_build"
TMP_DIR="${TMP_DIR_ROOT}/vpp/vnet/"
EMPTY_CFG="${TMP_DIR}/config.h"

mkdir -p "${TMP_DIR}"
touch "${EMPTY_CFG}"

${CC:-cc} \
 -Wall \
 -Werror \
 -O2 \
 -flto \
 -static \
 -I ${src} \
 -I "${TMP_DIR_ROOT}" \
 -g \
 ${src}/vpp/app/vppctl.c \
 -o vppctl

rm -rf "${TMP_DIR_ROOT}"

