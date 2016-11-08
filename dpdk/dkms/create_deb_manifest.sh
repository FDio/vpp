#!/bin/sh

VER=$1
DPDK_ROOT=../../$2/dpdk-${VER}
DEBIAN_DIR=../build-root/deb/debian
SRC_DIR=/usr/src/vpp-dpdk-dkms-${VER}/


cat > ${DEBIAN_DIR}/vpp-dpdk-dkms.install << _EOF_
${DPDK_ROOT}/lib/librte_eal/common/include/rte_pci_dev_feature_defs.h ${SRC_DIR}
${DPDK_ROOT}/lib/librte_eal/common/include/rte_pci_dev_features.h     ${SRC_DIR}
${DPDK_ROOT}/lib/librte_eal/linuxapp/igb_uio/igb_uio.c                ${SRC_DIR}
${DPDK_ROOT}/lib/librte_eal/linuxapp/igb_uio/compat.h                 ${SRC_DIR}
../../dpdk/dkms/Makefile ${SRC_DIR}
_EOF_


# dkms config
cat > ${DEBIAN_DIR}/vpp-dpdk-dkms.dkms << _EOF_
PACKAGE_VERSION="${VER}"
PACKAGE_NAME="vpp-dpdk-dkms"
CLEAN="make clean"
BUILT_MODULE_NAME[0]="igb_uio"
BUILT_MODULE_LOCATION[0]="./"
DEST_MODULE_LOCATION[0]="/kernel/net"
MAKE[1]="make"
AUTOINSTALL="yes"
_EOF_
