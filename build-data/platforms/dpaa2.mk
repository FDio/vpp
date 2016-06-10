#
# Copyright (c) 2016 Freescale Semiconductor, Inc. All rights reserved.
#

# Configuration for NXP DPAA2 ARM64 based platform
dpaa2_arch = aarch64
dpaa2_os = linux-gnu
dpaa2_target = aarch64-linux-gnu
dpaa2_mtune = cortex-A57
dpaa2_march = "armv8-a+fp+simd+crc+crypto"
dpaa2_cross_ldflags = \
	-Wl,--dynamic-linker=/lib/ld-linux-aarch64.so.1

dpaa2_native_tools = vppapigen
dpaa2_root_packages = vpp vlib vlib-api vnet svm vpp-api-test

# DPDK configuration parameters
#
# We are using external DPDK module with NXP-DPAA2 platform support.
# Compile DPDK only if "DPDK_PATH" variable is defined where we have
# installed DPDK libraries and headers.
ifeq ($(PLATFORM),dpaa2)
ifneq ($(DPDK_PATH),)
dpaa2_uses_dpdk = yes
dpaa2_uses_external_dpdk = yes
dpaa2_dpdk_inc_dir = $(DPDK_PATH)/include/dpdk
dpaa2_dpdk_lib_dir = $(DPDK_PATH)/lib
else
$(error Please define path <DPDK_PATH> for installed DPDK headers and libs)
endif
endif

vpp_configure_args_dpaa2 = --with-dpdk --without-ipsec --without-vcgn \
	--without-ipv6sr --with-sysroot=$(SYSROOT)
vnet_configure_args_dpaa2 = --with-dpdk --without-ipsec --without-vcgn \
	--without-ipv6sr --with-sysroot=$(SYSROOT)

# Set these parameters carefully. The vlib_buffer_t is 128 bytes, i.e.
vlib_configure_args_dpaa2 = --with-pre-data=128


dpaa2_debug_TAG_CFLAGS = -g -O2 -DCLIB_DEBUG -fPIC -fstack-protector-all \
			-march=$(MARCH) -Werror
dpaa2_debug_TAG_LDFLAGS = -g -O2 -DCLIB_DEBUG -fstack-protector-all \
			-march=$(MARCH) -Werror

# Use -rdynamic is for stack tracing, O0 for debugging....default is O2
# Use -DCLIB_LOG2_CACHE_LINE_BYTES to change cache line size
dpaa2_TAG_CFLAGS = -g -O2 -fPIC -march=$(MARCH) -mcpu=$(dpaa2_mtune) \
		-mtune=$(dpaa2_mtune) -funroll-all-loops -Werror
dpaa2_TAG_LDFLAGS = -g -O2 -fPIC -march=$(MARCH) -mcpu=$(dpaa2_mtune) \
		-mtune=$(dpaa2_mtune) -funroll-all-loops -Werror


