# Copyright (c) 2016 Freescale Semiconductor, Inc. All rights reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Configuration for NXP DPAA2 ARM64 based platform
dpaa2_arch = aarch64
dpaa2_os = linux-gnu
dpaa2_target = aarch64-linux-gnu
dpaa2_mtune = cortex-A57
dpaa2_march = "armv8-a+fp+simd+crc+crypto"
dpaa2_cross_ldflags = \
	-Wl,--dynamic-linker=/lib/ld-linux-aarch64.so.1 \
	-Wl,-rpath=/usr/lib64

dpaa2_native_tools = vppapigen
dpaa2_root_packages = vpp vlib vlib-api vnet svm vpp-api-test

# DPDK configuration parameters
dpaa2_uses_dpdk = yes
# Compile with external DPDK only if "DPDK_PATH" variable is defined where we have
# installed DPDK libraries and headers.
ifeq ($(PLATFORM),dpaa2)
ifneq ($(DPDK_PATH),)
dpaa2_uses_dpdk = yes
dpaa2_uses_external_dpdk = yes
dpaa2_dpdk_inc_dir = $(DPDK_PATH)/include/dpdk
dpaa2_dpdk_lib_dir = $(DPDK_PATH)/lib
else
# compile using internal DPDK + NXP DPAA2 Driver patch
dpaa2_dpdk_arch = "armv8a"
dpaa2_dpdk_target = "arm64-dpaa2-linuxapp-gcc"
dpaa2_dpdk_make_extra_args = "CROSS=$(dpaa2_target)- DPDK_PKTMBUF_HEADROOM=256"
endif
endif

vpp_configure_args_dpaa2 = --with-dpdk --without-libssl \
	--with-sysroot=$(SYSROOT)
vnet_configure_args_dpaa2 = --with-dpdk --without-libssl \
	--with-sysroot=$(SYSROOT)

# Set these parameters carefully. The vlib_buffer_t is 256 bytes, i.e.
vlib_configure_args_dpaa2 = --with-pre-data=256


dpaa2_debug_TAG_CFLAGS = -g -O2 -DCLIB_DEBUG -fPIC -fstack-protector-all \
			-march=$(MARCH) -Werror -DCLIB_LOG2_CACHE_LINE_BYTES=6
dpaa2_debug_TAG_LDFLAGS = -g -O2 -DCLIB_DEBUG -fstack-protector-all \
			-march=$(MARCH) -Werror -DCLIB_LOG2_CACHE_LINE_BYTES=6

# Use -rdynamic is for stack tracing, O0 for debugging....default is O2
# Use -DCLIB_LOG2_CACHE_LINE_BYTES to change cache line size
dpaa2_TAG_CFLAGS = -g -O2 -fPIC -march=$(MARCH) -mcpu=$(dpaa2_mtune) \
		-mtune=$(dpaa2_mtune) -funroll-all-loops -Werror -DCLIB_LOG2_CACHE_LINE_BYTES=6
dpaa2_TAG_LDFLAGS = -g -O2 -fPIC -march=$(MARCH) -mcpu=$(dpaa2_mtune) \
		-mtune=$(dpaa2_mtune) -funroll-all-loops -Werror -DCLIB_LOG2_CACHE_LINE_BYTES=6


