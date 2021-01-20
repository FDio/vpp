# Copyright 2018 NXP
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

# Configuration for NXP DPAA1/DPAA2 ARM64 based platform
MACHINE=$(shell uname -m)

dpaa_mtune = cortex-A72
dpaa_march = "armv8-a+fp+simd+crc+crypto"

ifeq ($(MACHINE),aarch64)
dpaa_arch = native
else
dpaa_arch = aarch64
dpaa_os = linux-gnu
dpaa_target = aarch64-fsl-linux
dpaa_cross_ldflags = \
	-Wl,--dynamic-linker=/lib/ld-linux-aarch64.so.1 \
	-Wl,-rpath=/usr/lib64 \
	-Wl,-rpath=./.libs \
	-Wl,-rpath=$(OPENSSL_PATH)/lib
endif

# Re-write Default configuration, if requied
ifneq ($(CROSS_PREFIX),)
# like: aarch64-linux-gnu
dpaa_target = $(CROSS_PREFIX)
endif

ifneq ($(CPU_MTUNE),)
# like: cortex-A53
dpaa_mtune = $(CPU_MTUNE)
endif

dpaa_native_tools = vppapigen
dpaa_root_packages = vpp

# DPDK configuration parameters
dpaa_uses_dpdk = yes

# Compile with external DPDK only if "DPDK_PATH" variable is defined where we have
# installed DPDK libraries and headers.
ifeq ($(PLATFORM),dpaa)
ifneq ($(DPDK_PATH),)
#dpaa_dpdk_shared_lib = yes
dpaa_uses_external_dpdk = yes
dpaa_dpdk_inc_dir = $(DPDK_PATH)/include/dpdk
dpaa_dpdk_lib_dir = $(DPDK_PATH)/lib
else
# compile using internal DPDK + NXP DPAA2 Driver patch
dpaa_dpdk_arch = "armv8a"
dpaa_dpdk_target = "arm64-dpaa-linuxapp-gcc"
dpaa_dpdk_make_extra_args = "CONFIG_RTE_KNI_KMOD=n"
endif
endif

# Disable the unused plugins in order to decrease the VPP pacakage size.
vpp_configure_args_dpaa = --without-ipv6sr --with-pre-data=128 --without-libnuma

# Other optional vpp_configure_args
ifneq ($(VPP_CFG_ARGS),)
vpp_configure_args_dpaa += $(VPP_CFG_ARGS)
endif


dpaa_debug_TAG_CFLAGS = -g -O0 -DCLIB_DEBUG -fPIC -fstack-protector-all -D_FORTIFY_SOURCE=2 -mtls-dialect=trad \
			-march=$(MARCH) -Werror -DCLIB_LOG2_CACHE_LINE_BYTES=6 -I$(OPENSSL_PATH)/include
dpaa_debug_TAG_LDFLAGS = -g -O0 -DCLIB_DEBUG -fstack-protector-all -D_FORTIFY_SOURCE=2 \
			-march=$(MARCH) -Werror -DCLIB_LOG2_CACHE_LINE_BYTES=6 -L$(OPENSSL_PATH)/lib


# Use -rdynamic is for stack tracing, O0 for debugging....default is O2
# Use -DCLIB_LOG2_CACHE_LINE_BYTES to change cache line size
dpaa_TAG_CFLAGS = -g -Ofast -fPIC -march=$(MARCH) -mcpu=$(dpaa_mtune) -mtls-dialect=trad \
		-mtune=$(dpaa_mtune) -funroll-all-loops -DCLIB_LOG2_CACHE_LINE_BYTES=6 -I$(OPENSSL_PATH)/include
dpaa_TAG_LDFLAGS = -g -Ofast -fPIC -march=$(MARCH) -mcpu=$(dpaa_mtune) \
		-mtune=$(dpaa_mtune) -funroll-all-loops -DCLIB_LOG2_CACHE_LINE_BYTES=6 -L$(OPENSSL_PATH)/lib

