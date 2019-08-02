# Copyright (c) 2015 Cisco and/or its affiliates.
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

ARCH = native

ifeq ($(HOST_ARCH),aarch64)
vpp_cmake_args ?=
vpp_cmake_args += -DVPP_LOG2_CACHE_LINE_SIZE=7
ifneq ($(TARGET_MARCH),)
DPDK_CONFIG_ARGS = DPDK_AARCH64_GENERIC=n
endif
endif

#TARGET = aarch64-linux-gnu
#MARCH = cortex-a72
#MTUNE = generic

#CMAKE_MARCH_VARIANTS = "$(MARCH)\;-march=armv8-a+crc+crypto -mtune=$(MTUNE) -DCLIB_N_PREFETCHES=6"
#CMAKE_MARCH_C_FLAG = -march=armv8-a+crc

#DPDK_CONFIG_ARGS = DPDK_MACHINE=armv8a \
#    DPDK_TARGET=arm64-armv8a-linuxapp-gcc \
#    DPDK_TUNE=$(MTUNE) \
#    DPDK_CACHE_LINE_SIZE=128 \
#    ARCH=$(ARCH)

#ifneq ($(ARCH),$(HOST_ARCH))
#CMAKE_CROSS_ARGS = -DCMAKE_SYSTEM_NAME=Linux
#CMAKE_CROSS_ARGS += -DCMAKE_SYSTEM_PROCESSOR=$(ARCH)
#CMAKE_CROSS_ARGS += -DCMAKE_C_COMPILER=$(TARGET)-gcc
#CMAKE_CROSS_ARGS += -DCMAKE_CXX_COMPILER=$(TARGET)-g++
#DPDK_MAKE_EXTRA_ARGS = CROSS=$(TARGET)-
#endif

ROOT_PACKAGES = vpp vom

-include ../build-data/platforms/common.mk
