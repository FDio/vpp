# Copyright (c) 2019 PANTHEON.tech s.r.o. and/or its affiliates.
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

# aarch64 generic build
# used for cross compilation as well as aarch64 host builds
ARCH = aarch64
TARGET = aarch64-linux-gnu
#DEB_ARCH = arm64
MARCH = cortex-a72
MTUNE = generic

vpp_cmake_args ?=
vpp_cmake_args += -DVPP_LOG2_CACHE_LINE_SIZE=7

CMAKE_MARCH_VARIANTS = "$(MARCH)\;-march=armv8-a+crc+crypto -mtune=$(MTUNE) -DCLIB_N_PREFETCHES=6"
CMAKE_MARCH_C_FLAG = -march=armv8-a+crc

DPDK_CONFIG_ARGS = DPDK_MACHINE=armv8a \
    DPDK_TARGET=arm64-armv8a-linuxapp-gcc \
    DPDK_TUNE=$(MTUNE) \
    DPDK_CACHE_LINE_SIZE=128 \
    ARCH=$(ARCH)

ifneq ($(ARCH),$(HOST_ARCH))
CMAKE_CROSS_ARGS = -DCMAKE_SYSTEM_NAME=Linux
CMAKE_CROSS_ARGS += -DCMAKE_SYSTEM_PROCESSOR=$(ARCH)
CMAKE_CROSS_ARGS += -DCMAKE_C_COMPILER=$(TARGET)-gcc
CMAKE_CROSS_ARGS += -DCMAKE_CXX_COMPILER=$(TARGET)-g++
CMAKE_CROSS_ARGS += -DCMAKE_IGNORE_PATH=/usr/lib/$(HOST_ARCH)-linux-gnu/
DPDK_MAKE_EXTRA_ARGS = CROSS=$(TARGET)-
endif

ROOT_PACKAGES = vpp vom

-include ../build-data/platforms/common.mk
