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

external_source = build

ifneq (,$(findstring debug,$(TAG)))
	DPDK_DEBUG=y
else
	DPDK_DEBUG=n
endif

DPDK_MAKE_ARGS = -C $(call find_source_fn,$(PACKAGE_SOURCE)) \
	BUILD_DIR=$(PACKAGE_BUILD_DIR) \
	INSTALL_DIR=$(PACKAGE_INSTALL_DIR) \
	DPDK_DEBUG=$(DPDK_DEBUG)

DPDK_MLX5_PMD=$(strip $($(PLATFORM)_uses_dpdk_mlx5_pmd))
ifneq ($(DPDK_MLX5_PMD),)
DPDK_MAKE_ARGS += DPDK_MLX5_PMD=y
endif

DPDK_MLX_IBVERBS_DLOPEN=$(strip $($(PLATFORM)_uses_dpdk_ibverbs_link_dlopen))
ifneq ($(DPDK_MLX_IBVERBS_DLOPEN),)
DPDK_MAKE_ARGS += DPDK_MLX_IBVERBS_DLOPEN=y
endif

DPDK_MLX4_PMD=$(strip $($(PLATFORM)_uses_dpdk_mlx4_pmd))
ifneq ($(DPDK_MLX4_PMD),)
DPDK_MAKE_ARGS += DPDK_MLX4_PMD=y
endif

ifeq ($(MACHINE),aarch64)
  # If not specified, cache line size is 128B by default, otherwise,
  # the value will be detected per native CPU info in /proc/cpuinfo
  ifeq (,$(TARGET_PLATFORM))
    CPU_CACHE_LINE_SIZE = 64
  else
    # Most Arm CPU cache line size is 64B
    CPU_CACHE_LINE_SIZE = 64
    MIDR_IMPLEMENTER=$(shell awk '/implementer/ {print $$4;exit}' /proc/cpuinfo)
    MIDR_PARTNUM=$(shell awk '/part/ {print $$4;exit}' /proc/cpuinfo)
    # Implementer 0x43 - Cavium
    # Part 0x0af - ThunderX2 is 64B, rest all Cavium CPUs are 128B
    ifeq ($(MIDR_IMPLEMENTER),0x43)
      ifeq ($(MIDR_PARTNUM),0x0af)
        CPU_CACHE_LINE_SIZE = 64
      else
        CPU_CACHE_LINE_SIZE = 128
      endif
    endif
  endif
  DPDK_MAKE_ARGS += DPDK_CACHE_LINE_SIZE=$(CPU_CACHE_LINE_SIZE)
endif

DPDK_MAKE_EXTRA_ARGS = $(strip $($(PLATFORM)_dpdk_make_extra_args))
ifneq ($(DPDK_MAKE_EXTRA_ARGS),)
DPDK_MAKE_ARGS += DPDK_MAKE_EXTRA_ARGS="$(DPDK_MAKE_EXTRA_ARGS)"
endif

external_configure = echo

external_build = echo

external_install =  make $(DPDK_MAKE_ARGS) -C external ebuild-build ebuild-install
