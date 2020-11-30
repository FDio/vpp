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

DPDK_PLATFORM_TARGET=$(strip $($(PLATFORM)_dpdk_target))
ifneq ($(DPDK_PLATFORM_TARGET),)
DPDK_MAKE_ARGS += DPDK_TARGET=$(DPDK_PLATFORM_TARGET)
endif

ifneq (,$(TARGET_PLATFORM))
DPDK_MAKE_ARGS += DPDK_AARCH64_GENERIC=n
endif

DPDK_MAKE_EXTRA_ARGS = $(strip $($(PLATFORM)_dpdk_make_extra_args))
ifneq ($(DPDK_MAKE_EXTRA_ARGS),)
DPDK_MAKE_ARGS += DPDK_MAKE_EXTRA_ARGS="$(DPDK_MAKE_EXTRA_ARGS)"
endif

external_configure = echo

external_build = echo

external_install =  make $(DPDK_MAKE_ARGS) -C external ebuild-build ebuild-install
