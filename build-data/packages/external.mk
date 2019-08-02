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

DPDK_PKG_MAKE_ARGS =  -C $(call find_source_fn,$(PACKAGE_SOURCE)) \
	DPDK_DEBUG=$(DPDK_DEBUG)

DPDK_MAKE_ARGS = $(DPDK_PKG_MAKE_ARGS) \
	BUILD_DIR=$(PACKAGE_BUILD_DIR) \
	INSTALL_DIR=$(PACKAGE_INSTALL_DIR)

external_configure = echo

# DPDK_CONFIG_ARGS are defined in $(build-data/platforms/$(PLATFORM).mk)
#   and modify DPDK configuration done in build/external/packages/dpdk.mk
# DPDK_MAKE_EXTRA_ARGS are defined in $(build-data/platforms/$(PLATFORM).mk)
#   and will be passed to the make command that builds DPDK defined in
#   build/external/packages/dpdk.mk

external_make = $(DPDK_MAKE_ARGS) DPDK_MAKE_EXTRA_ARGS="$(DPDK_MAKE_EXTRA_ARGS)" $(DPDK_CONFIG_ARGS)

external_make_args = $(external_make) -C external ebuild-build

external_install =  make $(external_make) -C external ebuild-install

external_install_$(PKG) = make $(DPDK_PKG_MAKE_ARGS) DPDK_MAKE_EXTRA_ARGS="$(DPDK_MAKE_EXTRA_ARGS)" $(DPDK_CONFIG_ARGS) -C external install-$(PKG)

