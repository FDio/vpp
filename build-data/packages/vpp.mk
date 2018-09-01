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

vpp_source = src
ifneq ($(vpp_uses_cmake),yes)

ifeq ($($(PLATFORM)_dpdk_shared_lib),yes)
vpp_configure_args = --enable-dpdk-shared
else
vpp_configure_args =
endif

# Platform dependent configure flags
vpp_configure_args += $(vpp_configure_args_$(PLATFORM))


vpp_CPPFLAGS =
vpp_LDFLAGS =

ifneq ($($(PLATFORM)_uses_dpdk),no)
ifeq ($($(PLATFORM)_uses_external_dpdk),yes)
vpp_CPPFLAGS += -I$($(PLATFORM)_dpdk_inc_dir)
vpp_LDFLAGS += -L$($(PLATFORM)_dpdk_lib_dir)
else
vpp_configure_depend += dpdk-install
vpp_CPPFLAGS += $(call installed_includes_fn, dpdk)/dpdk
vpp_LDFLAGS += $(call installed_libs_fn, dpdk)
vpp_CPPFLAGS += -I/usr/include/dpdk
endif
ifeq ($($(PLATFORM)_uses_dpdk_mlx5_pmd),yes)
vpp_configure_args += --with-dpdk-mlx5-pmd
endif
ifeq ($($(PLATFORM)_uses_dpdk_mlx4_pmd),yes)
vpp_configure_args += --with-dpdk-mlx4-pmd
endif
else
vpp_configure_args += --disable-dpdk-plugin
endif

ifeq ($($(PLATFORM)_enable_tests),yes)
vpp_configure_args += --enable-tests
endif

else
ifneq ($(shell which cmake3),)
CMAKE?=cmake3
else
CMAKE?=cmake
endif

vpp_cmake_args ?=
vpp_cmake_args += -DCMAKE_INSTALL_PREFIX:PATH=$(PACKAGE_INSTALL_DIR)
vpp_cmake_args += -DCMAKE_C_FLAGS="$($(TAG)_TAG_CFLAGS)"
vpp_cmake_args += -DCMAKE_LINKER_FLAGS="$($(TAG)_TAG_LDFLAGS)"
vpp_cmake_args += -DDPDK_INCLUDE_DIR_HINT="$(PACKAGE_INSTALL_DIR)/../dpdk/include"
vpp_cmake_args += -DDPDK_LIB_DIR_HINT="$(PACKAGE_INSTALL_DIR)/../dpdk/lib"

# Use devtoolset on centos 7
ifneq ($(wildcard /opt/rh/devtoolset-7/enable),)
vpp_cmake_args += -DCMAKE_PROGRAM_PATH:PATH="/opt/rh/devtoolset-7/root/bin"
endif

vpp_configure_depend += dpdk-install
vpp_configure = \
  cd $(PACKAGE_BUILD_DIR) && \
  $(CMAKE) -G Ninja $(vpp_cmake_args) $(call find_source_fn,$(PACKAGE_SOURCE))
#vpp_make_args = --no-print-directory
vpp_build = $(CMAKE) --build $(PACKAGE_BUILD_DIR)
vpp_install = $(CMAKE) --build $(PACKAGE_BUILD_DIR) -- install | grep -v 'Set runtime path'
endif
