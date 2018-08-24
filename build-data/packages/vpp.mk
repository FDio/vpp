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
