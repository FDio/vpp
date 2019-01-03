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

vppxaarch64_source = src

ifneq ($(shell which cmake3),)
CMAKE?=cmake3
else
CMAKE?=cmake
endif

vppxaarch64_cmake_prefix_path  = /opt/vppxaarch64/external/$(shell uname -m)
vppxaarch64_cmake_prefix_path += $(PACKAGE_INSTALL_DIR)external
vppxaarch64_cmake_prefix_path := $(subst $() $(),;,$(vppxaarch64_cmake_prefix_path))

vppxaarch64_cmake_args ?=
vppxaarch64_cmake_args += -DCMAKE_INSTALL_PREFIX:PATH=$(PACKAGE_INSTALL_DIR)
vppxaarch64_cmake_args += -DCMAKE_C_FLAGS="$($(TAG)_TAG_CFLAGS)"
vppxaarch64_cmake_args += -DCMAKE_LINKER_FLAGS="$($(TAG)_TAG_LDFLAGS)"
vppxaarch64_cmake_args += -DCMAKE_PREFIX_PATH:PATH="$(vppxaarch64_cmake_prefix_path)"
vppxaarch64_cmake_args += -DCMAKE_TOOLCHAIN_FILE="$(MU_BUILD_ROOT_DIR)/../build-data/platforms/xcompile-aarch64.txt"
ifeq ("$(V)","1")
vppxaarch64_cmake_args += -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON
endif

# Use devtoolset on centos 7
ifneq ($(wildcard /opt/rh/devtoolset-7/enable),)
vppxaarch64_cmake_args += -DCMAKE_PROGRAM_PATH:PATH="/opt/rh/devtoolset-7/root/bin"
endif

vppxaarch64_configure_depend += external-install
vppxaarch64_configure = \
  cd $(PACKAGE_BUILD_DIR) && \
  $(CMAKE) -G Ninja $(vppxaarch64_cmake_args) $(call find_source_fn,$(PACKAGE_SOURCE))
#vppxaarch64_make_args = --no-print-directory
vppxaarch64_build = $(CMAKE) --build $(PACKAGE_BUILD_DIR)
vppxaarch64_install = $(CMAKE) --build $(PACKAGE_BUILD_DIR) -- install | grep -v 'Set runtime path'
