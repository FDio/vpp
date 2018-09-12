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

sample-plugin_source = src
sample-plugin_configure_subdir = examples/sample-plugin
sample-plugin_configure_depend = vpp-install
sample-plugin_CPPFLAGS = $(call installed_includes_fn, vpp)
sample-plugin_LDFLAGS = $(call installed_libs_fn, vpp)
sample-plugin_PATH = $(call package_install_dir_fn,vpp)/bin

ifneq ($(shell which cmake3),)
CMAKE?=cmake3
else
CMAKE?=cmake
endif

sample-plugin_cmake_args ?=
sample-plugin_cmake_args += -DCMAKE_INSTALL_PREFIX:PATH=$(PACKAGE_INSTALL_DIR)
sample-plugin_cmake_args += -DCMAKE_C_FLAGS="$($(TAG)_TAG_CFLAGS)"
sample-plugin_cmake_args += -DCMAKE_SHARED_LINKER_FLAGS="$($(TAG)_TAG_LDFLAGS)"
sample-plugin_cmake_args += -DCMAKE_PREFIX_PATH:PATH="$(PACKAGE_INSTALL_DIR)/../vpp"

# Use devtoolset on centos 7
ifneq ($(wildcard /opt/rh/devtoolset-7/enable),)
sample-plugin_cmake_args += -DCMAKE_PROGRAM_PATH:PATH="/opt/rh/devtoolset-7/root/bin"
endif

sample-plugin_configure = \
  cd $(PACKAGE_BUILD_DIR) && \
  $(CMAKE) -G Ninja $(sample-plugin_cmake_args) \
  $(call find_source_fn,$(PACKAGE_SOURCE))$(PACKAGE_SUBDIR)

sample-plugin_build = $(CMAKE) --build $(PACKAGE_BUILD_DIR) -- $(MAKE_PARALLEL_FLAGS)

sample-plugin_install = $(CMAKE) --build $(PACKAGE_BUILD_DIR) -- install
