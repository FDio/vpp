# Copyright (c) 2017-2018 Cisco and/or its affiliates.
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

japi_configure_depend = vpp-install
japi_source = extras
japi_configure_subdir = japi

ifneq ($(shell which cmake3),)
CMAKE?=cmake3
else
CMAKE?=cmake
endif

japi_cmake_args ?=
japi_cmake_args += -DCMAKE_INSTALL_PREFIX:PATH=$(PACKAGE_INSTALL_DIR)
japi_cmake_args += -DCMAKE_C_FLAGS="$($(TAG)_TAG_CFLAGS)"
japi_cmake_args += -DCMAKE_SHARED_LINKER_FLAGS="$($(TAG)_TAG_LDFLAGS)"
japi_cmake_args += -DCMAKE_PREFIX_PATH:PATH="$(PACKAGE_INSTALL_DIR)/../vpp"
ifeq ("$(V)","1")
japi_cmake_args += -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON
endif

#Use devtoolset on centos 7
ifneq ($(wildcard /opt/rh/devtoolset-7/enable),)
japi_cmake_args += -DCMAKE_PROGRAM_PATH:PATH="/opt/rh/devtoolset-7/root/bin"
endif

japi_configure = \
 cd $(PACKAGE_BUILD_DIR) && \
 $(CMAKE) -G Ninja $(japi_cmake_args) $(call find_source_fn,$(PACKAGE_SOURCE))$(PACKAGE_SUBDIR)

japi_build = $(CMAKE) --build $(PACKAGE_BUILD_DIR) -- $(MAKE_PARALLEL_FLAGS)

japi_install = $(CMAKE) --build $(PACKAGE_BUILD_DIR) -- install
