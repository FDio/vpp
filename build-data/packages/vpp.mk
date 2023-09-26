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

vpp_cmake_prefix_path  = /opt/vpp/external/$(shell uname -m)
vpp_cmake_prefix_path += $(PACKAGE_INSTALL_DIR)external
vpp_cmake_prefix_path := $(subst $() $(),;,$(vpp_cmake_prefix_path))

vpp_cmake_args ?=
vpp_cmake_args += -DCMAKE_INSTALL_PREFIX:PATH=$(PACKAGE_INSTALL_DIR)
vpp_cmake_args += -DCMAKE_BUILD_TYPE="$($(TAG)_TAG_BUILD_TYPE)"
vpp_cmake_args += -DCMAKE_PREFIX_PATH:PATH="$(vpp_cmake_prefix_path)"
ifeq ("$(V)","1")
vpp_cmake_args += -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON
endif
ifneq ($(VPP_EXCLUDED_PLUGINS),)
vpp_cmake_args += -DVPP_EXCLUDED_PLUGINS="$(VPP_EXCLUDED_PLUGINS)"
endif

ifneq ($(VPP_EXTRA_CMAKE_ARGS),)
vpp_cmake_args += $(VPP_EXTRA_CMAKE_ARGS)
endif

vpp_configure_depend += external-install
vpp_configure = \
  cd $(PACKAGE_BUILD_DIR) && \
  $(CMAKE) -G Ninja $(vpp_cmake_args) $(call find_source_fn,$(PACKAGE_SOURCE))
vpp_build = $(CMAKE) --build $(PACKAGE_BUILD_DIR) -- $(MAKE_PARALLEL_FLAGS)
vpp_install = $(CMAKE) --build $(PACKAGE_BUILD_DIR) -- install | grep -v 'Set runtime path'

vpp-package-deb: vpp-install
	@$(CMAKE) --build $(PACKAGE_BUILD_DIR)/vpp -- pkg-deb
	@find $(PACKAGE_BUILD_DIR) \
          -maxdepth 2 \
          \( -name '*.changes' -o -name '*.deb' -o -name '*.buildinfo' \) \
          -exec mv {} $(CURDIR) \;
