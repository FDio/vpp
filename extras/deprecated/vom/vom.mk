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

vom_configure_depend = vpp-install
vom_source = extras
vom_configure_subdir = vom

# OS Detection
#
# We allow Darwin (MacOS) for docs generation; VPP build will still fail.
ifneq ($(shell uname),Darwin)
OS_ID        = $(shell grep '^ID=' /etc/os-release | cut -f2- -d= | sed -e 's/\"//g')
	ifeq ($(OS_ID),rhel)
		OS_VERSION_ID= $(shell grep '^VERSION_ID=' /etc/os-release | cut -f2- -d= | sed -e 's/\"//g' | sed -e 's/\..*//')
	else
		OS_VERSION_ID= $(shell grep '^VERSION_ID=' /etc/os-release | cut -f2- -d= | sed -e 's/\"//g')
	endif
endif

ifneq ($(shell which cmake3 2>/dev/null),)
CMAKE?=cmake3
else
CMAKE?=cmake
endif

vom_cmake_args ?=
vom_cmake_args += -DCMAKE_INSTALL_PREFIX:PATH=$(PACKAGE_INSTALL_DIR)
vom_cmake_args += -DCMAKE_CXX_FLAGS="$($(TAG)_TAG_CPPFLAGS)"
vom_cmake_args += -DCMAKE_SHARED_LINKER_FLAGS="$($(TAG)_TAG_LDFLAGS)"
vom_cmake_args += -DCMAKE_PREFIX_PATH:PATH="$(PACKAGE_INSTALL_DIR)/../vpp"

# Use devtoolset
ifeq ($(OS_ID)-$(OS_VERSION_ID),rhel-8)
	ifneq ($(wildcard /opt/rh/gcc-toolset-9/enable),)
	vom_cmake_args += -DCMAKE_PROGRAM_PATH:PATH="/opt/rh/gcc-toolset-9/root/bin"
	endif
else
	# Use devtoolset on centos 7
	ifneq ($(wildcard /opt/rh/devtoolset-9/enable),)
	vom_cmake_args += -DCMAKE_PROGRAM_PATH:PATH="/opt/rh/devtoolset-9/root/bin"
	endif
endif

vom_configure = \
  cd $(PACKAGE_BUILD_DIR) && \
  $(CMAKE) -G Ninja $(vom_cmake_args) $(call find_source_fn,$(PACKAGE_SOURCE))$(PACKAGE_SUBDIR)

vom_build = $(CMAKE) --build $(PACKAGE_BUILD_DIR) -- $(MAKE_PARALLEL_FLAGS)

vom_install = $(CMAKE) --build $(PACKAGE_BUILD_DIR) -- install

vom-package-deb: vom-install
	@$(CMAKE) --build $(PACKAGE_BUILD_DIR)/vom -- package
	@find $(PACKAGE_BUILD_DIR)/vom -name '*.deb' -exec mv {} $(CURDIR) \;
