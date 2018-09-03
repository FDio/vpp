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
vom_configure = \
  cd $(PACKAGE_BUILD_DIR) && \
  cmake -G Ninja \
    -DCMAKE_INSTALL_PREFIX:PATH=$(PACKAGE_INSTALL_DIR) \
    -DCMAKE_CXX_FLAGS=$(call installed_includes_fn, vpp) \
    -DCMAKE_LIBRARY_PATH:PATH="$(call installed_libs_fn, vpp)" \
    $(call find_source_fn,$(PACKAGE_SOURCE))

vom_build = cmake --build $(PACKAGE_BUILD_DIR)
vom_install = cmake --build $(PACKAGE_BUILD_DIR) -- install
