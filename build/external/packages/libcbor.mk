# Copyright (c) 2025 Cisco and/or its affiliates.
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

libcbor_version := 0.13.0
libcbor_tarball := libcbor-$(libcbor_version).tar.gz
libcbor_tarball_sha256sum := 95a7f0dd333fd1dce3e4f92691ca8be38227b27887599b21cd3c4f6d6a7abb10
libcbor_tarball_strip_dirs := 1
libcbor_url := https://github.com/PJK/libcbor/archive/refs/tags/v$(libcbor_version).tar.gz

define  libcbor_build_cmds
	@cd $(libcbor_build_dir) && \
		rm -f $(libcbor_build_log) && \
		$(CMAKE) -DCMAKE_INSTALL_PREFIX:PATH=$(libcbor_install_dir) \
		-DCMAKE_C_COMPILER="$(CC)" \
		-DCMAKE_CXX_COMPILER="$(CXX)" \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_POSITION_INDEPENDENT_CODE=ON \
		-DCMAKE_C_FLAGS="$(CFLAGS) -fPIC" \
		-DCMAKE_CXX_FLAGS="$(CXXFLAGS) -fPIC" \
		-DCMAKE_EXPORT_COMPILE_COMMANDS=OFF \
		-DCBOR_BUILD_SHARED_LIBS=OFF \
		-DCBOR_BUILD_TESTS=OFF \
		-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF \
		$(libcbor_src_dir) >> $(libcbor_build_log) 2>&1
	@$(MAKE) $(MAKE_ARGS) -C $(libcbor_build_dir) all >> $(libcbor_build_log) 2>&1
endef

define  libcbor_config_cmds
	@true
endef

define  libcbor_install_cmds
	@rm -f $(libcbor_install_log)
	@$(MAKE) $(MAKE_ARGS) -C $(libcbor_build_dir) install >> $(libcbor_install_log)
endef


$(eval $(call package,libcbor))
