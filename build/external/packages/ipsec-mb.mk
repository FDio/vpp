# Copyright (c) 2018 Cisco and/or its affiliates.
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

ipsec-mb_version             := 3.0
ipsec-mb_patch_version       := 1
ipsec-mb_version_str         := $(ipsec-mb_version).$(ipsec-mb_patch_version)
ipsec-mb_tarball             := v$(ipsec-mb_version_str).tar.gz
ipsec-mb_tarball_sha256sum_3.0  := f971b253d1ad4affa01bad557a4b8ae60fce37256e0afca03d480377c497c1aa

ipsec-mb_tarball_sha256sum   := $(ipsec-mb_tarball_sha256sum_$(ipsec-mb_version))
ipsec-mb_tarball_strip_dirs  := 1
ipsec-mb_url                 := https://github.com/intel/intel-ipsec-mb/archive/$(ipsec-mb_tarball)

# ipsec-mb 3.0 only supports CMake builds (legacy Makefiles were deprecated)
define  ipsec-mb_config_cmds
	@$(CMAKE) -S $(ipsec-mb_src_dir) -B $(ipsec-mb_build_dir) \
	  -DCMAKE_BUILD_TYPE=Release \
	  -DBUILD_SHARED_LIBS=OFF \
	  -DBUILD_LIBRARY_ONLY=ON \
	  -DSAFE_PARAM=OFF \
	  -DSAFE_LOOKUP=OFF \
	  -DSAFE_DATA=OFF \
	  -DCMAKE_INSTALL_PREFIX=$(ipsec-mb_install_dir) \
	  -DEXTRA_CFLAGS="-g -msse4.2" > $(ipsec-mb_config_log) 2>&1
endef

define  ipsec-mb_build_cmds
	@$(CMAKE) --build $(ipsec-mb_build_dir) --parallel $(JOBS) \
	  > $(ipsec-mb_build_log) 2>&1
endef

define  ipsec-mb_install_cmds
	@mkdir -p $(ipsec-mb_install_dir)/include
	@mkdir -p $(ipsec-mb_install_dir)/lib
	@cp $(ipsec-mb_src_dir)/lib/intel-ipsec-mb.h $(ipsec-mb_install_dir)/include
	@cp $(ipsec-mb_build_dir)/lib/libIPSec_MB.a $(ipsec-mb_install_dir)/lib
endef

$(eval $(call package,ipsec-mb))
