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

ipsec-mb_version             := 2.0
ipsec-mb_patch_version       := 0
ipsec-mb_version_str         := $(ipsec-mb_version).$(ipsec-mb_patch_version)
ipsec-mb_tarball             := v$(ipsec-mb_version).tar.gz
ipsec-mb_tarball_sha256sum_2.0  := 0c60e56f63b14212c7b388668acc219cbc6b79e5e79732aff7542fefbb498413

ipsec-mb_tarball_sha256sum   := $(ipsec-mb_tarball_sha256sum_$(ipsec-mb_version))
ipsec-mb_tarball_strip_dirs  := 1
ipsec-mb_url                 := http://github.com/intel/intel-ipsec-mb/archive/$(ipsec-mb_tarball)
define  ipsec-mb_config_cmds
	@true
endef

define  ipsec-mb_build_cmds
	@$(MAKE) -C $(ipsec-mb_src_dir)/lib -j \
	  SHARED=n \
	  SAFE_PARAM=n \
	  SAFE_LOOKUP=n \
	  SAFE_DATA=n \
	  PREFIX=$(ipsec-mb_install_dir) \
	  EXTRA_CFLAGS="-g -msse4.2" > $(ipsec-mb_build_log)
endef

define  ipsec-mb_install_cmds
	@mkdir -p $(ipsec-mb_install_dir)/include
	@mkdir -p $(ipsec-mb_install_dir)/lib
	@cp $(ipsec-mb_src_dir)/lib/intel-ipsec-mb.h $(ipsec-mb_install_dir)/include
	@cp $(ipsec-mb_src_dir)/lib/libIPSec_MB.a $(ipsec-mb_install_dir)/lib
endef

$(eval $(call package,ipsec-mb))
