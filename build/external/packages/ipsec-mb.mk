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
ipsec-mb_system_header       := $(wildcard /usr/include/intel-ipsec-mb.h)

define  ipsec-mb_config_cmds
	@true
endef

define  ipsec-mb_build_cmds
	@$(MAKE) -C $(ipsec-mb_src_dir)/lib -j \
	  SHARED=n \
	  SAFE_PARAM=n \
	  SAFE_LOOKUP=n \
	  SAFE_DATA=n \
	  PREFIX=$(ipsec-mb_root_dir)/$(ipsec-mb_install_dir) \
	  EXTRA_CFLAGS="-g -msse4.2" > $(ipsec-mb_build_log)
endef

ifneq   ($(ipsec-mb_system_header), )
	ipsec-mb_system_ver_str := $(shell awk '/^#define\s+IMB_VERSION_STR/ { print $$3 }' \
	$(ipsec-mb_system_header))
endif

define  ipsec-mb_install_cmds
	if [[ -n "$(ipsec-mb_system_header)" ]]; then \
		if [[ "$(ipsec-mb_system_ver_str)" != "$(ipsec-mb_version_str)" ]]; then \
		echo "Intel-ipsec-mb build Error: System installed Intel IPsec-mb lib \
		version mismatch with target version, \
		expecting $(ipsec-mb_version_str), \
		but system has $(ipsec-mb_system_ver_str) \
		please align/remove system installed $(ipsec-mb_system_header) before building."; \
		exit 1; \
		fi \
	fi
	@$(MAKE) -C $(ipsec-mb_src_dir)/lib install \
		V=1 \
		NOLDCONFIG=y \
		SHARED=n \
		SAFE_PARAM=n \
		SAFE_LOOKUP=n \
		SAFE_DATA=n \
		PREFIX=$(ipsec-mb_root_dir)/$(ipsec-mb_install_dir) >> $(ipsec-mb_install_log)
endef

$(eval $(call package,ipsec-mb))


