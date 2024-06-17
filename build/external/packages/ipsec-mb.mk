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

ipsec-mb_version             := 1.5
ipsec-mb_patch_version       := 0
ipsec-mb_version_str         := $(ipsec-mb_version).$(ipsec-mb_patch_version)
ipsec-mb_tarball             := v$(ipsec-mb_version).tar.gz
ipsec-mb_tarball_md5sum_1.0  := 906e701937751e761671dc83a41cff65
ipsec-mb_tarball_md5sum_1.1  := 3916471d3713d27e42473cb6af9c65e5
ipsec-mb_tarball_md5sum_1.2  := f551d9c208893a436c1f5c146a615bd6
ipsec-mb_tarball_md5sum_1.3  := d8692db9efe32a263b61f12ac0dca950
ipsec-mb_tarball_md5sum_1.4  := fddba2611f822296ddd82d1c31d22b24
ipsec-mb_tarball_md5sum_1.5  := f18680f8dd43208a15a19a494423bdb9
ipsec-mb_tarball_sha256sum_1.5  := 8d3f0a561b539303d81fda82584663daea65af85e07c40b393a4e8cfe839e057

ipsec-mb_tarball_sha256sum   := $(ipsec-mb_tarball_sha256sum_$(ipsec-mb_version))
ipsec-mb_tarball_md5sum      := $(ipsec-mb_tarball_md5sum_$(ipsec-mb_version))
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
	  PREFIX=$(ipsec-mb_install_dir) \
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
	@mkdir -p $(ipsec-mb_install_dir)/include
	@mkdir -p $(ipsec-mb_install_dir)/lib
	@cp $(ipsec-mb_src_dir)/lib/intel-ipsec-mb.h $(ipsec-mb_install_dir)/include
	@cp $(ipsec-mb_src_dir)/lib/libIPSec_MB.a $(ipsec-mb_install_dir)/lib
endef

$(eval $(call package,ipsec-mb))


