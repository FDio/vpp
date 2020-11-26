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

ipsec-mb_version             := 0.55
ipsec-mb_tarball             := v$(ipsec-mb_version).tar.gz
ipsec-mb_tarball_md5sum_0.49 := 3a2bee86f25f6c8ed720da5b4b8d4297
ipsec-mb_tarball_md5sum_0.52 := 11ecfa6db4dc0c4ca6e5c616c141ac46
ipsec-mb_tarball_md5sum_0.53 := e9b3507590efd1c23321518612b644cd
ipsec-mb_tarball_md5sum_0.54 := 258941f7ba90c275fcf9d19c622d2d21
ipsec-mb_tarball_md5sum_0.55 := deca674bca7ae2282890e1fa7f953609

ipsec-mb_tarball_md5sum      := $(ipsec-mb_tarball_md5sum_$(ipsec-mb_version))
ipsec-mb_tarball_strip_dirs  := 1
ipsec-mb_url                 := http://github.com/01org/intel-ipsec-mb/archive/$(ipsec-mb_tarball)

define  ipsec-mb_config_cmds
	@true
endef

define  ipsec-mb_build_cmds
	@make -C $(ipsec-mb_src_dir) -j \
	  SHARED=n \
	  SAFE_PARAM=n \
	  SAFE_LOOKUP=n \
	  SAFE_DATA=n \
	  PREFIX=$(ipsec-mb_install_dir) \
	  NASM=$(ipsec-mb_install_dir)/bin/nasm \
	  EXTRA_CFLAGS="-g -msse4.2" > $(ipsec-mb_build_log)
endef

define  ipsec-mb_install_cmds
	@mkdir -p $(ipsec-mb_install_dir)/include
	@mkdir -p $(ipsec-mb_install_dir)/lib
	@cp $(ipsec-mb_src_dir)/lib/intel-ipsec-mb.h $(ipsec-mb_install_dir)/include
	@cp $(ipsec-mb_src_dir)/lib/libIPSec_MB.a $(ipsec-mb_install_dir)/lib
endef

$(eval $(call package,ipsec-mb))


