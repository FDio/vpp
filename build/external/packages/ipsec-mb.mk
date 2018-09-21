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

ipsec-mb_version             := 0.49
ipsec-mb_tarball             := v$(ipsec-mb_version).tar.gz
ipsec-mb_tarball_md5sum_0.49 := 3a2bee86f25f6c8ed720da5b4b8d4297
ipsec-mb_tarball_md5sum_0.50 := c847ed77ae34da551237349f1c9db1e9
ipsec-mb_tarball_md5sum      := $(ipsec-mb_tarball_md5sum_$(ipsec-mb_version))
ipsec-mb_tarball_strip_dirs  := 1
ipsec-mb_depends             := nasm
ipsec-mb_url                 := http://github.com/01org/intel-ipsec-mb/archive/$(ipsec-mb_tarball)

define  ipsec-mb_config_cmds
	@true
endef

define  ipsec-mb_build_cmds
	@true
endef

define  ipsec-mb_install_cmds
	@mkdir -p $(ipsec-mb_install_dir)/include
	@make -C $(ipsec-mb_src_dir) -j \
	  SHARED=n \
	  EXTRA_CFLAGS=-fPIC \
	  NASM=$(ipsec-mb_install_dir)/bin/nasm \
	  PREFIX=$(ipsec-mb_install_dir) \
	  install > $(ipsec-mb_install_log)
endef

$(eval $(call package,ipsec-mb))


