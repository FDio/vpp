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

nasm_version            := 2.15.05
nasm_tarball            := nasm-$(nasm_version).tar.gz
nasm_tarball_md5sum     := 2e154a96a13bf937d5247467d986bbde
nasm_tarball_strip_dirs := 1
nasm_url                := https://github.com/netwide-assembler/nasm/archive/$(nasm_tarball)
nasm_cflags             := -Wno-implicit-fallthrough -std=c11

define  nasm_config_cmds
	cd $(nasm_src_dir) && sh autogen.sh && sh configure --prefix=$(nasm_install_dir)
endef

define  nasm_build_cmds
	make -C $(nasm_src_dir) -j
	make -C $(nasm_src_dir) -j manpages
endef

define  nasm_install_cmds
	make -C $(nasm_src_dir) install
endef

$(eval $(call package,nasm))
