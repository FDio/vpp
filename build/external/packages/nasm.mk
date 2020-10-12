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

nasm_version            := 2.14.02
nasm_tarball            := nasm-$(nasm_version).tar.xz
nasm_tarball_md5sum     := 6390bd67b07ff1df9fe628b6929c0353
nasm_tarball_strip_dirs := 1
nasm_url                := https://ftp.osuosl.org/pub/blfs/conglomeration/nasm/$(nasm_tarball)
nasm_cflags             := -Wno-implicit-fallthrough -std=c11

ARCH_X86_64=$(filter x86_64,$(shell uname -m))

ifndef $(ARCH_X86_64)
define  ipsec-mb_config_cmds
	@true
endef

define  ipsec-mb_build_cmds
	@true
endef

define  ipsec-mb_install_cmds
	@true
endef
endif

$(eval $(call package,nasm))
