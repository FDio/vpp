# Copyright (c) 2024 Cisco and/or its affiliates.
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

openssl_version             := 3.5.1
openssl_tarball             := openssl-$(openssl_version).tar.gz
openssl_tarball_sha256sum   := 529043b15cffa5f36077a4d0af83f3de399807181d607441d734196d889b641f

openssl_tarball_strip_dirs  := 1
openssl_url                 := https://github.com/openssl/openssl/releases/download/openssl-$(openssl_version)/$(openssl_tarball)

# DEBUG: Add the following line to openssl_config_args when debugging with gdb
# --debug -d -g3 -ggdb -gdwarf-5 -fno-inline -O0 -fno-omit-frame-pointer -DPURIFY
define openssl_config_args
--prefix=$(openssl_install_dir) \
--openssldir=$(openssl_build_dir) \
no-dtls1
endef

define  openssl_config_cmds
	@cd $(openssl_src_dir) && \
		$(openssl_src_dir)/config \
			$(openssl_config_args) | tee -a $(openssl_config_log)
endef

define  openssl_build_cmds
	@cd $(openssl_src_dir) && \
		$(MAKE) depend build_sw | tee $(openssl_build_log)
endef

define  openssl_install_cmds
	@cd $(openssl_src_dir) && \
		$(MAKE) install_sw | tee $(openssl_install_log)
endef

$(eval $(call package,openssl))

