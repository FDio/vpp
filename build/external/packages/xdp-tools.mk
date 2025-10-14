# Copyright (c) 2023 Intel and/or its affiliates.
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

xdp-tools_version             := 1.5.5
xdp-tools_tarball             := xdp-tools-$(xdp-tools_version).tar.gz
xdp-tools_tarball_sha256sum_1.5.5 := 9a4339ffc40df178c4ddf919cb2b23585a75b3023517c75e82c4dfb0899249c7

xdp-tools_tarball_sha256sum      := $(xdp-tools_tarball_sha256sum_$(xdp-tools_version))
xdp-tools_tarball_strip_dirs  := 1
xdp-tools_url                 := https://github.com/xdp-project/xdp-tools/releases/download/v$(xdp-tools_version)/$(xdp-tools_tarball)

define  xdp-tools_config_cmds
	@true
endef

define  xdp-tools_build_cmds
	@cd ${xdp-tools_src_dir} && $(MAKE) CC=gcc V=1 BUILD_STATIC_ONLY=y PREFIX='$(xdp-tools_install_dir)' > $(xdp-tools_build_log)
endef

define  xdp-tools_install_cmds
	@rm -f $(xdp-tools_install_log)
	@cd ${xdp-tools_src_dir} && \
		$(MAKE) -C lib/libbpf/src install V=1 BUILD_STATIC_ONLY=y PREFIX='$(xdp-tools_install_dir)' >> $(xdp-tools_install_log)
	@cd ${xdp-tools_src_dir} && \
		$(MAKE) -C lib/libxdp install V=1 BUILD_STATIC_ONLY=y PREFIX='$(xdp-tools_install_dir)' >> $(xdp-tools_install_log)
endef

$(eval $(call package,xdp-tools))
