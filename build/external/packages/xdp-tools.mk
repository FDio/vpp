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

xdp-tools_version             := 1.2.9
xdp-tools_tarball             := xdp-tools-$(xdp-tools_version).tar.gz
xdp-tools_tarball_md5sum_1.2.9:= 6e4a49ceea8354bb7bb3b55990e9aed7
xdp-tools_tarball_md5sum      := $(xdp-tools_tarball_md5sum_$(xdp-tools_version))
xdp-tools_tarball_strip_dirs  := 1
xdp-tools_url                 := https://github.com/xdp-project/xdp-tools/releases/download/v$(xdp-tools_version)/$(xdp-tools_tarball)

define  xdp-tools_config_cmds
	@true
endef

define  xdp-tools_build_cmds
	@cd ${xdp-tools_src_dir} && make V=1 BUILD_STATIC_ONLY=y > $(xdp-tools_build_log)
endef

define  xdp-tools_install_cmds
	@rm -f $(xdp-tools_install_log)
	@cd ${xdp-tools_src_dir} && \
		make -C lib/libbpf/src install V=1 BUILD_STATIC_ONLY=y PREFIX='' DESTDIR='$(xdp-tools_install_dir)' >> $(xdp-tools_install_log)
	@cd ${xdp-tools_src_dir} && \
		make libxdp_install V=1 BUILD_STATIC_ONLY=y PREFIX='' DESTDIR='$(xdp-tools_install_dir)' >> $(xdp-tools_install_log)
endef

$(eval $(call package,xdp-tools))
