# Copyright (c) 2020 Cisco and/or its affiliates.
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

srtp_version := 2.3.0
srtp_tarball := srtp_$(srtp_version).tar.gz
srtp_tarball_md5sum := da38ee5d9c31be212a12964c22d7f795
srtp_tarball_strip_dirs := 1
srtp_url := https://github.com/cisco/libsrtp/archive/v$(srtp_version).tar.gz

define  srtp_build_cmds
	@cd $(srtp_build_dir) && \
		$(CMAKE) -DCMAKE_INSTALL_PREFIX:PATH=$(srtp_install_dir)	\
		-DCMAKE_C_FLAGS='-fPIC -fvisibility=hidden'  $(srtp_src_dir) > $(srtp_build_log)
	@$(MAKE) $(MAKE_ARGS) -C $(srtp_build_dir) > $(srtp_build_log)
endef

define  srtp_config_cmds
	@true
endef

define  srtp_install_cmds
	@$(MAKE) $(MAKE_ARGS) -C $(srtp_build_dir) install > $(srtp_install_log)
endef


$(eval $(call package,srtp))