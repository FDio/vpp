# Copyright (c) 2019 Cisco and/or its affiliates.
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

quicly_version := 0.1.2-vpp
quicly_tarball := quicly_$(quicly_version).tar.gz
quicly_tarball_md5sum := 5b184b1733ba027843ab6605d931f752
quicly_tarball_strip_dirs := 1
quicly_url := https://github.com/vpp-quic/quicly/releases/download/v$(quicly_version)/quicly_$(quicly_version).tar.gz

picotls_build_dir := $(B)/build-picotls

define  quicly_build_cmds
	@cd $(quicly_build_dir) && \
		$(CMAKE) -DWITH_DTRACE=OFF -DCMAKE_INSTALL_PREFIX:PATH=$(quicly_install_dir) \
		$(quicly_src_dir) > $(quicly_build_log)
	@$(MAKE) $(MAKE_ARGS) -C $(quicly_build_dir) > $(quicly_build_log)

	@mkdir -p $(picotls_build_dir)
	@cd $(picotls_build_dir) && \
		$(CMAKE) -DWITH_DTRACE=OFF -DCMAKE_INSTALL_PREFIX:PATH=$(quicly_install_dir) \
		$(quicly_src_dir)/deps/picotls > $(quicly_build_log)
endef

define  quicly_config_cmds
	@true
endef

define  quicly_install_cmds
	@$(MAKE) $(MAKE_ARGS) -C $(quicly_build_dir) install > $(quicly_install_log)
	@$(MAKE) $(MAKE_ARGS) -C $(picotls_build_dir) install > $(quicly_install_log)
endef


$(eval $(call package,quicly))
