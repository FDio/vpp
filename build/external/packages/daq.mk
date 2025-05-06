# Copyright (c) 2025 Cisco and/or its affiliates.
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

daq_version             := 3.0.21
daq_tarball             := daq-$(daq_version).tar.gz
daq_tarball_sha256sum_3.0.21 := 60ad9405c1c6b75955e0784511b173570a601491ccdb6399da53ca811c446a96
daq_tarball_sha256sum      := $(daq_tarball_sha256sum_$(daq_version))
daq_tarball_strip_dirs  := 1
daq_url                 := https://github.com/snort3/libdaq/archive/refs/tags/v$(daq_version).tar.gz

define  daq_config_cmds
       	@rm -f $(daq_config_log)
        @cd ${daq_src_dir} && ./bootstrap > $(daq_config_log) 2>&1
	@cd ${daq_src_dir} && ./configure --prefix='$(daq_install_dir)' --enable-shared --enable-static \
                --disable-bundled-modules \
		CFLAGS='' \
		>> $(daq_config_log) 2>&1
endef

define  daq_build_cmds
	@cd ${daq_src_dir} && $(MAKE) V=1 > $(daq_build_log)
endef

define  daq_install_cmds
	@rm -f $(daq_install_log)
	@cd ${daq_src_dir} && \
		$(MAKE) install V=1 PREFIX='$(daq_install_dir)' >> $(daq_install_log)
endef

$(eval $(call package,daq))
