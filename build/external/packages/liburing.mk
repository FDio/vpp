# Copyright (c) 2026 Moinak Bhattacharyya <moinakb001@gmail.com>
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

liburing_version             := 2.13
liburing_tarball             := liburing-$(liburing_version).tar.gz
liburing_tarball_sha256sum_2.13 := 9a4339ffc40df178c4ddf919cb2b23585a75b3023517c75e82c4dfb0899249c7

liburing_tarball_sha256sum      := $(liburing_tarball_sha256sum_$(liburing_version))
liburing_tarball_strip_dirs  := 1
liburing_url                 := https://github.com/axboe/liburing/archive/refs/tags/$(liburing_tarball)

define  liburing_config_cmds
	@true
endef

define  liburing_build_cmds
	@cd ${liburing_src_dir} && $(MAKE) CC=gcc CXX=g++ > $(liburing_build_log)
endef

define  liburing_install_cmds
	@rm -f $(liburing_install_log)
	@cd ${liburing_src_dir} && \
		$(MAKE) install PREFIX='$(liburing_install_dir)' >> $(liburing_install_log)
endef

$(eval $(call package,liburing))
