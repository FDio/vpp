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

indent_version            := 2.2.11
indent_tarball            := indent-$(indent_version).tar.gz
indent_tarball_md5sum_2.2.10 := be35ea62705733859fbf8caf816d8959
indent_tarball_md5sum_2.2.11 := 98beafca62472805a3739d3867d5d70f
indent_tarball_md5sum_2.2.12 := 4764b6ac98f6654a35da117b8e5e8e14
indent_tarball_md5sum      := $(indent_tarball_md5sum_$(indent_version))
indent_tarball_strip_dirs := 1
indent_url                := https://ftpmirror.gnu.org/indent/$(indent_tarball)
indent_cflags             := -D HAVE_LOCALE_H=1 

define  indent_config_cmds
        mkdir $(indent_build_dir)/regression
	cp $(indent_src_dir)/regression/Makefile $(indent_build_dir)/regression/
        cd $(indent_build_dir) && \
          CFLAGS="$(indent_cflags) -I$(indent_build_dir) -I$(indent_src_dir) -I$(indent_src_dir)/intl" \
          $(indent_src_dir)/configure \
            --prefix=$(indent_install_dir) \
            $(indent_configure_args) > $(indent_config_log)
endef


$(eval $(call package,indent))
