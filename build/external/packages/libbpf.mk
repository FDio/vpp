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

LIBBPF_DEBUG?=n

libbpf_version             := 0.1.0
libbpf_tarball             := v$(libbpf_version).tar.gz
libbpf_tarball_md5sum_0.1.0 := 00b991a6e2d28d797a56ab1575ed40e1
libbpf_tarball_md5sum      := $(libbpf_tarball_md5sum_$(libbpf_version))
libbpf_tarball_strip_dirs  := 1
libbpf_url                 := https://github.com/libbpf/libbpf/archive/$(libbpf_tarball)

LIBBPF_CFLAGS:=-g -Werror -Wall -fPIC -fvisibility=hidden
ifeq ($(LIBBPF_DEBUG),y)
  LIBBPF_CFLAGS+= -O0
else
  LIBBPF_CFLAGS+= -O2
endif

# check for libelf, zlib and kernel if_xdp.h presence
LIBBPF_DEPS_CHECK:="\#include <linux/if_xdp.h>\\n\#include <gelf.h>\\n\#include <zlib.h>\\nint main(void){return 0;}"
LIBBPF_DEPS_CHECK:=$(shell echo -e $(LIBBPF_DEPS_CHECK) | $(CC) -xc -lelf -lz -o /dev/null - > /dev/null 2>&1)
LIBBPF_DEPS_CHECK:=$(.SHELLSTATUS)

define  libbpf_config_cmds
	@true
endef

define  libbpf_build_cmds__
	BUILD_STATIC_ONLY=y OBJDIR='$(libbpf_build_dir)' PREFIX='' DESTDIR='$(libbpf_install_dir)' CFLAGS='$(LIBBPF_CFLAGS)' make -C '$(libbpf_src_dir)/src' $(1) > $(2)
endef

define  libbpf_build_cmds
	$(call libbpf_build_cmds__,,$(libbpf_build_log))
endef

define  libbpf_install_cmds
	$(call libbpf_build_cmds__,install,$(libbpf_install_log))
endef

ifneq ($(LIBBPF_DEPS_CHECK),0)
  $(warning "Missing libbpf dependencies. libbpf will be skipped.")
libbpf-install:
	@true
else
  $(eval $(call package,libbpf))
endif
