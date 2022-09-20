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

RDMA_CORE_DEBUG?=n

rdma-core_version             := 41.0
rdma-core_tarball             := rdma-core-$(rdma-core_version).tar.gz
rdma-core_tarball_md5sum_39.1 := 63ba4632fd01173a2331e5b990373330
rdma-core_tarball_md5sum_41.0 := 2250389cb61a7130133e6411fdeef2f9
rdma-core_tarball_md5sum      := $(rdma-core_tarball_md5sum_$(rdma-core_version))
rdma-core_tarball_strip_dirs  := 1
rdma-core_url                 := http://github.com/linux-rdma/rdma-core/releases/download/v$(rdma-core_version)/$(rdma-core_tarball)

RDMA_BUILD_TYPE:=RelWithDebInfo
ifeq ($(RDMA_CORE_DEBUG),y)
RDMA_BUILD_TYPE:=Debug
endif

define  rdma-core_config_cmds
	cd $(rdma-core_build_dir) && \
	  $(CMAKE) -G Ninja $(rdma-core_src_dir) \
	    -DENABLE_STATIC=1 -DENABLE_RESOLVE_NEIGH=0 -DNO_PYVERBS=1 -DENABLE_VALGRIND=0\
	    -DCMAKE_BUILD_TYPE=$(RDMA_BUILD_TYPE) -DCMAKE_INSTALL_PREFIX=$(rdma-core_install_dir) \
	    -DCMAKE_INSTALL_LIBDIR=lib \
	    -DCMAKE_C_FLAGS='-fPIC' -DNO_MAN_PAGES=ON > $(rdma-core_config_log)
endef

define  rdma-core_build_cmds
	$(CMAKE) --build $(rdma-core_build_dir) > $(rdma-core_build_log)
endef

define  rdma-core_install_cmds
	$(CMAKE) --install $(rdma-core_build_dir) > $(rdma-core_install_log)
endef

$(eval $(call package,rdma-core))
