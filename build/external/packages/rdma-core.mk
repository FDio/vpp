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

rdma-core_version             := 23
rdma-core_tarball             := rdma-core-$(rdma-core_version).tar.gz
rdma-core_tarball_md5sum_22.1 := dde4d30e3db20893408ae51041117034
rdma-core_tarball_md5sum_23 := c78575735c4a71609c1a214ea16cd8dc
rdma-core_tarball_md5sum      := $(rdma-core_tarball_md5sum_$(rdma-core_version))
rdma-core_tarball_strip_dirs  := 1
rdma-core_url                 := http://github.com/linux-rdma/rdma-core/releases/download/v$(rdma-core_version)/$(rdma-core_tarball)

RDMA_BUILD_TYPE:=Release
ifeq ($(RDMA_CORE_DEBUG),y)
RDMA_BUILD_TYPE:=Debug
endif

RDMA_FILES := include/infiniband/verbs.h \
	      include/infiniband/verbs_api.h \
	      include/infiniband/ib_user_ioctl_verbs.h \
	      include/rdma/ib_user_verbs.h \
	      lib/statics/libibverbs.a \
	      lib/statics/libmlx5.a

define  rdma-core_config_cmds
	cd $(rdma-core_build_dir) && \
	  $(CMAKE) -G Ninja $(rdma-core_src_dir) \
	    -DENABLE_STATIC=1 -DENABLE_RESOLVE_NEIGH=0 -DNO_PYVERBS=1 -DENABLE_VALGRIND=0 \
	    -DCMAKE_BUILD_TYPE=$(RDMA_BUILD_TYPE) \
	    -DCMAKE_C_FLAGS='-fPIC -fvisibility=hidden' > $(rdma-core_config_log)
endef

define  rdma-core_build_cmds
	$(CMAKE) --build $(rdma-core_build_dir) -- libibverbs.a libmlx5.a > $(rdma-core_build_log)
endef

define  rdma-core_install_cmds
	mkdir -p $(rdma-core_install_dir)
	tar -C $(rdma-core_build_dir) --xform='s|/statics/|/|' -hc $(RDMA_FILES) | tar -C $(rdma-core_install_dir) -xv > $(rdma-core_install_log)
endef

$(eval $(call package,rdma-core))
