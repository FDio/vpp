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

rdma-core_version             := 31.1
rdma-core_tarball             := rdma-core-$(rdma-core_version).tar.gz
rdma-core_tarball_md5sum_31.0 := 6076b2cfd5b0b22b88f1fb8dffd1aef7
rdma-core_tarball_md5sum_31.1 := f14b3eba775c2eba0d9433bfb3bae637
rdma-core_tarball_md5sum      := $(rdma-core_tarball_md5sum_$(rdma-core_version))
rdma-core_tarball_strip_dirs  := 1
rdma-core_url                 := http://github.com/linux-rdma/rdma-core/releases/download/v$(rdma-core_version)/$(rdma-core_tarball)

RDMA_BUILD_TYPE:=RelWithDebInfo
ifeq ($(RDMA_CORE_DEBUG),y)
RDMA_BUILD_TYPE:=Debug
endif

BUILD_FILES := include/ \
	       lib/statics/libibverbs.a \
	       lib/statics/libmlx5.a \
	       lib/statics/libmlx4.a \
	       lib/pkgconfig/ \
	       util/librdma_util.a \
	       ccan/libccan.a

define  rdma-core_config_cmds
	cd $(rdma-core_build_dir) && \
	  $(CMAKE) -G Ninja $(rdma-core_src_dir) \
	    -DENABLE_STATIC=1 -DENABLE_RESOLVE_NEIGH=0 -DNO_PYVERBS=1 -DENABLE_VALGRIND=0\
	    -DCMAKE_BUILD_TYPE=$(RDMA_BUILD_TYPE) -DCMAKE_INSTALL_PREFIX=$(rdma-core_install_dir) \
	    -DCMAKE_C_FLAGS='-fPIC -fvisibility=hidden' > $(rdma-core_config_log)
endef

define  rdma-core_build_cmds
	$(CMAKE) --build $(rdma-core_build_dir) -- libccan.a libibverbs.a librdma_util.a libmlx5.a libmlx4.a > $(rdma-core_build_log)
endef

define  rdma-core_install_cmds
	mkdir -p $(rdma-core_install_dir)
	tar -C $(rdma-core_build_dir) -hc $(BUILD_FILES) | tar -C $(rdma-core_install_dir) -xv > $(rdma-core_install_log)
	find $(rdma-core_install_dir) -name '*.a' -exec mv -v {} $(rdma-core_install_dir)/lib \; >> $(rdma-core_install_log)
	rmdir -v $(rdma-core_install_dir)/util $(rdma-core_install_dir)/lib/statics >> $(rdma-core_install_log)
	sed '/Libs.private:/ s/$$/ -lrdma_util -lccan/' -i $(rdma-core_install_dir)/lib/pkgconfig/libibverbs.pc
endef

$(eval $(call package,rdma-core))
