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

# NOTE: When updating the rdma-core version in conjunction with an update of the
#       dpdk version, please update ../mlx_rdma_dpdk_matrix.txt to include the
#       updated version matrix with the dpdk and rdma-core version.
#
#       Also, please verify that the DPDK RDMA driver is built into the dpdk plugin
#       as follows:
#       	1. from workspace root directory, 'make -C build/external build-deb'
#       	2. Verify that the file build/external/dpdk_mlx_default.sh was generated
#              and contains 'DPDK_MLX_DEFAULT=y'
#
rdma-core_version             := 52.0
rdma-core_tarball             := rdma-core-$(rdma-core_version).tar.gz
rdma-core_tarball_md5sum_49.0 := 9fe3909f19c7e0276c9e546411bbb49c
rdma-core_tarball_md5sum_51.0 := ed95d79f782ea00bd7233d453abd60b3
rdma-core_tarball_sha256sum_51.0 := 0a4a55b1351356c2750f26ec9010e8c7370402a13c95799cb8b447cf0134dd61
rdma-core_tarball_md5sum_52.0 := c78dba484aac72eb8586d88f7b399b0f
rdma-core_tarball_sha256sum_52.o := 1f0ce5f2462c982b20d21156707076278807a7adf4d10e9142f3be4bec1b2b83
rdma-core_tarball_md5sum      := $(rdma-core_tarball_md5sum_$(rdma-core_version))
rdma-core_tarball_sha256sum      := $(rdma-core_tarball_sha256sum_$(rdma-core_version))
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
	    -DCMAKE_INSTALL_RUNDIR:PATH=/run \
	    -DCMAKE_C_FLAGS='-fPIC' -DNO_MAN_PAGES=ON | tee $(rdma-core_config_log)
endef

define  rdma-core_build_cmds
	$(CMAKE) --build $(rdma-core_build_dir) | tee $(rdma-core_build_log)
endef

define  rdma-core_install_cmds
	$(CMAKE) --install $(rdma-core_build_dir) | tee $(rdma-core_install_log)
endef

$(eval $(call package,rdma-core))
