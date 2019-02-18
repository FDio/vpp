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

rdma-core_version             := 22.1
rdma-core_tarball             := rdma-core-$(rdma-core_version).tar.gz
rdma-core_tarball_md5sum_22.1 := dde4d30e3db20893408ae51041117034
rdma-core_tarball_md5sum      := $(rdma-core_tarball_md5sum_$(rdma-core_version))
rdma-core_tarball_strip_dirs  := 1
rdma-core_url                 := http://github.com/linux-rdma/rdma-core/releases/download/v$(rdma-core_version)/$(rdma-core_tarball)

define  rdma-core_config_cmds
	cd $(rdma-core_build_dir)
	cmake -G Ninja $(rdma-core_src_dir) -DENABLE_STATIC=1 -DENABLE_RESOLVE_NEIGH=0 -DNO_PYVERBS=1 -DCMAKE_INSTALL_PREFIX:PATH=$(rdma-core_install_dir) -DCMAKE_INSTALL_RPATH:PATH=$(rdma-core_install_dir)/lib -DCMAKE_C_FLAGS=-fPIC
endef

define  rdma-core_build_cmds
	cd $(rdma-core_build_dir)
     	cmake --build .
endef

define  rdma-core_install_cmds
	cd $(rdma-core_build_dir)
	cmake --build . -- install
endef

$(eval $(call package,rdma-core))
