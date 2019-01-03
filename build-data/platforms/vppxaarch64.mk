# Copyright (c) 2015 Cisco and/or its affiliates.
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

# vector packet processor

MACHINE=aarch64
vppxaarch64_dpkg_build_args=-aarm64
vppxaarch64_cmake_args += -DCMAKE_TOOLCHAIN_FILE="$(MU_BUILD_ROOT_DIR)/../build-data/platforms/xcompile-aarch64.txt"

vppxaarch64_arch = native
ifeq ($(TARGET_PLATFORM),thunderx)
vppxaarch64_dpdk_target = arm64-thunderx-linuxapp-gcc
endif

vppxaarch64_root_packages = vppxaarch64

vppxaarch64_debug_TAG_CFLAGS = -g -O0 -DCLIB_DEBUG -DFORTIFY_SOURCE=2 \
	-fstack-protector-all -fPIC -Werror -Wno-unused-value
vppxaarch64_debug_TAG_CXXFLAGS = -g -O0 -DCLIB_DEBUG -DFORTIFY_SOURCE=2 \
	-fstack-protector-all -fPIC -Werror 
vppxaarch64_debug_TAG_LDFLAGS = -g -O0 -DCLIB_DEBUG -DFORTIFY_SOURCE=2 \
	-fstack-protector-all -fPIC -Werror

vppxaarch64_TAG_CFLAGS = -g -O2 -DFORTIFY_SOURCE=2 -fstack-protector -fPIC -Werror
vppxaarch64_TAG_CXXFLAGS = -g -O2 -DFORTIFY_SOURCE=2 -fstack-protector -fPIC -Werror
vppxaarch64_TAG_LDFLAGS = -g -O2 -DFORTIFY_SOURCE=2 -fstack-protector -fPIC -Werror -pie -Wl,-z,now

vppxaarch64_clang_TAG_CFLAGS = -g -O2 -DFORTIFY_SOURCE=2 -fstack-protector -fPIC -Werror
vppxaarch64_clang_TAG_CXXFLAGS = -g -O2 -DFORTIFY_SOURCE=2 -fstack-protector -fPIC -Werror
vppxaarch64_clang_TAG_LDFLAGS = -g -O2 -DFORTIFY_SOURCE=2 -fstack-protector -fPIC -Werror

vppxaarch64_gcov_TAG_CFLAGS = -g -O0 -DCLIB_DEBUG -fPIC -Werror -fprofile-arcs -ftest-coverage
vppxaarch64_gcov_TAG_LDFLAGS = -g -O0 -DCLIB_DEBUG -fPIC -Werror -coverage

vppxaarch64_coverity_TAG_CFLAGS = -g -O2 -fPIC -Werror -D__COVERITY__
vppxaarch64_coverity_TAG_LDFLAGS = -g -O2 -fPIC -Werror -D__COVERITY__

