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

MACHINE=$(shell uname -m)

vpp_arch = native
ifeq ($(TARGET_PLATFORM),thunderx)
vpp_dpdk_target = arm64-thunderx-linuxapp-gcc
endif

vpp_root_packages = vpp vom

vpp_common_cflags = \
	-g \
	-DFORTIFY_SOURCE=2 \
	-fstack-protector \
	-fPIC \
	-Wall \
	-Werror \
	-fno-common

vpp_debug_TAG_CFLAGS = -O0 -DCLIB_DEBUG $(vpp_common_cflags)
vpp_debug_TAG_CXXFLAGS = -O0 -DCLIB_DEBUG $(vpp_common_cflags)
vpp_debug_TAG_LDFLAGS = -O0 -DCLIB_DEBUG $(vpp_common_cflags)

vpp_TAG_CFLAGS = -O2 $(vpp_common_cflags)
vpp_TAG_CXXFLAGS = -O2 $(vpp_common_cflags)
vpp_TAG_LDFLAGS = -O2 $(vpp_common_cflags) -pie

vpp_clang_TAG_CFLAGS = -O2 $(vpp_common_cflags)
vpp_clang_TAG_CXXFLAGS = -O2 $(vpp_common_cflags)
vpp_clang_TAG_LDFLAGS = -O2 $(vpp_common_cflags)

vpp_gcov_TAG_CFLAGS = -g -O0 -DCLIB_DEBUG -DCLIB_GCOV -fPIC -Werror -fprofile-arcs -ftest-coverage
vpp_gcov_TAG_LDFLAGS = -g -O0 -DCLIB_DEBUG -DCLIB_GCOV -fPIC -Werror -coverage

vpp_coverity_TAG_CFLAGS = -g -O2 -fPIC -Werror -D__COVERITY__
vpp_coverity_TAG_LDFLAGS = -g -O2 -fPIC -Werror -D__COVERITY__
