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
vpp_arch = native
ifeq ($(shell uname -m),x86_64)
vpp_march = corei7			# Nehalem Instruction set
vpp_mtune = corei7-avx			# Optimize for Sandy Bridge
vpp_dpdk_arch = corei7
else
vpp_march = native
vpp_mtune = generic
vpp_dpdk_arch = native
endif
vpp_native_tools = vppapigen

vpp_uses_dpdk = yes

# Uncoment to enable building unit tests
# vpp_enable_tests = yes

vpp_root_packages = vpp vlib vlib-api vnet svm vpp-api-test \
	vpp-api gmod

vpp_configure_args_vpp = --with-dpdk
vnet_configure_args_vpp = --with-dpdk

# Set these parameters carefully. The vlib_buffer_t is 128 bytes, i.e.
vlib_configure_args_vpp = --with-pre-data=128

# DPDK configuration parameters
# vpp_uses_external_dpdk = yes
# vpp_dpdk_inc_dir = /usr/include/dpdk
# vpp_dpdk_lib_dir = /usr/lib
# vpp_dpdk_shared_lib = yes

vpp_debug_TAG_CFLAGS = -g -O0 -DCLIB_DEBUG -DFORTIFY_SOURCE=2 -march=$(MARCH) \
	-fstack-protector-all -fPIC -Werror
vpp_debug_TAG_LDFLAGS = -g -O0 -DCLIB_DEBUG -DFORTIFY_SOURCE=2 -march=$(MARCH) \
	-fstack-protector-all -fPIC -Werror

vpp_TAG_CFLAGS = -g -O2 -DFORTIFY_SOURCE=2 -march=$(MARCH) -mtune=$(MTUNE) \
	-fstack-protector -fPIC -Werror
vpp_TAG_LDFLAGS = -g -O2 -DFORTIFY_SOURCE=2 -march=$(MARCH) -mtune=$(MTUNE) \
	-fstack-protector -fPIC -Werror

vpp_gcov_TAG_CFLAGS = -g -O0 -DCLIB_DEBUG -march=$(MARCH) \
	-fPIC -Werror -fprofile-arcs -ftest-coverage
vpp_gcov_TAG_LDFLAGS = -g -O0 -DCLIB_DEBUG -march=$(MARCH) \
	-fPIC -Werror -coverage
