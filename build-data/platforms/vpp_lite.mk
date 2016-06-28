# Copyright (c) 2016 Cisco and/or its affiliates.
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
vpp_lite_arch = native
ifeq ($(shell uname -m),x86_64)
vpp_lite_march = corei7				# Nehalem Instruction set
vpp_lite_mtune = corei7-avx			# Optimize for Sandy Bridge
else
vpp_lite_march = native
vpp_lite_mtune = generic
endif
vpp_lite_native_tools = vppapigen

vpp_lite_uses_dpdk = no

vpp_lite_root_packages = vpp vlib vlib-api vnet svm vpp-api-test \
	vpp-api gmod

vlib_configure_args_vpp_lite = --with-pre-data=128

vnet_configure_args_vpp_lite =
vpp_configure_args_vpp_lite =

vpp_lite_debug_TAG_CFLAGS = -g -O0 -DCLIB_DEBUG -DFORTIFY_SOURCE=2 -march=$(MARCH) \
	-fstack-protector-all -fPIC -Werror
vpp_lite_debug_TAG_LDFLAGS = -g -O0 -DCLIB_DEBUG -DFORTIFY_SOURCE=2 -march=$(MARCH) \
	-fstack-protector-all -fPIC -Werror

vpp_lite_TAG_CFLAGS = -g -O2 -DFORTIFY_SOURCE=2 -march=$(MARCH) -mtune=$(MTUNE) \
	-fstack-protector -fPIC -Werror
vpp_lite_TAG_LDFLAGS = -g -O2 -DFORTIFY_SOURCE=2 -march=$(MARCH) -mtune=$(MTUNE) \
	-fstack-protector -fPIC -Werror
