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
vpp_native_tools = vppapigen

vpp_root_packages = vpp vlib vlib-api vnet svm dpdk vpp-api-test \
	vpp-japi gmod

vpp_configure_args_vpp = --with-dpdk
vnet_configure_args_vpp = --with-dpdk

# Set these parameters carefully. The vlib_buffer_t is 128 bytes, i.e.
# dpdk_headroom = uiotarball_headroom = vlib_pre_data + 128
dpdk_configure_args_vpp = --with-headroom=256
vlib_configure_args_vpp = --with-pre-data=128


vpp_debug_TAG_CFLAGS = -g -O0 -DCLIB_DEBUG -DFORTIFY_SOURCE=2 -march=$(MARCH) \
	-fstack-protector-all -fPIC -Werror
vpp_debug_TAG_LDFLAGS = -g -O0 -DCLIB_DEBUG -DFORTIFY_SOURCE=2 -march=$(MARCH) \
	-fstack-protector-all -fPIC -Werror

vpp_TAG_CFLAGS = -g -O2 -DFORTIFY_SOURCE=2 -march=$(MARCH) \
	-fstack-protector -fPIC -Werror
vpp_TAG_LDFLAGS = -g -O2 -DFORTIFY_SOURCE=2 -march=$(MARCH) \
	-fstack-protector -fPIC -Werror
