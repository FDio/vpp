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

# Qemu "p-series" powerpc64 

qppc_os = linux-gnu

qppc_cross_ldflags = \
    -Wl,--dynamic-linker=/lib64/ld64.so.1

qppc_arch = powerpc

qppc_root_packages = vppinfra vlib vlib-api vnet svm \
	vpp vpp-api-test

vnet_configure_args_qppc = \
	--without-libssl

vpp_configure_args_qppc = \
	--without-libssl

vlib_configure_args_qppc = --with-pre-data=128

qppc_march=powerpc64

# native tool chain additions for this platform
qppc_native_tools = vppapigen

qppc_uses_dpdk = no

qppc_debug_TAG_CFLAGS = -m64 -g -O0 -DCLIB_DEBUG -DCLIB_LOG2_CACHE_LINE_BYTES=6 -maltivec
qppc_debug_TAG_LDFLAGS = -m64 -g -O0 -DCLIB_DEBUG -DCLIB_LOG2_CACHE_LINE_BYTES=6 -maltivec

qppc_TAG_CFLAGS = -m64 -g -O2 -DCLIB_LOG2_CACHE_LINE_BYTES=6 -maltivec
qppc_TAG_LDFLAGS = -m64 -g -O2 -DCLIB_LOG2_CACHE_LINE_BYTES=6 -maltivec


