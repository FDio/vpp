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
arm32_arch = native
arm32_native_tools = vppapigen

arm32_uses_dpdk = no
arm32_uses_openssl = no

arm32_root_packages = vpp vlib vlib-api vnet svm vpp-api-test \
	vpp-japi gmod

vlib_configure_args_arm32 = --with-pre-data=128

vnet_configure_args_arm32 = --without-vcgn --without-ipsec --without-ipv6sr
vpp_configure_args_arm32 = --without-vcgn --without-ipsec --without-ipv6sr

arm32_debug_TAG_CFLAGS = -g -O0 -DCLIB_DEBUG -DFORTIFY_SOURCE=2 -DVLIB_MAX_CPUS=4 -march=armv7-a \
	-fstack-protector-all -fPIC -Werror
arm32_debug_TAG_LDFLAGS = -g -O0 -DCLIB_DEBUG -DFORTIFY_SOURCE=2 -DVLIB_MAX_CPUS=4 -march=armv7-a \
	-fstack-protector-all -fPIC -Werror

arm32_TAG_CFLAGS = -g -O2 -DFORTIFY_SOURCE=2 -DVLIB_MAX_CPUS=4 -march=armv7-a \
	-fstack-protector -fPIC -Werror
arm32_TAG_LDFLAGS = -g -O2 -DFORTIFY_SOURCE=2 -DVLIB_MAX_CPUS=4 -march=armv7-a \
	-fstack-protector -fPIC -Werror
