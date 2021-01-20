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

arm32_uses_dpdk = yes
arm32_uses_openssl = no

arm32_root_packages = vpp vlib vlib-api vnet svm vpp-api-test \
	gmod

vlib_configure_args_arm32 = --with-pre-data=128
vnet_configure_args_arm32 = --with-dpdk --without-libssl
vpp_configure_args_arm32 = --with-dpdk --without-libssl

arm32_dpdk_arch = "armv7a"
arm32_dpdk_target = "arm-armv7a-linuxapp-gcc"
arm32_dpdk_make_extra_args = "CPU_CFLAGS='-mfloat-abi=hard' \
	CONFIG_RTE_EAL_IGB_UIO=y \
	CONFIG_RTE_LIBRTE_E1000_PMD=y \
	CONFIG_RTE_MAX_LCORE=4 \
	CONFIG_RTE_MAX_NUMA_NODES=1"


arm32_debug_TAG_CFLAGS = -g -O0 -DCLIB_DEBUG -D_FORTIFY_SOURCE=2 -DVLIB_MAX_CPUS=4 -march=armv7-a \
	-fstack-protector-all -fPIC -Werror
arm32_debug_TAG_LDFLAGS = -g -O0 -DCLIB_DEBUG -D_FORTIFY_SOURCE=2 -DVLIB_MAX_CPUS=4 -march=armv7-a \
	-fstack-protector-all -fPIC -Werror

arm32_TAG_CFLAGS = -g -O2 -D_FORTIFY_SOURCE=2 -DVLIB_MAX_CPUS=4 -march=armv7-a \
	-fstack-protector -fPIC -Werror
arm32_TAG_LDFLAGS = -g -O2 -D_FORTIFY_SOURCE=2 -DVLIB_MAX_CPUS=4 -march=armv7-a \
	-fstack-protector -fPIC -Werror
