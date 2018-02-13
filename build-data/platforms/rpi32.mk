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
rpi32_arch = native
rpi32_native_tools = vppapigen

rpi32_uses_dpdk = yes
rpi32_uses_openssl = no

rpi32_root_packages = vpp vlib vlib-api vnet svm vpp-api-test \
	jvpp gmod

vlib_configure_args_rpi32 = --with-pre-data=128
vnet_configure_args_rpi32 = --with-dpdk --without-libssl
vpp_configure_args_rpi32 = --with-dpdk --without-libssl

rpi32_dpdk_arch = "armv7a"
rpi32_dpdk_target = "arm-armv7a-linuxapp-gcc"
rpi32_dpdk_make_extra_args = "CPU_CFLAGS='-mfloat-abi=hard' \
	CONFIG_RTE_EAL_IGB_UIO=n \
	CONFIG_RTE_LIBRTE_E1000_PMD=n \
	CONFIG_RTE_ARCH_ARM_TUNE=arm7 \
	CONFIG_RTE_LIBRTE_PMD_VHOST=n \
	CONFIG_RTE_LIBRTE_VIRTIO_PMD=n \
	CONFIG_RTE_LIBRTE_PMD_SOFTNIC=y \
	CONFIG_RTE_APP_CRYPTO_PERF=n \
	CONFIG_RTE_APP_EVENTDEV=n \
	CONFIG_RTE_MAX_LCORE=4 \
	CONFIG_RTE_MAX_NUMA_NODES=1"


rpi32_debug_TAG_CFLAGS = -g -O0 -DCLIB_DEBUG -DFORTIFY_SOURCE=2 -DVLIB_MAX_CPUS=4 -DRASPBERRY_PI_32 -march=armv7-a \
	-fstack-protector-all -fPIC -Werror
rpi32_debug_TAG_LDFLAGS = -g -O0 -DCLIB_DEBUG -DFORTIFY_SOURCE=2 -DVLIB_MAX_CPUS=4 -DRASPBERRY_PI_32 -march=armv7-a \
	-fstack-protector-all -fPIC -Werror

rpi32_TAG_CFLAGS = -g -O2 -DFORTIFY_SOURCE=2 -DVLIB_MAX_CPUS=4 -DRASPBERRY_PI_32 -march=armv7-a \
	-fstack-protector -fPIC -Werror
rpi32_TAG_LDFLAGS = -g -O2 -DFORTIFY_SOURCE=2 -DVLIB_MAX_CPUS=4 -DRASPBERRY_PI_32 -march=armv7-a \
	-fstack-protector -fPIC -Werror

# disable building VPP object model and java api
vpp_configure_args_rpi32 += --disable-vom --disable-japi
