# Copyright (c) 2019 PANTHEON.tech s.r.o. and/or its affiliates.
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

# aarch64

aarch64_arch = aarch64
aarch64_os = linux
aarch64_target = aarch64-linux-gnu
aarch64_march = armv8-a

aarch64_native_tools = vppapigen
aarch64_cross_tools = libnuma openssl

aarch64_root_packages = vpp vlib vlib-api vnet svm vpp-api-test gmod vom

aarch64_debug_TAG_CFLAGS = -g -O0 -DCLIB_DEBUG -DFORTIFY_SOURCE=2 \
        -fstack-protector-all -fPIC -Werror
aarch64_debug_TAG_CXXFLAGS = -g -O0 -DCLIB_DEBUG -DFORTIFY_SOURCE=2 \
        -fstack-protector-all -fPIC -Werror
aarch64_debug_TAG_LDFLAGS = -g -O0 -DCLIB_DEBUG -DFORTIFY_SOURCE=2 \
        -fstack-protector-all -fPIC -Werror

aarch64_TAG_CFLAGS = -g -O2 -DFORTIFY_SOURCE=2 -fstack-protector -fPIC -Werror
aarch64_TAG_CXXFLAGS = -g -O2 -DFORTIFY_SOURCE=2 -fstack-protector -fPIC -Werror
aarch64_TAG_LDFLAGS = -g -O2 -DFORTIFY_SOURCE=2 -fstack-protector -fPIC -Werror -pie

aarch64_clang_TAG_CFLAGS = -g -O2 -DFORTIFY_SOURCE=2 -fstack-protector -fPIC -Werror
aarch64_clang_TAG_CXXFLAGS = -g -O2 -DFORTIFY_SOURCE=2 fstack-protector -fPIC -Werror
aarch64_clang_TAG_LDFLAGS = -g -O2 -DFORTIFY_SOURCE=2 -fstack-protector -fPIC -Werror

aarch64_dpdk_target = arm64-armv8a-linuxapp-gcc
aarch64_dpdk_machine = armv8a
aarch64_dpdk_tune = generic

#aarch64_dpdk_cross = aarch64-linux-gnu-
aarch64_dpdk_make_extra_args = CROSS=aarch64-linux-gnu- CONFIG_RTE_KNI_KMOD=n CONFIG_RTE_EAL_IGB_UIO=n
aarch64_dpdk_extra_cflags = -isystem /home/jlinkes/cross-compile/include
aarch64_dpdk_extra_ldflags = -L/home/jlinkes/cross-compile/lib -lnuma
