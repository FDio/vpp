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

vpp_debug_TAG_BUILD_TYPE = debug
vpp_TAG_BUILD_TYPE = release
vpp_clang_TAG_BUILD_TYPE = release
vpp_gcov_TAG_BUILD_TYPE = gcov
vpp_coverity_TAG_BUILD_TYPE = coverity
