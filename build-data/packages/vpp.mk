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

vpp_source = src

ifeq ($($(PLATFORM)_dpdk_shared_lib),yes)
vpp_configure_args = --enable-dpdk-shared
else
vpp_configure_args =
endif

# Platform dependent configure flags
vpp_configure_args += $(vpp_configure_args_$(PLATFORM))


vpp_CPPFLAGS =
vpp_LDFLAGS =

ifneq ($($(PLATFORM)_uses_dpdk),no)
ifeq ($($(PLATFORM)_uses_external_dpdk),yes)
vpp_CPPFLAGS += -I$($(PLATFORM)_dpdk_inc_dir)
vpp_LDFLAGS += -L$($(PLATFORM)_dpdk_lib_dir)
else
vpp_configure_depend += dpdk-install
vpp_CPPFLAGS += $(call installed_includes_fn, dpdk)/dpdk
vpp_LDFLAGS += $(call installed_libs_fn, dpdk)
vpp_CPPFLAGS += -I/usr/include/dpdk
endif
ifeq ($($(PLATFORM)_uses_dpdk_mlx5_pmd),yes)
vpp_configure_args += --with-dpdk-mlx5-pmd
endif
ifeq ($($(PLATFORM)_uses_dpdk_mlx4_pmd),yes)
vpp_configure_args += --with-dpdk-mlx4-pmd
endif
else
vpp_configure_args += --disable-dpdk-plugin
endif

ifeq ($($(PLATFORM)_enable_tests),yes)
vpp_configure_args += --enable-tests
endif
