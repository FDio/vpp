# Copyright (c) 2020 Cisco and/or its affiliates.
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

DPDK_PKTMBUF_HEADROOM        ?= 128
DPDK_CACHE_LINE_SIZE         ?= 64
DPDK_DEBUG                   ?= n
DPDK_MLX4_PMD                ?= n
DPDK_MLX5_PMD                ?= n
DPDK_TAP_PMD                 ?= n
DPDK_FAILSAFE_PMD            ?= n

dpdk_version                 ?= 20.08
dpdk_base_url                ?= http://fast.dpdk.org/rel
dpdk_tarball                 := dpdk-$(dpdk_version).tar.xz
dpdk_tarball_md5sum_20.08    := 64badd32cd6bc0761befc8f2402c2148
dpdk_tarball_md5sum          := $(dpdk_tarball_md5sum_$(dpdk_version))
dpdk_url                     := $(dpdk_base_url)/$(dpdk_tarball)
dpdk_tarball_strip_dirs      := 1

DPDK_BUILD_TYPE:=release
ifeq ($(DPDK_DEBUG), y)
DPDK_BUILD_TYPE:=debug
endif

MACHINE=$(shell uname -m)

##############################################################################
# Intel x86
##############################################################################
ifeq ($(MACHINE),$(filter $(MACHINE),x86_64 i686))
DPDK_CPU_FAMILY       := x86_64
DPDK_MACHINE          ?= native
endif

DPDK_MESON_ARGS = \
	--default-library static \
	--libdir lib \
	--prefix $(dpdk_install_dir) \
	-Dtests=false \
	-Ddisable_drivers=event/\*,net/tap,net/af_xdp,net/bond,net/af_packet,baseband/\*,compress/\* \
	-Db_pie=true \
	-Dmachine=$(DPDK_MACHINE) \
	--buildtype=$(DPDK_BUILD_TYPE) 

define dpdk_config_cmds
	cd $(dpdk_build_dir) && \
	meson setup $(dpdk_src_dir) $(dpdk_build_dir) \
	$(DPDK_MESON_ARGS) > $(dpdk_config_log)
endef

define dpdk_build_cmds
	cd $(dpdk_build_dir) && \
	ninja $$(cat build.ninja | \
	 grep -E "^build .*\.a:" | \
	 awk '{print $$2}' | \
	 sed 's/://g' | \
	 grep -e pmd -e eal -e mbuf \
	 ) >$(dpdk_build_log)
endef

define dpdk_install_cmds
	cd $(dpdk_build_dir) && \
	meson introspect --installed -i | \
	grep ": " | sed 's/:/ /g' | sed 's/,//g' | sed 's/"//g'| \
	while read l; \
	do \
	if ls $$(echo $$l | awk '{print $$1}') 1>/dev/null 2> /dev/null ; \
	then echo $$l; fi done | \
	grep -v examples > install_plan && \
	cat install_plan | awk '{print $$2}' | \
	while read l; do echo $$(dirname $$l); done | \
	sort | uniq | while read l; do mkdir -p $$l; done && \
	cat install_plan | while read l; do cp -r $$l; done && \
	cd $(dpdk_install_dir)/lib && \
	echo "GROUP ( $$(ls librte*.a ) )" > $(dpdk_install_dir)/lib/libdpdk.a && \
	rm -f install_plan
endef

$(eval $(call package,dpdk))