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
DPDK_DEBUG                   ?= n
DPDK_MLX4_PMD                ?= n
DPDK_MLX5_PMD                ?= n
DPDK_MLX5_COMMON_PMD         ?= n
DPDK_TAP_PMD                 ?= n
DPDK_FAILSAFE_PMD            ?= n

dpdk_version                 ?= 20.08
dpdk_base_url                ?= http://fast.dpdk.org/rel
dpdk_tarball                 := dpdk-$(dpdk_version).tar.xz
dpdk_tarball_md5sum_20.08    := 64badd32cd6bc0761befc8f2402c2148
dpdk_tarball_md5sum          := $(dpdk_tarball_md5sum_$(dpdk_version))
dpdk_url                     := $(dpdk_base_url)/$(dpdk_tarball)
dpdk_tarball_strip_dirs      := 1

# Debug or release

DPDK_BUILD_TYPE:=release
ifeq ($(DPDK_DEBUG), y)
DPDK_BUILD_TYPE:=debug
endif

# Machine specific: for each architecture
# choose the most generically supported Instruction Set
MACHINE=$(shell uname -m)

##############################################################################
# Intel x86
##############################################################################
ifeq ($(MACHINE),$(filter $(MACHINE),x86_64 i686))
DPDK_MACHINE          ?= nehalem
endif

DPDK_DRIVERS_DISABLED := baseband/\*,	\
	bus/dpaa,							\
	bus/ifpga,							\
	compress/\*,						\
	crypto/ccp,							\
	crypto/dpaa_sec,					\
	crypto/openssl,						\
	event/\*,							\
	mempool/dpaa,						\
	net/af_packet,						\
	net/af_xdp,							\
	net/bnx2x,							\
	net/bonding,						\
	net/ipn3ke,							\
	net/liquidio,						\
	net/pcap,							\
	net/pfe,							\
	net/sfc,							\
	net/softnic,						\
	net/thunderx,						\
	raw/ifpga

DPDK_LIBS_DISABLED := acl,				\
	bbdev,								\
	bitratestats,						\
	bpf,								\
	cfgfile,							\
	distributor,						\
	efd,								\
	fib,								\
	flow_classify,						\
	graph,								\
	gro,								\
	gso,								\
	jobstats,							\
	kni,								\
	latencystats,						\
	lpm,								\
	member,								\
	node,								\
	pipeline,							\
	port,								\
	power,								\
	rawdev,								\
	rib,								\
	table

# Adjust disabled pmd and libs depending on user provided variables
ifeq ($(DPDK_MLX4_PMD), n)
	DPDK_DRIVERS_DISABLED += ,net/mlx4
endif
ifeq ($(DPDK_MLX5_PMD), n)
	DPDK_DRIVERS_DISABLED += ,net/mlx5
endif
ifeq ($(DPDK_MLX5_COMMON_PMD), n)
	DPDK_DRIVERS_DISABLED += ,common/mlx5
endif
ifeq ($(DPDK_TAP_PMD), n)
	DPDK_DRIVERS_DISABLED += ,net/tap
endif
ifeq ($(DPDK_FAILSAFE_PMD), n)
	DPDK_DRIVERS_DISABLED += ,net/failsafe
endif

# Sanitize DPDK_DRIVERS_DISABLED and DPDK_LIBS_DISABLED
DPDK_DRIVERS_DISABLED := $(shell echo $(DPDK_DRIVERS_DISABLED) | tr -d '\\\t ')
DPDK_LIBS_DISABLED := $(shell echo $(DPDK_LIBS_DISABLED) | tr -d '\\\t ')

HASH := \#
# post-meson-setup snippet to alter rte_build_config.h
define dpdk_config
if grep -q RTE_$(1) $(dpdk_src_dir)/config/rte_config.h ; then	\
sed -i -e 's/$(HASH)define RTE_$(1).*/$(HASH)define RTE_$(1) $(DPDK_$(1))/' \
	$(dpdk_src_dir)/config/rte_config.h; \
elif grep -q RTE_$(1) $(dpdk_build_dir)/rte_build_config.h ; then \
sed -i -e 's/$(HASH)define RTE_$(1).*/$(HASH)define RTE_$(1) $(DPDK_$(1))/' \
	$(dpdk_build_dir)/rte_build_config.h; \
else \
echo '$(HASH)define RTE_$(1) $(DPDK_$(1))' \
	>> $(dpdk_build_dir)/rte_build_config.h ; \
fi
endef

DPDK_MESON_ARGS = \
	--default-library static \
	--libdir lib \
	--prefix $(dpdk_install_dir) \
	-Dtests=false \
	"-Ddisable_drivers=$(DPDK_DRIVERS_DISABLED)" \
	"-Ddisable_libs=$(DPDK_LIBS_DISABLED)" \
	-Db_pie=true \
	-Dmachine=$(DPDK_MACHINE) \
	--buildtype=$(DPDK_BUILD_TYPE) 

define dpdk_config_cmds
	cd $(dpdk_build_dir) && \
	rm -rf ../dpdk-meson-venv && \
	mkdir -p ../dpdk-meson-venv && \
	python3 -m venv ../dpdk-meson-venv && \
	source ../dpdk-meson-venv/bin/activate && \
	pip3 install meson==0.54 && \
	meson setup $(dpdk_src_dir) \
		$(dpdk_build_dir) \
		$(DPDK_MESON_ARGS) \
			> $(dpdk_config_log) && \
	deactivate && \
	echo "DPDK post meson configuration" && \
	echo "Altering rte_build_config.h" && \
	$(call dpdk_config,PKTMBUF_HEADROOM) 
endef

define dpdk_build_cmds
	cd $(dpdk_build_dir) && \
	source ../dpdk-meson-venv/bin/activate && \
	meson compile -C . > $(dpdk_build_log) && \
	deactivate
endef

define dpdk_install_cmds
	cd $(dpdk_build_dir) && \
	source ../dpdk-meson-venv/bin/activate && \
	meson install && \
	cd $(dpdk_install_dir)/lib && \
	echo "GROUP ( $$(ls librte*.a ) )" > libdpdk.a && \
	deactivate && \
	rm -rf $(dpdk_build_dir)/../dpdk-meson-venv
endef

$(eval $(call package,dpdk))
