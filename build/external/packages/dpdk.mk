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
DPDK_USE_LIBBSD              ?= n
DPDK_DEBUG                   ?= n
DPDK_MLX4_PMD                ?= n
DPDK_MLX5_PMD                ?= n
DPDK_MLX5_COMMON_PMD         ?= n
DPDK_TAP_PMD                 ?= n
DPDK_FAILSAFE_PMD            ?= n
DPDK_MACHINE                 ?= default
DPDK_MLX_IBV_LINK            ?= static

dpdk_version                 ?= 21.11
dpdk_base_url                ?= http://fast.dpdk.org/rel
dpdk_tarball                 := dpdk-$(dpdk_version).tar.xz
dpdk_tarball_md5sum_21.11    := 58660bbbe9e95abce86e47692b196555
dpdk_tarball_md5sum_21.08    := de33433a1806280996a0ecbe66e3642f
dpdk_tarball_md5sum_21.05    := a78bba290b11d9717d1272cc6bfaf7c3
dpdk_tarball_md5sum          := $(dpdk_tarball_md5sum_$(dpdk_version))
dpdk_url                     := $(dpdk_base_url)/$(dpdk_tarball)
dpdk_tarball_strip_dirs      := 1
dpdk_depends		     := rdma-core $(if $(ARCH_X86_64), ipsec-mb)
# Debug or release

DPDK_BUILD_TYPE:=release
ifeq ($(DPDK_DEBUG), y)
DPDK_BUILD_TYPE:=debug
endif

DPDK_DRIVERS_DISABLED := baseband/\*,	\
	bus/dpaa,							\
	bus/ifpga,							\
	compress/isal,						\
	compress/octeontx,					\
	compress/zlib,						\
	crypto/ccp,							\
	crypto/dpaa_sec,					\
	crypto/openssl,						\
	crypto/aesni_mb,						\
	crypto/aesni_gcm,						\
	crypto/kasumi,						\
	crypto/snow3g,						\
	crypto/zuc,						\
	event/\*,							\
	mempool/dpaa,						\
	net/af_packet,						\
	net/bnx2x,							\
	net/bonding,						\
	net/ipn3ke,							\
	net/liquidio,						\
	net/pcap,							\
	net/pfe,							\
	net/sfc,							\
	net/softnic,						\
	net/thunderx,						\
	raw/ifpga,							\
	net/af_xdp

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

DPDK_MLX_CONFIG_FLAG :=

# Adjust disabled pmd and libs depending on user provided variables
ifeq ($(DPDK_MLX4_PMD), n)
	DPDK_DRIVERS_DISABLED += ,net/mlx4
else
	DPDK_MLX_CONFIG_FLAG := -Dibverbs_link=${DPDK_MLX_IBV_LINK}
endif
ifeq ($(DPDK_MLX5_PMD), n)
	DPDK_DRIVERS_DISABLED += ,net/mlx5
else
	DPDK_MLX_CONFIG_FLAG := -Dibverbs_link=${DPDK_MLX_IBV_LINK}
endif
ifeq ($(DPDK_MLX5_COMMON_PMD), n)
	DPDK_DRIVERS_DISABLED += ,common/mlx5
else
	DPDK_MLX_CONFIG_FLAG := -Dibverbs_link=${DPDK_MLX_IBV_LINK}
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

define dpdk_config_def
if [[ "$(DPDK_$(1))" == "y" ]]; then \
    if ! grep -q "RTE_$(1)" $(dpdk_build_dir)/rte_build_config.h \
      $(dpdk_src_dir)/config/rte_config.h ; then \
        echo '$(HASH)define RTE_$(1) 1' \
          >> $(dpdk_build_dir)/rte_build_config.h ; \
    fi; \
elif [[ "$(DPDK_$(1))" == "n" ]]; then \
    sed -i '/$(HASH)define RTE_$(1) .*/d' $(dpdk_build_dir)/rte_build_config.h \
      $(dpdk_src_dir)/config/rte_config.h ; \
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
	--buildtype=$(DPDK_BUILD_TYPE) \
	${DPDK_MLX_CONFIG_FLAG}

PIP_DOWNLOAD_DIR = $(CURDIR)/downloads/

define dpdk_config_cmds
	cd $(dpdk_build_dir) && \
	rm -rf ../dpdk-meson-venv && \
	mkdir -p ../dpdk-meson-venv && \
	python3 -m venv ../dpdk-meson-venv && \
	source ../dpdk-meson-venv/bin/activate && \
	(if ! ls $(PIP_DOWNLOAD_DIR)meson* ; then pip3 download -d $(PIP_DOWNLOAD_DIR) -f $(DL_CACHE_DIR) meson==0.55 setuptools wheel pyelftools; fi) && \
	pip3 install --no-index --find-links=$(PIP_DOWNLOAD_DIR) meson==0.55 pyelftools && \
	PKG_CONFIG_PATH=$(dpdk_install_dir)/lib/pkgconfig meson setup $(dpdk_src_dir) \
		$(dpdk_build_dir) \
		$(DPDK_MESON_ARGS) \
			| tee $(dpdk_config_log) && \
	deactivate && \
	echo "DPDK post meson configuration" && \
	echo "Altering rte_build_config.h" && \
	$(call dpdk_config,PKTMBUF_HEADROOM) && \
	$(call dpdk_config_def,USE_LIBBSD)
endef

ifeq ("$(DPDK_VERBOSE)","1")
DPDK_VERBOSE_BUILD = --verbose
endif

define dpdk_build_cmds
	cd $(dpdk_build_dir) && \
	source ../dpdk-meson-venv/bin/activate && \
	meson compile $(DPDK_VERBOSE_BUILD) -C . | tee $(dpdk_build_log) && \
	deactivate
endef

define dpdk_install_cmds
	cd $(dpdk_build_dir) && \
	source ../dpdk-meson-venv/bin/activate && \
	meson install && \
	cd $(dpdk_install_dir)/lib && \
	echo "GROUP ( $$(ls librte*.a ) )" > libdpdk.a && \
	rm -rf librte*.so librte*.so.* dpdk/*/librte*.so dpdk/*/librte*.so.* && \
	deactivate
endef

$(eval $(call package,dpdk))
