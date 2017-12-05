# Copyright (c) 2018 Cisco and/or its affiliates.
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
DPDK_DOWNLOAD_DIR            ?= $(DL_CACHE_DIR)
DPDK_DEBUG                   ?= n
DPDK_MLX4_PMD                ?= n
DPDK_MLX5_PMD                ?= n
DPDK_MLX5_PMD_DLOPEN_DEPS    ?= n
DPDK_TAP_PMD                 ?= n
DPDK_FAILSAFE_PMD            ?= n

DPDK_VERSION                 ?= 18.08
DPDK_BASE_URL                ?= http://fast.dpdk.org/rel
DPDK_TARBALL                 := dpdk-$(DPDK_VERSION).tar.xz
DPDK_TAR_URL                 := $(DPDK_BASE_URL)/$(DPDK_TARBALL)
DPDK_18.05_TARBALL_MD5_CKSUM := 9fc86367cd9407ff6a8dfea56c4eddc4
DPDK_18.08_TARBALL_MD5_CKSUM := da5e7fb25ab063c47e53929fb8c58be5
MACHINE=$(shell uname -m)

# replace dot with space, and if 3rd word exists we deal with stable dpdk rel
ifeq ($(word 3,$(subst ., ,$(DPDK_VERSION))),)
DPDK_SOURCE := $(B)/dpdk-$(DPDK_VERSION)
else
DPDK_SOURCE := $(B)/dpdk-stable-$(DPDK_VERSION)
endif

ifeq ($(MACHINE),$(filter $(MACHINE),x86_64))
  AESNI ?= y
  DPDK_BUILD_DEPS := ipsec-mb-install
else
  AESNI ?= n
endif

ifneq (,$(findstring clang,$(CC)))
DPDK_CC=clang
else ifneq (,$(findstring icc,$(CC)))
DPDK_CC=icc
else
DPDK_CC=gcc
endif

##############################################################################
# Intel x86
##############################################################################
ifeq ($(MACHINE),$(filter $(MACHINE),x86_64 i686))
DPDK_TARGET           ?= $(MACHINE)-native-linuxapp-$(DPDK_CC)
DPDK_MACHINE          ?= nhm
DPDK_TUNE             ?= core-avx2

##############################################################################
# ARM64
##############################################################################
else ifeq ($(MACHINE),aarch64)
CROSS :=
export CROSS
DPDK_TARGET           ?= arm64-armv8a-linuxapp-$(DPDK_CC)
DPDK_MACHINE          ?= armv8a
DPDK_TUNE             ?= generic

CPU_IMP_ARM                     = 0x41
CPU_IMP_CAVIUM                  = 0x43

CPU_PART_ARM_CORTEX_A53         = 0xd03
CPU_PART_ARM_CORTEX_A57         = 0xd07
CPU_PART_ARM_CORTEX_A72         = 0xd08
CPU_PART_ARM_CORTEX_A73         = 0xd09

CPU_PART_CAVIUM_THUNDERX        = 0x0a1
CPU_PART_CAVIUM_THUNDERX_81XX   = 0x0a2
CPU_PART_CAVIUM_THUNDERX_83XX   = 0x0a3

MIDR_IMPLEMENTER=$(shell awk '/implementer/ {print $$4;exit}' /proc/cpuinfo)
MIDR_PARTNUM=$(shell awk '/part/ {print $$4;exit}' /proc/cpuinfo)

ifeq ($(MIDR_IMPLEMENTER),$(CPU_IMP_ARM))
##############################################################################
# Arm Cortex
##############################################################################
CPU_PART_ARM_TUNE := $(CPU_PART_ARM_CORTEX_A53)/cortex-a53 \
		     $(CPU_PART_ARM_CORTEX_A57)/cortex-a57 \
		     $(CPU_PART_ARM_CORTEX_A72)/cortex-a72 \
		     $(CPU_PART_ARM_CORTEX_A73)/cortex-a73
CPU_TUNE = $(notdir $(filter $(MIDR_PARTNUM)/%,$(CPU_PART_ARM_TUNE)))
ifneq ($(CPU_TUNE),)
DPDK_TUNE             = $(CPU_TUNE)
else
$(warning Unknown Arm CPU)
endif

else ifeq ($(MIDR_IMPLEMENTER),$(CPU_IMP_CAVIUM))
##############################################################################
# Cavium ThunderX
##############################################################################
ifneq (,$(findstring $(MIDR_PARTNUM),$(CPU_PART_CAVIUM_THUNDERX) \
	$(CPU_PART_CAVIUM_THUNDERX_81XX) $(CPU_PART_CAVIUM_THUNDERX_83XX)))
DPDK_TARGET           = arm64-thunderx-linuxapp-$(DPDK_CC)
DPDK_MACHINE          = thunderx
DPDK_CACHE_LINE_SIZE := 128
else
$(warning Unknown Cavium CPU)
endif
endif

##############################################################################
# Unknown platform
##############################################################################
else
$(error Unknown platform)
endif

# compiler/linker custom arguments
ifeq ($(DPDK_CC),clang)
DPDK_CPU_CFLAGS := -fPIE -fPIC
else
DPDK_CPU_CFLAGS := -pie -fPIC
endif

ifeq ($(DPDK_DEBUG),n)
DPDK_EXTRA_CFLAGS := -g -mtune=$(DPDK_TUNE)
else
DPDK_EXTRA_CFLAGS := -g -O0
endif

# -Wimplicit-fallthrough was introduced starting from GCC 7,
# and it requires newer version of ccache.
# Disable fallthrough warning for old ccache version.
ifeq ($(DPDK_CC),gcc)
GCC_VER_V = "7.0.0"
CCACHE_VER_V = "3.4.1"
GCC_VER = $(shell gcc --version | grep ^gcc | sed 's/^.* //g')
CCACHE_VER = $(shell ccache --version | grep ^ccache | sed 's/^.* //g')
ifeq ($(shell expr "$(GCC_VER)" ">=" "$(GCC_VER_V)"),1)
ifeq ($(shell expr "$(CCACHE_VER)" "<" "$(CCACHE_VER_V)"),1)
DPDK_EXTRA_CFLAGS += -Wimplicit-fallthrough=0
endif
endif
endif

DPDK_EXTRA_CFLAGS += -L$(I)/lib -I$(I)/include

# assemble DPDK make arguments
DPDK_MAKE_ARGS := -C $(DPDK_SOURCE) -j $(JOBS) \
	T=$(DPDK_TARGET) \
	RTE_CONFIG_TEMPLATE=../custom-config \
	EXTRA_CFLAGS="$(DPDK_EXTRA_CFLAGS)" \
	EXTRA_LDFLAGS="$(DPDK_EXTRA_LDFLAGS)" \
	CPU_CFLAGS="$(DPDK_CPU_CFLAGS)" \
	DESTDIR=$(I) \
        $(DPDK_MAKE_EXTRA_ARGS)

define set
@if grep -q CONFIG_$1 $@ ; \
	then sed -i -e 's/.*\(CONFIG_$1=\).*/\1$2/' $@ ; \
	else echo CONFIG_$1=$2 >> $@ ; \
fi
endef

all: build

$(B)/custom-config: $(B)/.patch.ok Makefile
	@echo --- generating custom config from $(DPDK_SOURCE)/config/defconfig_$(DPDK_TARGET) ---
	@cpp -undef -ffreestanding -x assembler-with-cpp $(DPDK_SOURCE)/config/defconfig_$(DPDK_TARGET) $@
	$(call set,RTE_MACHINE,$(DPDK_MACHINE))
	@# modify options
	$(call set,RTE_MAX_LCORE,256)
	$(call set,RTE_PKTMBUF_HEADROOM,$(DPDK_PKTMBUF_HEADROOM))
	$(call set,RTE_CACHE_LINE_SIZE,$(DPDK_CACHE_LINE_SIZE))
	$(call set,RTE_LIBEAL_USE_HPET,y)
	$(call set,RTE_BUILD_COMBINE_LIBS,y)
	$(call set,RTE_PCI_CONFIG,y)
	$(call set,RTE_PCI_EXTENDED_TAG,"on")
	$(call set,RTE_PCI_MAX_READ_REQUEST_SIZE,4096)
	$(call set,RTE_LIBRTE_PMD_BOND,y)
	$(call set,RTE_LIBRTE_IP_FRAG,y)
	$(call set,RTE_LIBRTE_PMD_QAT,y)
	$(call set,RTE_LIBRTE_PMD_QAT_SYM,y)
	$(call set,RTE_LIBRTE_PMD_AESNI_MB,$(AESNI))
	$(call set,RTE_LIBRTE_PMD_AESNI_GCM,$(AESNI))
	$(call set,RTE_LIBRTE_MLX4_PMD,$(DPDK_MLX4_PMD))
	$(call set,RTE_LIBRTE_MLX5_PMD,$(DPDK_MLX5_PMD))
	$(call set,RTE_LIBRTE_PMD_SOFTNIC,n)
	$(call set,RTE_LIBRTE_MLX4_DLOPEN_DEPS,$(DPDK_MLX4_PMD))
	$(call set,RTE_LIBRTE_MLX5_DLOPEN_DEPS,$(DPDK_MLX5_PMD_DLOPEN_DEPS))
	$(call set,RTE_LIBRTE_PMD_TAP,$(DPDK_TAP_PMD))
	$(call set,RTE_LIBRTE_GSO,$(DPDK_TAP_PMD))
	$(call set,RTE_LIBRTE_PMD_FAILSAFE,$(DPDK_FAILSAFE_PMD))
	@# required for UPF
	$(call set,RTE_LIBRTE_ACL,y)
	@# not needed
	$(call set,RTE_ETHDEV_RXTX_CALLBACKS,n)
	$(call set,RTE_LIBRTE_CFGFILE,n)
	$(call set,RTE_LIBRTE_LPM,n)
	$(call set,RTE_LIBRTE_JOBSTATS,n)
	$(call set,RTE_LIBRTE_EFD,n)
	$(call set,RTE_LIBRTE_MEMBER,n)
	$(call set,RTE_LIBRTE_BITRATE,n)
	$(call set,RTE_LIBRTE_LATENCY_STATS,n)
	$(call set,RTE_LIBRTE_POWER,n)
	$(call set,RTE_LIBRTE_DISTRIBUTOR,n)
	$(call set,RTE_LIBRTE_PORT,n)
	$(call set,RTE_LIBRTE_TABLE,n)
	$(call set,RTE_LIBRTE_PIPELINE,n)
	$(call set,RTE_LIBRTE_PMD_SOFTNIC,n)
	$(call set,RTE_LIBRTE_FLOW_CLASSIFY,n)
	$(call set,RTE_LIBRTE_GRO,n)
	$(call set,RTE_LIBRTE_KNI,n)
	$(call set,RTE_LIBRTE_BPF,n)
	$(call set,RTE_LIBRTE_RAWDEV,n)
	$(call set,RTE_LIBRTE_PMD_IFPGA_RAWDEV,n)
	$(call set,RTE_LIBRTE_IFPGA_BUS,n)
	$(call set,RTE_LIBRTE_BBDEV,n)
	$(call set,RTE_LIBRTE_BBDEV_NULL,n)
	$(call set,RTE_TEST_PMD,n)
	$(call set,RTE_KNI_KMOD,n)
	$(call set,RTE_EAL_IGB_UIO,n)
	@# currently broken in 18.02
	$(call set,RTE_LIBRTE_DPAA_BUS,n)
	$(call set,RTE_LIBRTE_DPAA_MEMPOOL,n)
	$(call set,RTE_LIBRTE_DPAA_PMD,n)
	$(call set,RTE_LIBRTE_PMD_DPAA_SEC,n)
	$(call set,RTE_LIBRTE_PMD_DPAA_EVENTDEV,n)
	@rm -f .config.ok

$(CURDIR)/$(DPDK_TARBALL):
	@if [ -e $(DPDK_DOWNLOAD_DIR)/$(DPDK_TARBALL) ] ; \
		then cp $(DPDK_DOWNLOAD_DIR)/$(DPDK_TARBALL) $(CURDIR) ; \
		else curl -o $(CURDIR)/$(DPDK_TARBALL) -LO $(DPDK_TAR_URL) ; \
	fi
	@rm -f $(B)/.download.ok

DPDK_DOWNLOADS = $(CURDIR)/$(DPDK_TARBALL)

$(B)/.download.ok: $(DPDK_DOWNLOADS)
	@mkdir -p $(B)
	@openssl md5 $< | cut -f 2 -d " " - > $(B)/$(DPDK_TARBALL).md5sum
	@([ "$$(<$(B)/$(DPDK_TARBALL).md5sum)" = "$(DPDK_$(DPDK_VERSION)_TARBALL_MD5_CKSUM)" ] || \
	( echo "Bad Checksum! Please remove $< and retry" && \
		rm $(B)/$(DPDK_TARBALL).md5sum && false ))
	@touch $@

.PHONY: download
download: $(B)/.download.ok

$(B)/.extract.ok: $(B)/.download.ok
	@echo --- extracting $(DPDK_TARBALL) ---
	@tar --directory $(B) --extract --file $(CURDIR)/$(DPDK_TARBALL)
	@touch $@

.PHONY: extract
extract: $(B)/.extract.ok

$(B)/.patch.ok: $(B)/.extract.ok
ifneq ($(wildcard $(CURDIR)/patches/dpdk_$(DPDK_VERSION)/*.patch),)
	@echo --- patching ---
	@for f in $(CURDIR)/patches/dpdk_$(DPDK_VERSION)/*.patch ; do \
		echo Applying patch: $$(basename $$f) ; \
		patch -p1 -d $(DPDK_SOURCE) < $$f ; \
	done
endif
	@touch $@

.PHONY: patch
patch: $(B)/.patch.ok

$(B)/.config.ok: $(B)/.patch.ok $(B)/custom-config
	@make $(DPDK_MAKE_ARGS) config
	@touch $@

.PHONY: config
config: $(B)/.config.ok

.PHONY: build-dpdk
build-dpdk: $(DPDK_BUILD_DEPS)
	@if [ ! -e $(B)/.config.ok ] ; then echo 'Please run "make config" first' && false ; fi
	@make $(DPDK_MAKE_ARGS) install

$(B)/.build.ok: build-dpdk
	@touch $@

.PHONY: build
build: $(B)/.build.ok

.PHONY: install
install: $(B)/.build.ok
