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

# Scripts require non-POSIX parts of bash
SHELL := /bin/bash

DPDK_BUILD_DIR        ?= $(CURDIR)/_build
DPDK_INSTALL_DIR      ?= $(CURDIR)/_install
DPDK_PKTMBUF_HEADROOM ?= 128
DPDK_DOWNLOAD_DIR     ?= $(HOME)/Downloads
DPDK_DEBUG            ?= n
DPDK_MLX4_PMD         ?= n
DPDK_MLX5_PMD         ?= n

B := $(DPDK_BUILD_DIR)
I := $(DPDK_INSTALL_DIR)
DPDK_VERSION ?= 18.02
PKG_SUFFIX ?= vpp1
DPDK_BASE_URL ?= http://fast.dpdk.org/rel
DPDK_TARBALL := dpdk-$(DPDK_VERSION).tar.xz
DPDK_TAR_URL := $(DPDK_BASE_URL)/$(DPDK_TARBALL)
DPDK_17.11_TARBALL_MD5_CKSUM := 53ee9e054a8797c9e67ffa0eb5d0c701
DPDK_18.02_TARBALL_MD5_CKSUM := ca13077a014a2102c6e10153dfa3b920
DPDK_SOURCE := $(B)/dpdk-$(DPDK_VERSION)
MACHINE=$(shell uname -m)

NASM_BASE_URL := http://www.nasm.us/pub/nasm/releasebuilds
NASM_VER := 2.13.01
NASM_TARBALL := nasm-$(NASM_VER).tar.xz
NASM_TAR_URL := $(NASM_BASE_URL)/$(NASM_VER)/$(NASM_TARBALL)
NASM_SOURCE := $(B)/nasm-$(NASM_VER)

ifeq ($(DPDK_VERSION),17.11)
IPSEC_MB_VER ?= 0.47
else
IPSEC_MB_VER ?= 0.48
endif

ifeq ($(MACHINE),$(filter $(MACHINE),x86_64))
  AESNI ?= y
$(info Building IPSec-MB $(IPSEC_MB_VER) library)
else
  AESNI ?= N
endif

AESNIMB_LIB_TARBALL := v$(IPSEC_MB_VER).tar.gz
AESNIMB_LIB_TARBALL_URL := http://github.com/01org/intel-ipsec-mb/archive/$(AESNIMB_LIB_TARBALL)
AESNIMB_LIB_SOURCE := $(B)/intel-ipsec-mb-$(IPSEC_MB_VER)

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
export CROSS=""
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

# /proc/cpuinfo does not exist on platforms without a /proc and on some
# platforms, notably inside containers, it has no content. In those cases
# we assume there's 1 processor; we use 2*ncpu for the -j option.
# NB: GNU Make 4.2 will let us use '$(file </proc/cpuinfo)' to both test
# for file presence and content; for now this will have to do.
JOBS := $(if $(shell [ -f /proc/cpuinfo ] && head /proc/cpuinfo),\
	$(shell grep -c ^processor /proc/cpuinfo), 2)

# compiler/linker custom arguments
DPDK_CPU_CFLAGS := -pie -fPIC

ifeq ($(DPDK_DEBUG),n)
DPDK_EXTRA_CFLAGS := -g -mtune=$(DPDK_TUNE)
else
DPDK_EXTRA_CFLAGS := -g -O0
endif

DPDK_MAKE_EXTRA_ARGS += AESNI_MULTI_BUFFER_LIB_PATH=$(AESNIMB_LIB_SOURCE)

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
	$(call set,RTE_LIBEAL_USE_HPET,y)
	$(call set,RTE_BUILD_COMBINE_LIBS,y)
	$(call set,RTE_PCI_CONFIG,y)
	$(call set,RTE_PCI_EXTENDED_TAG,"on")
	$(call set,RTE_PCI_MAX_READ_REQUEST_SIZE,4096)
	@# enable debug init for device drivers
	$(call set,RTE_LIBRTE_I40E_DEBUG_INIT,$(DPDK_DEBUG))
	$(call set,RTE_LIBRTE_IXGBE_DEBUG_INIT,$(DPDK_DEBUG))
	$(call set,RTE_LIBRTE_E1000_DEBUG_INIT,$(DPDK_DEBUG))
	$(call set,RTE_LIBRTE_VIRTIO_DEBUG_INIT,$(DPDK_DEBUG))
	$(call set,RTE_LIBRTE_VMXNET3_DEBUG_INIT,$(DPDK_DEBUG))
	$(call set,RTE_LIBRTE_PMD_BOND,y)
	$(call set,RTE_LIBRTE_IP_FRAG,y)
	$(call set,RTE_LIBRTE_PMD_QAT,y)
	$(call set,RTE_LIBRTE_PMD_AESNI_MB,$(AESNI))
	$(call set,RTE_LIBRTE_PMD_AESNI_GCM,$(AESNI))
	$(call set,RTE_LIBRTE_MLX4_PMD,$(DPDK_MLX4_PMD))
	$(call set,RTE_LIBRTE_MLX5_PMD,$(DPDK_MLX5_PMD))
	@# not needed
	$(call set,RTE_LIBRTE_PMD_TAP,n)
	$(call set,RTE_LIBRTE_TIMER,n)
	$(call set,RTE_LIBRTE_CFGFILE,n)
	$(call set,RTE_LIBRTE_LPM,n)
	$(call set,RTE_LIBRTE_ACL,n)
	$(call set,RTE_LIBRTE_POWER,n)
	$(call set,RTE_LIBRTE_DISTRIBUTOR,n)
	$(call set,RTE_LIBRTE_PORT,n)
	$(call set,RTE_LIBRTE_TABLE,n)
	$(call set,RTE_LIBRTE_PIPELINE,n)
	$(call set,RTE_LIBRTE_FLOW_CLASSIFY,n)
	$(call set,RTE_KNI_KMOD,n)
	$(call set,RTE_EAL_IGB_UIO,n)
	@rm -f .config.ok

$(CURDIR)/$(DPDK_TARBALL):
	@if [ -e $(DPDK_DOWNLOAD_DIR)/$(DPDK_TARBALL) ] ; \
		then cp $(DPDK_DOWNLOAD_DIR)/$(DPDK_TARBALL) $(CURDIR) ; \
		else curl -o $(CURDIR)/$(DPDK_TARBALL) -LO $(DPDK_TAR_URL) ; \
	fi
	@rm -f $(B)/.download.ok

$(CURDIR)/$(NASM_TARBALL):
	@if [ -e $(DPDK_DOWNLOAD_DIR)/$(NASM_TARBALL) ] ; \
		then cp $(DPDK_DOWNLOAD_DIR)/$(NASM_TARBALL) $(CURDIR) ; \
		else curl -o $(CURDIR)/$(NASM_TARBALL) -LO $(NASM_TAR_URL) ; \
	fi

$(CURDIR)/$(AESNIMB_LIB_TARBALL):
	@if [ -e $(DPDK_DOWNLOAD_DIR)/$(AESNIMB_LIB_TARBALL) ] ; \
		then cp $(DPDK_DOWNLOAD_DIR)/$(AESNIMB_LIB_TARBALL) $(CURDIR) ; \
		else curl -o $@ -LO $(AESNIMB_LIB_TARBALL_URL) ; \
	fi

DPDK_DOWNLOADS = $(CURDIR)/$(DPDK_TARBALL)
ifeq ($(AESNI),y)
DPDK_DOWNLOADS += $(CURDIR)/$(NASM_TARBALL)
DPDK_DOWNLOADS += $(CURDIR)/$(AESNIMB_LIB_TARBALL)
endif

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
ifeq ($(AESNI),y)
	@echo --- extracting $(NASM_TARBALL) ---
	@tar --directory $(B) --extract --file $(CURDIR)/$(NASM_TARBALL)
	@echo --- extracting $(AESNIMB_LIB_TARBALL) ---
	@tar --directory $(B) --extract --file $(CURDIR)/$(AESNIMB_LIB_TARBALL)
endif
	@touch $@

.PHONY: extract
extract: $(B)/.extract.ok

$(B)/.patch.ok: $(B)/.extract.ok
ifneq ($(wildcard $(CURDIR)/dpdk-$(DPDK_VERSION)_patches/*.patch),)
	@echo --- patching ---
	@for f in $(CURDIR)/dpdk-$(DPDK_VERSION)_patches/*.patch ; do \
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

.PHONY: build-nasm
build-nasm:
	cd $(NASM_SOURCE) && sh configure && make -j

.PHONY: build-ipsec-mb
build-ipsec-mb:
	mkdir -p $(I)/lib/
	# Do not build GCM stuff if we are building ISA_L
	make -C $(AESNIMB_LIB_SOURCE) -j \
	  DEBUG=$(DPDK_DEBUG) EXTRA_CFLAGS=-fPIC NASM=$(NASM_SOURCE)/nasm
	cp $(AESNIMB_LIB_SOURCE)/libIPSec_MB.a $(I)/lib/

.PHONY: build-dpdk
build-dpdk:
	@if [ ! -e $(B)/.config.ok ] ; then echo 'Please run "make config" first' && false ; fi
	@make $(DPDK_MAKE_ARGS) install

# Order matters
ifeq ($(AESNI),y)
BUILD_TARGETS += build-nasm
BUILD_TARGETS += build-ipsec-mb
endif
BUILD_TARGETS += build-dpdk

$(B)/.build.ok: $(BUILD_TARGETS)
	@touch $@

.PHONY: build
build: $(B)/.build.ok

.PHONY: install
install: $(B)/.build.ok

.PHONY: clean
clean:
	@rm -rf $(B) $(I)

##############################################################################
# .deb packaging
##############################################################################

DEB_ARCH=$(shell dpkg --print-architecture 2> /dev/null)
DEV_DEB=vpp-dpdk-dev_$(DPDK_VERSION)-$(PKG_SUFFIX)_$(DEB_ARCH).deb
INSTALLED_DEB_VER=$(shell dpkg-query --showformat='$${Version}' --show vpp-dpdk-dev 2> /dev/null)

.PHONY: build-deb install-deb check-deb

deb/debian/changelog: Makefile
	@echo "vpp-dpdk ($(DPDK_VERSION)-$(PKG_SUFFIX)) unstable; urgency=low" > $@
	@echo "" >> $@
	@echo "  * DPDK Release $(DPDK_VERSION)" >> $@
	@echo "" >> $@
	@echo " -- VPP Dev <vpp-dev@lists.fd.io>  $(shell date -R)" >> $@

$(DEV_DEB): deb/debian/changelog
	@cd deb && dpkg-buildpackage -b -uc -us
	git clean -fdx deb

build-deb: $(DEV_DEB)

install-deb:
ifneq ($(INSTALLED_DEB_VER),$(DPDK_VERSION)-$(PKG_SUFFIX))
	@echo "=========================================================="
	@echo " Out of date DPDK package installed."
	@echo " Installed: $(INSTALLED_DEB_VER)"
	@echo " Needed: $(DPDK_VERSION)-$(PKG_SUFFIX)"
	@echo "=========================================================="
	@make $(DEV_DEB)
	@sudo dpkg -i $(DEV_DEB)
else
	@echo "=========================================================="
	@echo " Up-to-date DPDK package already installed"
	@echo "=========================================================="
endif

check-deb:
ifneq ($(INSTALLED_DEB_VER),$(DPDK_VERSION)-$(PKG_SUFFIX))
	@echo "=========================================================="
	@echo " Outdated DPDK package detected:"
	@echo "  Installed: vpp-dpdk-dev $(INSTALLED_DEB_VER)"
	@echo "  Current:   vpp-dpdk-dev $(DPDK_VERSION)-$(PKG_SUFFIX)"
	@echo ""
	@echo " Please upgrade by invoking 'make dpdk-install-dev'"
	@echo " from the top level directory."
	@echo "=========================================================="
endif

##############################################################################
# .rpm packaging
##############################################################################

RPM_ARCH=$(shell rpm --eval "%{_arch}" 2> /dev/null)
DEV_RPM=vpp-dpdk-devel-$(DPDK_VERSION)-$(PKG_SUFFIX).$(RPM_ARCH).rpm
INSTALLED_RPM_VER=$(shell rpm -q --queryformat '%{VERSION}-%{RELEASE}' vpp-dpdk-devel 2> /dev/null | grep -v "not inst")

.PHONY: build-rpm install-rpm check-rpm

$(DEV_RPM): Makefile rpm/vpp-dpdk.spec
	@rpmbuild -bb \
	  --define "_topdir $(CURDIR)/rpm" \
	  --define "_version $(DPDK_VERSION)" \
	  --define "_release $(PKG_SUFFIX)" \
	  $(CURDIR)/rpm/vpp-dpdk.spec
	mv rpm/RPMS/$(RPM_ARCH)/*.rpm .
	git clean -fdx rpm

build-rpm: $(DEV_RPM)

install-rpm:
ifneq ($(INSTALLED_RPM_VER),$(DPDK_VERSION)-$(PKG_SUFFIX))
	@$(MAKE) $(DEV_RPM)
	sudo rpm -Uih $(DEV_RPM)
else
	@echo "=========================================================="
	@echo " Up-to-date DPDK package already installed"
	@echo "=========================================================="
endif

check-rpm:
ifneq ($(INSTALLED_RPM_VER),$(DPDK_VERSION)-$(PKG_SUFFIX))
	@echo "=========================================================="
	@echo " Outdated DPDK package detected:"
	@echo "  Installed: vpp-dpdk-devel $(INSTALLED_RPM_VER)"
	@echo "  Current:   vpp-dpdk-devel $(DPDK_VERSION)-$(PKG_SUFFIX)"
	@echo ""
	@echo " Please upgrade by invoking 'make dpdk-install-dev'"
	@echo " from the top level directory."
	@echo "=========================================================="
endif

##############################################################################
# ebuild support
##############################################################################

.PHONY: ebuild-build ebuild-install

ebuild-build:
ifeq ($(INSTALLED_DEB_VER)$(INSTALLED_RPM_VER),)
	@echo "=========================================================="
	@echo "Building DPDK from source. Consider installing development"
	@echo "package by invoking 'make dpdk-install-dev' from the"
	@echo "top level directory"
	@echo "=========================================================="
	make config
else
ifneq ($(INSTALLED_DEB_VER),)
	make check-deb
endif
ifneq ($(INSTALLED_RPM_VER),)
	make check-rpm
endif
endif

ebuild-install:
ifeq ($(INSTALLED_DEB_VER)$(INSTALLED_RPM_VER),)
	make install
endif
