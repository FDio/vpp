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
DPDK_VERSION ?= 17.08
PKG_SUFFIX ?= vpp1
DPDK_BASE_URL ?= http://fast.dpdk.org/rel
DPDK_TARBALL := dpdk-$(DPDK_VERSION).tar.xz
DPDK_TAR_URL := $(DPDK_BASE_URL)/$(DPDK_TARBALL)
DPDK_17.05_TARBALL_MD5_CKSUM := 0a68c31cd6a6cabeed0a4331073e4c05
DPDK_17.08_TARBALL_MD5_CKSUM := 0641f59ea8ea98afefa7cfa2699f6241
DPDK_SOURCE := $(B)/dpdk-$(DPDK_VERSION)
MACHINE=$(shell uname -m)

AESNI ?= n
ISA_L_CRYPTO_LIB := n

IPSEC_MB_VER ?= 0.46
ISA_L_CRYPTO_VER := 2.18.0

ifeq ($(MACHINE),$(filter $(MACHINE),x86_64))
AESNI = y
# DPDK pre 17.08 depends on ISA-L Crypto library for GCM PMD
  ifneq ($(firstword $(sort $(DPDK_VERSION), 17.08)), 17.08)
  ISA_L_CRYPTO_LIB = y
  IPSEC_MB_VER = 0.45
  $(info Building ISA-L Crypto $(ISA_L_CRYPTO_VER) library)
  endif
$(info Building IPSec-MB $(IPSEC_MB_VER) library)
endif

AESNIMB_LIB_TARBALL := v$(IPSEC_MB_VER).tar.gz
AESNIMB_LIB_TARBALL_URL := http://github.com/01org/intel-ipsec-mb/archive/$(AESNIMB_LIB_TARBALL)
AESNIMB_LIB_SOURCE := $(B)/intel-ipsec-mb-$(IPSEC_MB_VER)

ISA_L_CRYPTO_LIB_TARBALL := v$(ISA_L_CRYPTO_VER).tar.gz
ISA_L_CRYPTO_LIB_TARBALL_URL := http://github.com/01org/isa-l_crypto/archive/$(ISA_L_CRYPTO_LIB_TARBALL)
ISA_L_CRYPTO_LIB_SOURCE := $(B)/isa-l_crypto-$(ISA_L_CRYPTO_VER)
ISA_L_CRYPTO_INSTALL_DIR := $(ISA_L_CRYPTO_LIB_SOURCE)/install

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
else ifeq ($(MACHINE),aarch64)
export CROSS=""
ifneq (,$(findstring thunder,$(shell [[ -f /sys/bus/pci/devices/0000:00:01.0/uevent ]] && cat /sys/bus/pci/devices/0000:00:01.0/uevent | grep cavium)))
##############################################################################
# Cavium ThunderX
##############################################################################
DPDK_TARGET           ?= arm64-thunderx-linuxapp-$(DPDK_CC)
DPDK_MACHINE          ?= thunderx
DPDK_TUNE             ?= generic
else
##############################################################################
# Generic ARM64
##############################################################################
DPDK_TARGET           ?= arm64-armv8a-linuxapp-$(DPDK_CC)
DPDK_MACHINE          ?= armv8a
DPDK_TUNE             ?= generic
endif

##############################################################################
# Unknown platofrm
##############################################################################
else
$(error unknown platform)
endif

# /proc/cpuinfo does not exist on platforms without a /proc and on some
# platforms, notably inside containers, it has no content. In those cases
# we assume there's 1 processor; we use 2*ncpu for the -j option.
# NB: GNU Make 4.2 will let us use '$(file </proc/cpuinfo)' to both test
# for file presence and content; for now this will have to do.
JOBS := $(if $(shell [ -f /proc/cpuinfo ] && head /proc/cpuinfo),\
	$(shell expr 2 '*' $$(grep -c ^processor /proc/cpuinfo)), 2)

# compiler/linker custom arguments
DPDK_CPU_CFLAGS := -pie -fPIC
DPDK_EXTRA_LDFLAGS := -g

ifeq ($(DPDK_DEBUG),n)
DPDK_EXTRA_CFLAGS := -g -mtune=$(DPDK_TUNE)
else
DPDK_EXTRA_CFLAGS := -g -O0
endif

ifeq ($(ISA_L_CRYPTO_LIB),y)
DPDK_EXTRA_CFLAGS += -I$(ISA_L_CRYPTO_INSTALL_DIR)/include -Wl,-z,muldefs
DPDK_EXTRA_LDFLAGS += -L$(I)/lib
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
	$(call set,RTE_MAX_MEMSEG,4096)
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
	$(call set,RTE_KNI_KMOD,n)
	$(call set,RTE_EAL_IGB_UIO,n)
	@rm -f .config.ok

$(CURDIR)/$(DPDK_TARBALL):
	@if [ -e $(DPDK_DOWNLOAD_DIR)/$(DPDK_TARBALL) ] ; \
		then cp $(DPDK_DOWNLOAD_DIR)/$(DPDK_TARBALL) $(CURDIR) ; \
		else curl -o $(CURDIR)/$(DPDK_TARBALL) -LO $(DPDK_TAR_URL) ; \
	fi
	@rm -f $(B)/.download.ok

$(CURDIR)/$(AESNIMB_LIB_TARBALL):
	@if [ -e $(DPDK_DOWNLOAD_DIR)/$(AESNIMB_LIB_TARBALL) ] ; \
		then cp $(DPDK_DOWNLOAD_DIR)/$(AESNIMB_LIB_TARBALL) $(CURDIR) ; \
		else curl -o $@ -LO $(AESNIMB_LIB_TARBALL_URL) ; \
	fi

$(CURDIR)/$(ISA_L_CRYPTO_LIB_TARBALL):
	@if [ -e $(DPDK_DOWNLOAD_DIR)/$(ISA_L_CRYPTO_LIB_TARBALL) ] ; \
		then cp $(DPDK_DOWNLOAD_DIR)/$(ISA_L_CRYPTO_LIB_TARBALL) $(CURDIR) ; \
		else curl -o $@ -LO $(ISA_L_CRYPTO_LIB_TARBALL_URL) ; \
	fi

DPDK_DOWNLOADS = $(CURDIR)/$(DPDK_TARBALL)
ifeq ($(AESNI),y)
DPDK_DOWNLOADS += $(CURDIR)/$(AESNIMB_LIB_TARBALL)
endif
ifeq ($(ISA_L_CRYPTO_LIB),y)
DPDK_DOWNLOADS += $(CURDIR)/$(ISA_L_CRYPTO_LIB_TARBALL)
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
	@echo --- extracting $(AESNIMB_LIB_TARBALL) ---
	@tar --directory $(B) --extract --file $(CURDIR)/$(AESNIMB_LIB_TARBALL)
endif
ifeq ($(ISA_L_CRYPTO_LIB),y)
	@echo --- extracting $(ISA_L_CRYPTO_LIB_TARBALL) ---
	@tar --directory $(B) --extract --file $(CURDIR)/$(ISA_L_CRYPTO_LIB_TARBALL)
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

.PHONY: build-ipsec-mb
build-ipsec-mb:
	mkdir -p $(I)/lib/
	# Do not build GCM stuff if we are building ISA_L
	make -C $(AESNIMB_LIB_SOURCE) -j NO_GCM=$(ISA_L_CRYPTO_LIB)
	cp $(AESNIMB_LIB_SOURCE)/libIPSec_MB.a $(I)/lib/

.PHONY: build-isal-crypto
build-isal-crypto:
	mkdir -p $(I)/lib/
	cd $(ISA_L_CRYPTO_LIB_SOURCE) && ./autogen.sh && \
	  ./configure --prefix=$(ISA_L_CRYPTO_INSTALL_DIR) \
	  --libdir=$(ISA_L_CRYPTO_INSTALL_DIR)/lib CFLAGS='-fPIC -DPIC -O2'
	make -C $(ISA_L_CRYPTO_LIB_SOURCE) -j install
	cp $(ISA_L_CRYPTO_INSTALL_DIR)/lib/libisal_crypto.a $(I)/lib/

.PHONY: build-dpdk
build-dpdk:
	@if [ ! -e $(B)/.config.ok ] ; then echo 'Please run "make config" first' && false ; fi
	@make $(DPDK_MAKE_ARGS) install

# Order matters
ifeq ($(AESNI),y)
BUILD_TARGETS += build-ipsec-mb
endif
ifeq ($(ISA_L_CRYPTO_LIB),y)
BUILD_TARGETS += build-isal-crypto
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
