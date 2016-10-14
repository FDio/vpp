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

WS_ROOT=$(CURDIR)
BR=$(WS_ROOT)/build-root
CCACHE_DIR?=$(BR)/.ccache
GDB?=gdb
PLATFORM?=vpp

MINIMAL_STARTUP_CONF="unix { interactive }"

GDB_ARGS= -ex "handle SIGUSR1 noprint nostop"

#
# OS Detection
#
# We allow Darwin (MacOS) for docs generation; VPP build will still fail.
ifneq ($(shell uname),Darwin)
OS_ID        = $(shell grep '^ID=' /etc/os-release | cut -f2- -d= | sed -e 's/\"//g')
OS_VERSION_ID= $(shell grep '^VERSION_ID=' /etc/os-release | cut -f2- -d= | sed -e 's/\"//g')
endif

DEB_DEPENDS  = curl build-essential autoconf automake bison libssl-dev ccache
DEB_DEPENDS += debhelper dkms git libtool libganglia1-dev libapr1-dev dh-systemd
DEB_DEPENDS += libconfuse-dev git-review exuberant-ctags cscope
DEB_DEPENDS += python-dev
ifeq ($(OS_VERSION_ID),14.04)
	DEB_DEPENDS += openjdk-8-jdk-headless
else
	DEB_DEPENDS += default-jdk-headless
endif

RPM_DEPENDS_GROUPS = 'Development Tools'
RPM_DEPENDS  = redhat-lsb glibc-static java-1.8.0-openjdk-devel yum-utils
RPM_DEPENDS += openssl-devel https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm apr-devel
RPM_DEPENDS += python-devel
EPEL_DEPENDS = libconfuse-devel ganglia-devel

ifneq ($(wildcard $(STARTUP_DIR)/startup.conf),)
        STARTUP_CONF ?= $(STARTUP_DIR)/startup.conf
endif

ifeq ($(findstring y,$(UNATTENDED)),y)
CONFIRM=-y
FORCE=--force-yes
endif

.PHONY: help bootstrap wipe wipe-release build build-release rebuild rebuild-release
.PHONY: run run-release debug debug-release build-vat run-vat pkg-deb pkg-rpm
.PHONY: ctags cscope plugins plugins-release build-vpp-api
.PHONY: test test-debug retest retest-debug

help:
	@echo "Make Targets:"
	@echo " bootstrap           - prepare tree for build"
	@echo " install-dep         - install software dependencies"
	@echo " wipe                - wipe all products of debug build "
	@echo " wipe-release        - wipe all products of release build "
	@echo " build               - build debug binaries"
	@echo " build-release       - build release binaries"
	@echo " plugins             - build debug plugin binaries"
	@echo " plugins-release     - build release plugin binaries"
	@echo " rebuild             - wipe and build debug binares"
	@echo " rebuild-release     - wipe and build release binares"
	@echo " run                 - run debug binary"
	@echo " run-release         - run release binary"
	@echo " debug               - run debug binary with debugger"
	@echo " debug-release       - run release binary with debugger"
	@echo " test                - build and run functional tests"
	@echo " test-debug          - build and run functional tests (debug build)"
	@echo " retest              - run functional tests"
	@echo " retest-debug        - run functional tests (debug build)"
	@echo " build-vat           - build vpp-api-test tool"
	@echo " build-vpp-api       - build vpp-api"
	@echo " run-vat             - run vpp-api-test tool"
	@echo " pkg-deb             - build DEB packages"
	@echo " pkg-rpm             - build RPM packages"
	@echo " ctags               - (re)generate ctags database"
	@echo " gtags               - (re)generate gtags database"
	@echo " cscope              - (re)generate cscope database"
	@echo " checkstyle          - check coding style"
	@echo " fixstyle            - fix coding style"
	@echo " doxygen             - (re)generate documentation"
	@echo " bootstrap-doxygen   - setup Doxygen dependencies"
	@echo " wipe-doxygen        - wipe all generated documentation"
	@echo ""
	@echo "Make Arguments:"
	@echo " V=[0|1]             - set build verbosity level"
	@echo " STARTUP_CONF=<path> - startup configuration file"
	@echo "                       (e.g. /etc/vpp/startup.conf)"
	@echo " STARTUP_DIR=<path>  - startup drectory (e.g. /etc/vpp)"
	@echo "                       It also sets STARTUP_CONF if"
	@echo "                       startup.conf file is present"
	@echo " GDB=<path>          - gdb binary to use for debugging"
	@echo " PLATFORM=<name>     - target platform. default is vpp"
	@echo " TEST=<name>         - only run specific test"
	@echo ""
	@echo "Current Argumernt Values:"
	@echo " V            = $(V)"
	@echo " STARTUP_CONF = $(STARTUP_CONF)"
	@echo " STARTUP_DIR  = $(STARTUP_DIR)"
	@echo " GDB          = $(GDB)"
	@echo " PLATFORM     = $(PLATFORM)"
	@echo " DPDK_VERSION = $(DPDK_VERSION)"

$(BR)/.bootstrap.ok:
ifeq ($(OS_ID),ubuntu)
	@MISSING=$$(apt-get install -y -qq -s $(DEB_DEPENDS) | grep "^Inst ") ; \
	if [ -n "$$MISSING" ] ; then \
	  echo "\nPlease install missing packages: \n$$MISSING\n" ; \
	  echo "by executing \"make install-dep\"\n" ; \
	  exit 1 ; \
	fi ; \
	exit 0
endif
	@echo "SOURCE_PATH = $(WS_ROOT)"                   > $(BR)/build-config.mk
	@echo "#!/bin/bash\n"                              > $(BR)/path_setup
	@echo 'export PATH=$(BR)/tools/ccache-bin:$$PATH' >> $(BR)/path_setup
	@echo 'export PATH=$(BR)/tools/bin:$$PATH'        >> $(BR)/path_setup
	@echo 'export CCACHE_DIR=$(CCACHE_DIR)'           >> $(BR)/path_setup

ifeq ("$(wildcard /usr/bin/ccache )","")
	@echo "WARNING: Please install ccache AYEC and re-run this script"
else
	@rm -rf $(BR)/tools/ccache-bin
	@mkdir -p $(BR)/tools/ccache-bin
	@ln -s /usr/bin/ccache $(BR)/tools/ccache-bin/gcc
	@ln -s /usr/bin/ccache $(BR)/tools/ccache-bin/g++
endif
	@make -C $(BR) V=$(V) is_build_tool=yes vppapigen-install
	@touch $@

bootstrap: $(BR)/.bootstrap.ok

install-dep:
ifeq ($(OS_ID),ubuntu)
ifeq ($(OS_VERSION_ID),14.04)
	@sudo -E apt-get $(CONFIRM) $(FORCE) install software-properties-common
	@sudo -E add-apt-repository ppa:openjdk-r/ppa $(CONFIRM)
	@sudo -E apt-get update
endif
	@sudo -E apt-get $(CONFIRM) $(FORCE) install $(DEB_DEPENDS)
else ifneq ("$(wildcard /etc/redhat-release)","")
	@sudo yum groupinstall $(CONFIRM) $(RPM_DEPENDS_GROUPS)
	@sudo yum install $(CONFIRM) $(RPM_DEPENDS)
	@sudo yum install $(CONFIRM) --enablerepo=epel $(EPEL_DEPENDS)
	@sudo debuginfo-install $(CONFIRM) glibc-2.17-106.el7_2.4.x86_64 openssl-libs-1.0.1e-51.el7_2.4.x86_64 zlib-1.2.7-15.el7.x86_64
else
	$(error "This option currently works only on Ubuntu or Centos systems")
endif

define make
	@make -C $(BR) PLATFORM=$(PLATFORM) TAG=$(1) $(2)
endef

build: $(BR)/.bootstrap.ok
	$(call make,$(PLATFORM)_debug,vpp-install)

wipe: $(BR)/.bootstrap.ok
	$(call make,$(PLATFORM)_debug,vpp-wipe)

rebuild: wipe build

build-release: $(BR)/.bootstrap.ok
	$(call make,$(PLATFORM),vpp-install)

wipe-release: $(BR)/.bootstrap.ok
	$(call make,$(PLATFORM),vpp-wipe)

rebuild-release: wipe-release build-release

plugins: $(BR)/.bootstrap.ok
	$(call make,$(PLATFORM)_debug,plugins-install)

plugins-release: $(BR)/.bootstrap.ok
	$(call make,$(PLATFORM),plugins-install)

build-vpp-api: $(BR)/.bootstrap.ok
	$(call make,$(PLATFORM)_debug,vpp-api-install)

define test
	@make -C test \
	  VPP_TEST_BIN=$(BR)/install-$(1)-native/vpp/bin/vpp \
	  VPP_TEST_API_TEST_BIN=$(BR)/install-$(1)-native/vpp-api-test/bin/vpp_api_test \
	  VPP_TEST_PLUGIN_PATH=$(BR)/install-$(1)-native/plugins/lib64/vpp_plugins \
	  V=$(V) TEST=$(TEST)
endef

test: bootstrap
ifeq ($(OS_ID),ubuntu)
	@if ! (dpkg -l python-dev python-scapy &> /dev/null); then \
	  sudo -E apt-get $(CONFIRM) $(FORCE) install python-dev python-scapy; \
	fi
endif
	@make -C $(BR) PLATFORM=vpp_lite TAG=vpp_lite vpp-api-install plugins-install vpp-install vpp-api-test-install
	$(call test,vpp_lite)

test-debug: bootstrap
ifeq ($(OS_ID),ubuntu)
	@if ! (dpkg -l python-dev python-scapy &> /dev/null); then \
	  sudo -E apt-get $(CONFIRM) $(FORCE) install python-dev python-scapy; \
	fi
endif
	@make -C $(BR) PLATFORM=vpp_lite TAG=vpp_lite_debug vpp-api-install plugins-install vpp-install vpp-api-test-install
	$(call test,vpp_lite_debug)

retest:
	$(call test,vpp_lite)

retest-debug:
	$(call test,vpp_lite_debug)

STARTUP_DIR ?= $(PWD)
ifeq ("$(wildcard $(STARTUP_CONF))","")
define run
	@echo "WARNING: STARTUP_CONF not defined or file doesn't exist."
	@echo "         Running with minimal startup config: $(MINIMAL_STARTUP_CONF)\n"
	@cd $(STARTUP_DIR) && \
	  sudo $(2) $(1)/vpp/bin/vpp $(MINIMAL_STARTUP_CONF) plugin_path $(1)/plugins/lib64/vpp_plugins
endef
else
define run
	@cd $(STARTUP_DIR) && \
	  sudo $(2) $(1)/vpp/bin/vpp $(shell cat $(STARTUP_CONF) | sed -e 's/#.*//') plugin_path $(1)/plugins/lib64/vpp_plugins
endef
endif

%.files: .FORCE
	@find . \( -name '*\.[chyS]' -o -name '*\.java' -o -name '*\.lex' \) -and \
		\( -not -path './build-root*' -o -path \
		'./build-root/build-vpp_debug-native/dpdk*' \) > $@

.FORCE:

run:
	$(call run, $(BR)/install-$(PLATFORM)_debug-native)

run-release:
	$(call run, $(BR)/install-$(PLATFORM)-native)

debug:
	$(call run, $(BR)/install-$(PLATFORM)_debug-native,$(GDB) $(GDB_ARGS) --args)

debug-release:
	$(call run, $(BR)/install-$(PLATFORM)-native,$(GDB) $(GDB_ARGS) --args)

build-vat:
	$(call make,$(PLATFORM)_debug,vpp-api-test-install)

run-vat:
	@sudo $(BR)/install-$(PLATFORM)_debug-native/vpp-api-test/bin/vpp_api_test

pkg-deb:
	$(call make,$(PLATFORM),install-deb)

pkg-rpm:
	$(call make,$(PLATFORM),install-rpm)

ctags: ctags.files
	@ctags --totals --tag-relative -L $<
	@rm $<

gtags: ctags
	@gtags --gtagslabel=ctags

cscope: cscope.files
	@cscope -b -q -v

checkstyle:
	@build-root/scripts/checkstyle.sh

fixstyle:
	@build-root/scripts/checkstyle.sh --fix

#
# Build the documentation
#

# Doxygen configuration and our utility scripts
export DOXY_DIR ?= $(WS_ROOT)/doxygen

define make-doxy
	@OS_ID="$(OS_ID)" WS_ROOT="$(WS_ROOT)" BR="$(BR)" make -C $(DOXY_DIR) $@
endef

.PHONY: bootstrap-doxygen doxygen wipe-doxygen

bootstrap-doxygen:
	$(call make-doxy)

doxygen:
	$(call make-doxy)

wipe-doxygen:
	$(call make-doxy)

