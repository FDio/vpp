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
V?=0
GDB?=gdb
PLATFORM?=vpp

MINIMAL_STARTUP_CONF="unix { interactive } dpdk { no-pci socket-mem 1024 }"

GDB_ARGS= -ex "handle SIGUSR1 noprint nostop"

DEB_DEPENDS  = curl build-essential autoconf automake bison libssl-dev ccache
DEB_DEPENDS += debhelper dkms openjdk-7-jdk git libtool libganglia1-dev libapr1-dev
DEB_DEPENDS += libconfuse-dev git-review exuberant-ctags cscope

RPM_DEPENDS_GROUPS = 'Development Tools'
RPM_DEPENDS  = redhat-lsb glibc-static java-1.8.0-openjdk-devel
RPM_DEPENDS += openssl-devel epel-release apr-devel
EPEL_DEPENDS = libconfuse-devel ganglia-devel

ifneq ("$(wildcard $(STARTUP_DIR)/startup.conf),"")
        STARTUP_CONF ?= $(STARTUP_DIR)/startup.conf
endif

.PHONY: help bootstrap wipe wipe-release build build-release rebuild rebuild-release
.PHONY: run run-release debug debug-release build-vat run-vat pkg-deb pkg-rpm
.PHONY: ctags cscope

help:
	@echo "Make Targets:"
	@echo " bootstrap           - prepare tree for build"
	@echo " install-dep         - install software dependencies"
	@echo " wipe                - wipe all products of debug build "
	@echo " wipe-release        - wipe all products of release build "
	@echo " build               - build debug binaries"
	@echo " build-release       - build release binaries"
	@echo " rebuild             - wipe and build debug binares"
	@echo " rebuild-release     - wipe and build release binares"
	@echo " run                 - run debug binary"
	@echo " run-release         - run release binary"
	@echo " debug               - run debug binary with debugger"
	@echo " debug-release       - run release binary with debugger"
	@echo " build-vat           - build vpp-api-test tool"
	@echo " run-vat             - run vpp-api-test tool"
	@echo " pkg-deb             - build DEB packages"
	@echo " pkg-rpm             - build RPM packages"
	@echo " ctags               - (re)generate ctags database"
	@echo " cscope              - (re)generate cscope database"
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
	@echo ""
	@echo "Current Argumernt Values:"
	@echo " V            = $(V)"
	@echo " STARTUP_CONF = $(STARTUP_CONF)"
	@echo " STARTUP_DIR  = $(STARTUP_DIR)"
	@echo " GDB          = $(GDB)"
	@echo " PLATFORM     = $(PLATFORM)"

$(BR)/.bootstrap.ok:
ifeq ("$(shell lsb_release -si)", "Ubuntu")
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
ifeq ("$(shell lsb_release -si)", "Ubuntu")
	@sudo apt-get -y install $(DEB_DEPENDS)
else ifneq ("$(wildcard /etc/redhat-release)","")
	@sudo yum groupinstall -y $(RPM_DEPENDS_GROUPS)
	@sudo yum install -y $(RPM_DEPENDS)
	@sudo yum install -y --enablerepo=epel $(EPEL_DEPENDS)
else
	$(error "This option currently works only on Ubuntu or Centos systems")
endif

define make
	@make -C $(BR) V=$(V) PLATFORM=$(PLATFORM) TAG=$(1) $(2)
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

STARTUP_DIR ?= $(PWD)
ifeq ("$(wildcard $(STARTUP_CONF))","")
define run
	@echo "WARNING: STARTUP_CONF not defined or file doesn't exist."
	@echo "         Running with minimal startup config: $(MINIMAL_STARTUP_CONF)\n"
	@cd $(STARTUP_DIR) && sudo $(1) $(MINIMAL_STARTUP_CONF)
endef
else
define run
	@cd $(STARTUP_DIR) && sudo $(1) -c $(STARTUP_CONF)
endef
endif

%.files: .FORCE
	@find . \( -name '*\.[chyS]' -o -name '*\.java' -o -name '*\.lex' \) -and \
		\( -not -path './build-root*' -o -path \
		'./build-root/build-vpp_debug-native/dpdk*' \) > $@

.FORCE:

run:
	$(call run, $(BR)/install-$(PLATFORM)_debug-native/vpp/bin/vpp)

run-release:
	$(call run, $(BR)/install-$(PLATFORM)-native/vpp/bin/vpp)

debug:
	$(call run, $(GDB) $(GDB_ARGS) --args $(BR)/install-$(PLATFORM)_debug-native/vpp/bin/vpp)

debug-release:
	$(call run, $(GDB) $(GDB_ARGS) --args $(BR)/install-$(PLATFORM)-native/vpp/bin/vpp)

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

cscope: cscope.files
	@cscope -b -q -v
