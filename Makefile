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

export WS_ROOT=$(CURDIR)
export BR=$(WS_ROOT)/build-root
CCACHE_DIR?=$(BR)/.ccache
GDB?=gdb
PLATFORM?=vpp
SAMPLE_PLUGIN?=no
STARTUP_DIR?=$(PWD)
MACHINE=$(shell uname -m)
SUDO?=sudo
DPDK_CONFIG?=no-pci

,:=,
define disable_plugins
$(if $(1), \
  "plugins {" \
  $(patsubst %,"plugin %_plugin.so { disable }",$(subst $(,), ,$(1))) \
  " }" \
  ,)
endef

MINIMAL_STARTUP_CONF="							\
unix { 									\
	interactive 							\
	cli-listen /run/vpp/cli.sock					\
	gid $(shell id -g)						\
	$(if $(wildcard startup.vpp),"exec startup.vpp",)		\
}									\
$(if $(DPDK_CONFIG), "dpdk { $(DPDK_CONFIG) }",)			\
$(call disable_plugins,$(DISABLED_PLUGINS))				\
"

GDB_ARGS= -ex "handle SIGUSR1 noprint nostop"

#
# OS Detection
#
# We allow Darwin (MacOS) for docs generation; VPP build will still fail.
ifneq ($(shell uname),Darwin)
OS_ID        = $(shell grep '^ID=' /etc/os-release | cut -f2- -d= | sed -e 's/\"//g')
OS_VERSION_ID= $(shell grep '^VERSION_ID=' /etc/os-release | cut -f2- -d= | sed -e 's/\"//g')
endif

ifeq ($(filter ubuntu debian,$(OS_ID)),$(OS_ID))
PKG=deb
else ifeq ($(filter rhel centos fedora opensuse opensuse-leap opensuse-tumbleweed,$(OS_ID)),$(OS_ID))
PKG=rpm
endif

# +libganglia1-dev if building the gmond plugin

DEB_DEPENDS  = curl build-essential autoconf automake ccache
DEB_DEPENDS += debhelper dkms git libtool libapr1-dev dh-systemd
DEB_DEPENDS += libconfuse-dev git-review exuberant-ctags cscope pkg-config
DEB_DEPENDS += lcov chrpath autoconf indent clang-format libnuma-dev
DEB_DEPENDS += python-all python3-all python3-setuptools python-dev
DEB_DEPENDS += python-virtualenv python-pip libffi6 check
DEB_DEPENDS += libboost-all-dev libffi-dev python3-ply libmbedtls-dev
DEB_DEPENDS += cmake ninja-build uuid-dev python3-jsonschema python3-yaml
DEB_DEPENDS += python3-venv  # ensurepip
DEB_DEPENDS += python3-dev   # needed for python3 -m pip install psutil
# python3.6 on 16.04 requires python36-dev
 
ifeq ($(OS_VERSION_ID),14.04)
	DEB_DEPENDS += libssl-dev
else ifeq ($(OS_ID)-$(OS_VERSION_ID),debian-8)
	DEB_DEPENDS += libssl-dev
	APT_ARGS = -t jessie-backports
else ifeq ($(OS_ID)-$(OS_VERSION_ID),debian-9)
	DEB_DEPENDS += libssl1.0-dev
else
	DEB_DEPENDS += libssl-dev
endif

RPM_DEPENDS  = redhat-lsb glibc-static
RPM_DEPENDS += apr-devel
RPM_DEPENDS += numactl-devel
RPM_DEPENDS += check check-devel
RPM_DEPENDS += boost boost-devel
RPM_DEPENDS += selinux-policy selinux-policy-devel
RPM_DEPENDS += ninja-build
RPM_DEPENDS += libuuid-devel
RPM_DEPENDS += mbedtls-devel
RPM_DEPENDS += python3-devel  # needed for python3 -m pip install psutil

ifeq ($(OS_ID),fedora)
	RPM_DEPENDS += dnf-utils
	RPM_DEPENDS += subunit subunit-devel
	RPM_DEPENDS += compat-openssl10-devel
	RPM_DEPENDS += python3-ply  # for vppapigen
	RPM_DEPENDS += python3-virtualenv python3-jsonschema
	RPM_DEPENDS += cmake
	RPM_DEPENDS_GROUPS = 'C Development Tools and Libraries'
else ifeq ($(OS_ID)-$(OS_VERSION_ID),centos-8)
	RPM_DEPENDS += dnf-utils
	RPM_DEPENDS += compat-openssl10
	RPM_DEPENDS += python3-devel python3-ply
	RPM_DEPENDS += python3-virtualenv python3-jsonschema
	RPM_DEPENDS += cmake
	RPM_DEPENDS_GROUPS = 'Development Tools'
else
	RPM_DEPENDS += yum-utils
	RPM_DEPENDS += openssl-devel
	RPM_DEPENDS += python36-ply  # for vppapigen
	RPM_DEPENDS += python3-devel python3-pip
	RPM_DEPENDS += python-virtualenv python36-jsonschema
	RPM_DEPENDS += devtoolset-7
	RPM_DEPENDS += cmake3
	RPM_DEPENDS_GROUPS = 'Development Tools'
endif

# +ganglia-devel if building the ganglia plugin

RPM_DEPENDS += chrpath libffi-devel rpm-build
# lowercase- replace spaces with dashes.
SUSE_NAME= $(shell grep '^NAME=' /etc/os-release | cut -f2- -d= | sed -e 's/\"//g' | sed -e 's/ /-/' | awk '{print tolower($$0)}')
SUSE_ID= $(shell grep '^VERSION_ID=' /etc/os-release | cut -f2- -d= | sed -e 's/\"//g' | cut -d' ' -f2)
RPM_SUSE_BUILDTOOLS_DEPS = autoconf automake ccache check-devel chrpath
RPM_SUSE_BUILDTOOLS_DEPS += clang cmake indent libtool make ninja python3-ply

RPM_SUSE_DEVEL_DEPS = glibc-devel-static libnuma-devel
RPM_SUSE_DEVEL_DEPS += libopenssl-devel openssl-devel mbedtls-devel libuuid-devel

RPM_SUSE_PYTHON_DEPS = python-devel python3-devel python-pip python3-pip
RPM_SUSE_PYTHON_DEPS += python-rpm-macros python3-rpm-macros

RPM_SUSE_PLATFORM_DEPS = distribution-release shadow rpm-build

ifeq ($(OS_ID),opensuse)
ifeq ($(SUSE_NAME),tumbleweed)
	RPM_SUSE_DEVEL_DEPS = libboost_headers1_68_0-devel-1.68.0  libboost_thread1_68_0-devel-1.68.0 gcc
	RPM_SUSE_PYTHON_DEPS += python3-ply python2-virtualenv
endif
ifeq ($(SUSE_ID),15.0)
	RPM_SUSE_DEVEL_DEPS += libboost_headers-devel libboost_thread-devel gcc
	RPM_SUSE_PYTHON_DEPS += python3-ply python2-virtualenv
else
	RPM_SUSE_DEVEL_DEPS += libboost_headers1_68_0-devel-1.68.0 gcc6
	RPM_SUSE_PYTHON_DEPS += python-virtualenv
endif
endif

ifeq ($(OS_ID),opensuse-leap)
ifeq ($(SUSE_ID),15.0)
	RPM_SUSE_DEVEL_DEPS += libboost_headers-devel libboost_thread-devel gcc git curl
	RPM_SUSE_PYTHON_DEPS += python3-ply python2-virtualenv
endif
endif

RPM_SUSE_DEPENDS += $(RPM_SUSE_BUILDTOOLS_DEPS) $(RPM_SUSE_DEVEL_DEPS) $(RPM_SUSE_PYTHON_DEPS) $(RPM_SUSE_PLATFORM_DEPS)

ifneq ($(wildcard $(STARTUP_DIR)/startup.conf),)
        STARTUP_CONF ?= $(STARTUP_DIR)/startup.conf
endif

ifeq ($(findstring y,$(UNATTENDED)),y)
CONFIRM=-y
FORCE=--force-yes
endif

TARGETS = vpp

ifneq ($(SAMPLE_PLUGIN),no)
TARGETS += sample-plugin
endif

define banner
	@echo "========================================================================"
	@echo " $(1)"
	@echo "========================================================================"
	@echo " "
endef

.PHONY: help
help:
	@echo "Make Targets:"
	@echo " install-dep[s]       - install software dependencies"
	@echo " wipe                 - wipe all products of debug build "
	@echo " wipe-release         - wipe all products of release build "
	@echo " build                - build debug binaries"
	@echo " build-release        - build release binaries"
	@echo " build-coverity       - build coverity artifacts"
	@echo " rebuild              - wipe and build debug binaries"
	@echo " rebuild-release      - wipe and build release binaries"
	@echo " run                  - run debug binary"
	@echo " run-release          - run release binary"
	@echo " debug                - run debug binary with debugger"
	@echo " debug-release        - run release binary with debugger"
	@echo " test                 - build and run tests"
	@echo " test-help            - show help on test framework"
	@echo " run-vat              - run vpp-api-test tool"
	@echo " pkg-deb              - build DEB packages"
	@echo " pkg-deb-debug        - build DEB debug packages"
	@echo " vom-pkg-deb          - build vom DEB packages"
	@echo " vom-pkg-deb-debug    - build vom DEB debug packages"
	@echo " pkg-rpm              - build RPM packages"
	@echo " install-ext-dep[s]   - install external development dependencies"
	@echo " ctags                - (re)generate ctags database"
	@echo " gtags                - (re)generate gtags database"
	@echo " cscope               - (re)generate cscope database"
	@echo " checkstyle           - check coding style"
	@echo " checkstyle-commit    - check commit message format"
	@echo " checkstyle-test      - check test framework coding style"
	@echo " fixstyle             - fix coding style"
	@echo " doxygen              - (re)generate documentation"
	@echo " bootstrap-doxygen    - setup Doxygen dependencies"
	@echo " wipe-doxygen         - wipe all generated documentation"
	@echo " checkfeaturelist     - check FEATURE.yaml according to schema"
	@echo " featurelist          - dump feature list in markdown"
	@echo " json-api-files       - (re)-generate json api files"
	@echo " json-api-files-debug - (re)-generate json api files for debug target"
	@echo " docs                 - Build the Sphinx documentation"
	@echo " docs-venv            - Build the virtual environment for the Sphinx docs"
	@echo " docs-clean           - Remove the generated files from the Sphinx docs"
	@echo ""
	@echo "Make Arguments:"
	@echo " V=[0|1]                  - set build verbosity level"
	@echo " STARTUP_CONF=<path>      - startup configuration file"
	@echo "                            (e.g. /etc/vpp/startup.conf)"
	@echo " STARTUP_DIR=<path>       - startup directory (e.g. /etc/vpp)"
	@echo "                            It also sets STARTUP_CONF if"
	@echo "                            startup.conf file is present"
	@echo " GDB=<path>               - gdb binary to use for debugging"
	@echo " PLATFORM=<name>          - target platform. default is vpp"
	@echo " TEST=<filter>            - apply filter to test set, see test-help"
	@echo " DPDK_CONFIG=<conf>       - add specified dpdk config commands to"
	@echo "                            autogenerated startup.conf"
	@echo "                            (e.g. \"no-pci\" )"
	@echo " SAMPLE_PLUGIN=yes        - in addition build/run/debug sample plugin"
	@echo " DISABLED_PLUGINS=<list>  - comma separated list of plugins which"
	@echo "                            should not be loaded"
	@echo ""
	@echo "Current Argument Values:"
	@echo " V                 = $(V)"
	@echo " STARTUP_CONF      = $(STARTUP_CONF)"
	@echo " STARTUP_DIR       = $(STARTUP_DIR)"
	@echo " GDB               = $(GDB)"
	@echo " PLATFORM          = $(PLATFORM)"
	@echo " DPDK_VERSION      = $(DPDK_VERSION)"
	@echo " DPDK_CONFIG       = $(DPDK_CONFIG)"
	@echo " SAMPLE_PLUGIN     = $(SAMPLE_PLUGIN)"
	@echo " DISABLED_PLUGINS  = $(DISABLED_PLUGINS)"

$(BR)/.deps.ok:
ifeq ($(findstring y,$(UNATTENDED)),y)
	make install-dep
endif
ifeq ($(filter ubuntu debian,$(OS_ID)),$(OS_ID))
	@MISSING=$$(apt-get install -y -qq -s $(DEB_DEPENDS) | grep "^Inst ") ; \
	if [ -n "$$MISSING" ] ; then \
	  echo "\nPlease install missing packages: \n$$MISSING\n" ; \
	  echo "by executing \"make install-dep\"\n" ; \
	  exit 1 ; \
	fi ; \
	exit 0
else ifneq ("$(wildcard /etc/redhat-release)","")
	@for i in $(RPM_DEPENDS) ; do \
	    RPM=$$(basename -s .rpm "$${i##*/}" | cut -d- -f1,2,3)  ;	\
	    MISSING+=$$(rpm -q $$RPM | grep "^package")	   ;    \
	done							   ;	\
	if [ -n "$$MISSING" ] ; then \
	  echo "Please install missing RPMs: \n$$MISSING\n" ; \
	  echo "by executing \"make install-dep\"\n" ; \
	  exit 1 ; \
	fi ; \
	exit 0
endif
	@touch $@

.PHONY: bootstrap
bootstrap:
	@echo "'make bootstrap' is not needed anymore"

.PHONY: install-dep
install-dep:
ifeq ($(filter ubuntu debian,$(OS_ID)),$(OS_ID))
ifeq ($(OS_VERSION_ID),14.04)
	@sudo -E apt-get $(CONFIRM) $(FORCE) install software-properties-common
endif
ifeq ($(OS_ID)-$(OS_VERSION_ID),debian-8)
	@grep -q jessie-backports /etc/apt/sources.list /etc/apt/sources.list.d/* 2> /dev/null \
           || ( echo "Please install jessie-backports" ; exit 1 )
endif
	@sudo -E apt-get update
	@sudo -E apt-get $(APT_ARGS) $(CONFIRM) $(FORCE) install $(DEB_DEPENDS)
else ifneq ("$(wildcard /etc/redhat-release)","")
ifeq ($(OS_ID),rhel)
	@sudo -E yum-config-manager --enable rhel-server-rhscl-7-rpms
	@sudo -E yum groupinstall $(CONFIRM) $(RPM_DEPENDS_GROUPS)
	@sudo -E yum install $(CONFIRM) $(RPM_DEPENDS)
	@sudo -E debuginfo-install $(CONFIRM) glibc openssl-libs mbedtls-devel zlib
else ifeq ($(OS_ID)-$(OS_VERSION_ID),centos-8)
	@sudo -E dnf groupinstall $(CONFIRM) $(RPM_DEPENDS_GROUPS)
	@sudo -E dnf install $(CONFIRM) $(RPM_DEPENDS)
else ifeq ($(OS_ID),centos)
	@sudo -E yum install $(CONFIRM) centos-release-scl-rh epel-release
	@sudo -E yum groupinstall $(CONFIRM) $(RPM_DEPENDS_GROUPS)
	@sudo -E yum install $(CONFIRM) $(RPM_DEPENDS)
	@sudo -E debuginfo-install $(CONFIRM) glibc openssl-libs mbedtls-devel zlib
else ifeq ($(OS_ID),fedora)
	@sudo -E dnf groupinstall $(CONFIRM) $(RPM_DEPENDS_GROUPS)
	@sudo -E dnf install $(CONFIRM) $(RPM_DEPENDS)
	@sudo -E debuginfo-install $(CONFIRM) glibc openssl-libs mbedtls-devel zlib
endif
else ifeq ($(filter opensuse-tumbleweed,$(OS_ID)),$(OS_ID))
	@sudo -E zypper refresh
	@sudo -E zypper install -y $(RPM_SUSE_DEPENDS)
else ifeq ($(filter opensuse-leap,$(OS_ID)),$(OS_ID))
	@sudo -E zypper refresh
	@sudo -E zypper install  -y $(RPM_SUSE_DEPENDS)
else ifeq ($(filter opensuse,$(OS_ID)),$(OS_ID))
	@sudo -E zypper refresh
	@sudo -E zypper install -y $(RPM_SUSE_DEPENDS)
else
	$(error "This option currently works only on Ubuntu, Debian, RHEL, CentOS or openSUSE systems")
endif
	git config commit.template .git_commit_template.txt

.PHONY: install-deps
install-deps: install-dep

define make
	@make -C $(BR) PLATFORM=$(PLATFORM) TAG=$(1) $(2)
endef

$(BR)/scripts/.version:
ifneq ("$(wildcard /etc/redhat-release)","")
	$(shell $(BR)/scripts/version rpm-string > $(BR)/scripts/.version)
else
	$(shell $(BR)/scripts/version > $(BR)/scripts/.version)
endif

DIST_FILE = $(BR)/vpp-$(shell src/scripts/version).tar
DIST_SUBDIR = vpp-$(shell src/scripts/version|cut -f1 -d-)

.PHONY: dist
dist:
	@if git rev-parse 2> /dev/null ; then \
	    git archive \
	      --prefix=$(DIST_SUBDIR)/ \
	      --format=tar \
	      -o $(DIST_FILE) \
	    HEAD ; \
	    git describe > $(BR)/.version ; \
	else \
	    (cd .. ; tar -cf $(DIST_FILE) $(DIST_SUBDIR) --exclude=*.tar) ; \
	    src/scripts/version > $(BR)/.version ; \
	fi
	@tar --append \
	  --file $(DIST_FILE) \
	  --transform='s,.*/.version,$(DIST_SUBDIR)/src/scripts/.version,' \
	  $(BR)/.version
	@$(RM) $(BR)/.version $(DIST_FILE).xz
	@xz -v --threads=0 $(DIST_FILE)
	@$(RM) $(BR)/vpp-latest.tar.xz
	@ln -rs $(DIST_FILE).xz $(BR)/vpp-latest.tar.xz

.PHONY: build
build: $(BR)/.deps.ok
	$(call make,$(PLATFORM)_debug,$(addsuffix -install,$(TARGETS)))

.PHONY: wipedist
wipedist:
	@$(RM) $(BR)/*.tar.xz

.PHONY: wipe
wipe: wipedist test-wipe $(BR)/.deps.ok
	$(call make,$(PLATFORM)_debug,$(addsuffix -wipe,$(TARGETS)))
	@find . -type f -name "*.api.json" ! -path "./test/*" -exec rm {} \;

.PHONY: rebuild
rebuild: wipe build

.PHONY: build-release
build-release: $(BR)/.deps.ok
	$(call make,$(PLATFORM),$(addsuffix -install,$(TARGETS)))

.PHONY: wipe-release
wipe-release: test-wipe $(BR)/.deps.ok
	$(call make,$(PLATFORM),$(addsuffix -wipe,$(TARGETS)))

.PHONY: rebuild-release
rebuild-release: wipe-release build-release

libexpand = $(subst $(subst ,, ),:,$(foreach lib,$(1),$(BR)/install-$(2)-native/vpp/$(lib)/$(3)))

export TEST_DIR ?= $(WS_ROOT)/test
export RND_SEED ?= $(shell python3 -c 'import time; print(time.time())')

define test
	$(if $(filter-out $(3),retest),make -C $(BR) PLATFORM=$(1) TAG=$(2) vpp-install,)
	$(eval libs:=lib lib64)
	make -C test \
	  VPP_BUILD_DIR=$(BR)/build-$(2)-native \
	  VPP_BIN=$(BR)/install-$(2)-native/vpp/bin/vpp \
	  VPP_PLUGIN_PATH=$(call libexpand,$(libs),$(2),vpp_plugins) \
	  VPP_TEST_PLUGIN_PATH=$(call libexpand,$(libs),$(2),vpp_api_test_plugins) \
	  VPP_INSTALL_PATH=$(BR)/install-$(2)-native/ \
	  LD_LIBRARY_PATH=$(call libexpand,$(libs),$(2),) \
	  EXTENDED_TESTS=$(EXTENDED_TESTS) \
	  PYTHON=$(PYTHON) \
	  OS_ID=$(OS_ID) \
	  RND_SEED=$(RND_SEED) \
	  CACHE_OUTPUT=$(CACHE_OUTPUT) \
	  $(3)
endef

.PHONY: test
test:
	$(call test,vpp,vpp,test)

.PHONY: test-debug
test-debug:
	$(call test,vpp,vpp_debug,test)

.PHONY: test-gcov
test-gcov:
	$(call test,vpp,vpp_gcov,test)

.PHONY: test-all
test-all:
	$(if $(filter-out $(3),retest),make -C $(BR) PLATFORM=vpp TAG=vpp vom-install,)
	$(eval EXTENDED_TESTS=yes)
	$(call test,vpp,vpp,test)

.PHONY: test-all-debug
test-all-debug:
	$(if $(filter-out $(3),retest),make -C $(BR) PLATFORM=vpp TAG=vpp_debug vom-install,)
	$(eval EXTENDED_TESTS=yes)
	$(call test,vpp,vpp_debug,test)

.PHONY: papi-wipe
papi-wipe: test-wipe-papi
	$(call banner,"This command is deprecated. Please use 'test-wipe-papi'")

.PHONY: test-wipe-papi
test-wipe-papi:
	@make -C test papi-wipe

.PHONY: test-help
test-help:
	@make -C test help

.PHONY: test-wipe
test-wipe:
	@make -C test wipe

.PHONY: test-shell
test-shell:
	$(call test,vpp,vpp,shell)

.PHONY: test-shell-debug
test-shell-debug:
	$(call test,vpp,vpp_debug,shell)

.PHONY: test-shell-gcov
test-shell-gcov:
	$(call test,vpp,vpp_gcov,shell)

.PHONY: test-dep
test-dep:
	@make -C test test-dep

.PHONY: test-doc
test-doc:
	@make -C test doc

.PHONY: test-wipe-doc
test-wipe-doc:
	@make -C test wipe-doc

.PHONY: test-cov
test-cov:
	@make -C $(BR) PLATFORM=vpp TAG=vpp_gcov vom-install
	$(eval EXTENDED_TESTS=yes)
	$(call test,vpp,vpp_gcov,cov)

.PHONY: test-wipe-cov
test-wipe-cov:
	@make -C test wipe-cov

.PHONY: test-wipe-all
test-wipe-all:
	@make -C test wipe-all

.PHONY: test-checkstyle
test-checkstyle:
	@make -C test checkstyle

.PHONY: test-refresh-deps
test-refresh-deps:
	@make -C test refresh-deps

.PHONY: retest
retest:
	$(call test,vpp,vpp,retest)

.PHONY: retest-debug
retest-debug:
	$(call test,vpp,vpp_debug,retest)

.PHONY: retest-all
retest-all:
	$(eval EXTENDED_TESTS=yes)
	$(call test,vpp,vpp,retest)

.PHONY: retest-all-debug
retest-all-debug:
	$(eval EXTENDED_TESTS=yes)
	$(call test,vpp,vpp_debug,retest)

ifeq ("$(wildcard $(STARTUP_CONF))","")
define run
	@echo "WARNING: STARTUP_CONF not defined or file doesn't exist."
	@echo "         Running with minimal startup config: $(MINIMAL_STARTUP_CONF)\n"
	@cd $(STARTUP_DIR) && \
	  $(SUDO) $(2) $(1)/vpp/bin/vpp $(MINIMAL_STARTUP_CONF)
endef
else
define run
	@cd $(STARTUP_DIR) && \
	  $(SUDO) $(2) $(1)/vpp/bin/vpp $(shell cat $(STARTUP_CONF) | sed -e 's/#.*//')
endef
endif

%.files: .FORCE
	@find . \( -name '*\.[chyS]' -o -name '*\.java' -o -name '*\.lex' \) -and \
		\( -not -path './build-root*' -o -path \
		'./build-root/build-vpp_debug-native/dpdk*' \) > $@

.FORCE:

.PHONY: run
run:
	$(call run, $(BR)/install-$(PLATFORM)_debug-native)

.PHONY: run-release
run-release:
	$(call run, $(BR)/install-$(PLATFORM)-native)

.PHONY: debug
debug:
	$(call run, $(BR)/install-$(PLATFORM)_debug-native,$(GDB) $(GDB_ARGS) --args)

.PHONY: build-coverity
build-coverity:
	$(call make,$(PLATFORM)_coverity,install-packages)

.PHONY: debug-release
debug-release:
	$(call run, $(BR)/install-$(PLATFORM)-native,$(GDB) $(GDB_ARGS) --args)

.PHONY: build-vat
build-vat:
	$(call make,$(PLATFORM)_debug,vpp-api-test-install)

.PHONY: run-vat
run-vat:
	@$(SUDO) $(BR)/install-$(PLATFORM)_debug-native/vpp/bin/vpp_api_test

.PHONY: pkg-deb
pkg-deb:
	$(call make,$(PLATFORM),vpp-package-deb)

.PHONY: vom-pkg-deb
vom-pkg-deb: pkg-deb
	$(call make,$(PLATFORM),vom-package-deb)

.PHONY: pkg-deb-debug
pkg-deb-debug:
	$(call make,$(PLATFORM)_debug,vpp-package-deb)

.PHONY: vom-pkg-deb-debug
vom-pkg-deb-debug: pkg-deb-debug
	$(call make,$(PLATFORM)_debug,vom-package-deb)

.PHONY: pkg-rpm
pkg-rpm: dist
	make -C extras/rpm

.PHONY: pkg-srpm
pkg-srpm: dist
	make -C extras/rpm srpm

.PHONY: dpdk-install-dev
dpdk-install-dev:
	$(call banner,"This command is deprecated. Please use 'make install-ext-deps'")
	make -C build/external install-$(PKG)

.PHONY: install-ext-deps
install-ext-deps:
	make -C build/external install-$(PKG)

.PHONY: install-ext-dep
install-ext-dep: install-ext-deps

.PHONY: json-api-files
json-api-files:
	$(WS_ROOT)/src/tools/vppapigen/generate_json.py

.PHONY: json-api-files-debug
json-api-files-debug:
	$(WS_ROOT)/src/tools/vppapigen/generate_json.py --debug-target

.PHONY: ctags
ctags: ctags.files
	@ctags --totals --tag-relative -L $<
	@rm $<

.PHONY: gtags
gtags: ctags
	@gtags --gtagslabel=ctags

.PHONY: cscope
cscope: cscope.files
	@cscope -b -q -v

.PHONY: checkstyle
checkstyle: checkfeaturelist
	@build-root/scripts/checkstyle.sh

.PHONY: checkstyle-commit
checkstyle-commit:
	@extras/scripts/check_commit_msg.sh

.PHONY: checkstyle-test
checkstyle-test: test-checkstyle

.PHONY: checkstyle-all
checkstyle-all: checkstyle-commit checkstyle checkstyle-test

.PHONY: fixstyle
fixstyle:
	@build-root/scripts/checkstyle.sh --fix

# necessary because Bug 1696324 - Update to python3.6 breaks PyYAML dependencies
# Status:	CLOSED CANTFIX
# https://bugzilla.redhat.com/show_bug.cgi?id=1696324
.PHONY: centos-pyyaml
centos-pyyaml:
ifeq ($(OS_ID)-$(OS_VERSION_ID),centos-7)
	@python3 -m pip install pyyaml
endif
ifeq ($(OS_ID)-$(OS_VERSION_ID),centos-8)
	@sudo -E yum install $(CONFIRM) python3-pyyaml
endif

.PHONY: featurelist
featurelist: centos-pyyaml
	@build-root/scripts/fts.py --all --markdown

.PHONY: checkfeaturelist
checkfeaturelist: centos-pyyaml
	@build-root/scripts/fts.py --validate --all

#
# Build the documentation
#

# Doxygen configuration and our utility scripts
export DOXY_DIR ?= $(WS_ROOT)/doxygen

define make-doxy
	@OS_ID="$(OS_ID)" make -C $(DOXY_DIR) $@
endef

.PHONY: bootstrap-doxygen
bootstrap-doxygen:
	$(call make-doxy)

.PHONY: doxygen
doxygen: bootstrap-doxygen
	$(call make-doxy)

.PHONY: wipe-doxygen
wipe-doxygen:
	$(call make-doxy)

# Sphinx Documents
export DOCS_DIR = $(WS_ROOT)/docs
export VENV_DIR = $(WS_ROOT)/sphinx_venv
export SPHINX_SCRIPTS_DIR = $(WS_ROOT)/docs/scripts

.PHONY: docs-venv
docs-venv:
	@($(SPHINX_SCRIPTS_DIR)/sphinx-make.sh venv)

.PHONY: docs
docs: $(DOCS_DIR)
	@($(SPHINX_SCRIPTS_DIR)/sphinx-make.sh html)

.PHONY: docs-clean
docs-clean:
	@rm -rf $(DOCS_DIR)/_build
	@rm -rf $(VENV_DIR)

.PHONY: pkg-verify
pkg-verify: install-dep $(BR)/.deps.ok install-ext-deps
	$(call banner,"Building for PLATFORM=vpp using gcc")
	@make -C build-root PLATFORM=vpp TAG=vpp wipe-all install-packages
	$(call banner,"Building sample-plugin")
	@make -C build-root PLATFORM=vpp TAG=vpp sample-plugin-install
	$(call banner,"Building libmemif")
	@make -C build-root PLATFORM=vpp TAG=vpp libmemif-install
	$(call banner,"Building VOM")
	@make -C build-root PLATFORM=vpp TAG=vpp vom-install
	$(call banner,"Building $(PKG) packages")
	@make pkg-$(PKG)
ifeq ($(OS_ID),ubuntu)
	$(call banner,"Building VOM $(PKG) package")
	@make vom-pkg-deb
endif

MAKE_VERIFY_GATE_OS ?= ubuntu-18.04
.PHONY: verify
verify: pkg-verify
ifeq ($(OS_ID)-$(OS_VERSION_ID),$(MAKE_VERIFY_GATE_OS))
	$(call banner,"Testing vppapigen")
	@src/tools/vppapigen/test_vppapigen.py
	$(call banner,"Running tests")
	@make COMPRESS_FAILED_TEST_LOGS=yes RETRIES=3 test
else
	$(call banner,"Skipping tests. Tests under 'make verify' supported on $(MAKE_VERIFY_GATE_OS)")
endif
