# Copyright (c) 2024 Cisco and/or its affiliates.
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

PKG_SUFFIX ?= $(shell git log --oneline v$(PKG_VERSION)-rc0.. . | wc -l)

include ../build_common.mk
include ../packages_common.mk

ifneq ($(shell uname), FreeBSD)
include packages/openssl.mk
endif	# ! FreeBSD

.PHONY: clean
clean:
	@rm -rf $(B) $(I)

.PHONY: install
ifeq ($(shell uname), FreeBSD)
install:
else
install: openssl-install
endif	# FreeBSD

.PHONY: config
ifeq ($(shell uname), FreeBSD)
config:
else
config: openssl-config
endif	# FreeBSD

##############################################################################
# .deb packaging
##############################################################################

DEB_VER := $(PKG_VERSION)
DEB_ARCH=$(shell dpkg --print-architecture 2> /dev/null)
DEV_DEB=vpp-opt-deps_$(DEB_VER)-$(PKG_SUFFIX)_$(DEB_ARCH).deb
INSTALLED_VER=$(shell dpkg-query --showformat='$${Version}' --show vpp-opt-deps 2> /dev/null)

.PHONY: build-deb install-deb check-deb

deb/debian/changelog: Makefile
	@echo "vpp-opt-deps ($(DEB_VER)-$(PKG_SUFFIX)) unstable; urgency=low" > $@
	@echo "" >> $@
	@echo "  * Version $(DEB_VER)" >> $@
	@echo "" >> $@
	@echo " -- VPP Dev <vpp-dev@lists.fd.io>  $(shell date -R --date=@${SOURCE_DATE_EPOCH})" >> $@

$(DEV_DEB): deb/debian/changelog
	@cd deb && dpkg-buildpackage -b -uc -us
	git clean -fdx deb

build-deb: $(DEV_DEB)

install-deb:
ifneq ($(INSTALLED_VER),$(DEB_VER)-$(PKG_SUFFIX))
	@$(MAKE) $(DEV_DEB)
	@sudo dpkg -i $(DEV_DEB)
else
	@echo "=========================================================="
	@echo " Up-to-date vpp-opt-deps package already installed"
	@echo "=========================================================="
endif

check-deb:
ifneq ($(INSTALLED_VER),$(DEB_VER)-$(PKG_SUFFIX))
	@echo "=========================================================="
	@echo " Out of date vpp-opt-deps package installed."
	@echo " Installed: $(INSTALLED_VER)"
	@echo " Needed: $(DEB_VER)-$(PKG_SUFFIX)"
	@echo ""
	@echo " Please upgrade by invoking 'make install-opt-deps'"
	@echo " from the top level directory."
	@echo "=========================================================="
endif

##############################################################################
# .rpm packaging
##############################################################################

RPM_VER := $(PKG_VERSION)
RPM_ARCH=$(shell rpm --eval "%{_arch}" 2> /dev/null)
DEV_RPM=vpp-opt-deps-$(RPM_VER)-$(PKG_SUFFIX).$(RPM_ARCH).rpm
INSTALLED_RPM_VER=$(shell rpm -q --queryformat '%{VERSION}-%{RELEASE}' vpp-opt-deps 2> /dev/null | grep -v "vpp-opt-deps")

.PHONY: build-rpm install-rpm check-rpm

$(DEV_RPM): Makefile rpm/vpp-opt-deps.spec
	@rpmbuild -bb \
	  --define "_topdir $(CURDIR)/rpm" \
	  --define "_version $(RPM_VER)" \
	  --define "_release $(PKG_SUFFIX)" \
	  $(CURDIR)/rpm/vpp-opt-deps.spec
	mv rpm/RPMS/$(RPM_ARCH)/*.rpm .
	@git clean -fdx rpm

build-rpm: $(DEV_RPM)

install-rpm:
ifneq ($(INSTALLED_RPM_VER),$(RPM_VER)-$(PKG_SUFFIX))
	@$(MAKE) $(DEV_RPM)
	sudo rpm -e vpp-opt-deps || true
	sudo rpm -Uih --force $(DEV_RPM)
else
	@echo "=========================================================="
	@echo " Up-to-date vpp-opt-deps package already installed"
	@echo "=========================================================="
endif

check-rpm:
ifneq ($(INSTALLED_RPM_VER),$(RPM_VER)-$(PKG_SUFFIX))
	@echo "=========================================================="
	@echo " Out of date vpp-opt-deps package installed."
	@echo " Installed: $(INSTALLED_RPM_VER)"
	@echo " Needed: $(RPM_VER)-$(PKG_SUFFIX)"
	@echo ""
	@echo " Please upgrade by invoking 'make install-opt-deps'"
	@echo " from the top level directory."
	@echo "=========================================================="
endif

##############################################################################
# ebuild support
##############################################################################

.PHONY: ebuild-build ebuild-install

ebuild-build:
ifeq ($(INSTALLED_VER)$(INSTALLED_RPM_VER),)
	@echo "=========================================================="
	@echo "Building vpp-opt-deps from source. Consider installing"
	@echo "development package by invoking 'make install-opt-deps'"
	@echo "from the top level directory"
	@echo "=========================================================="
	$(MAKE) config
else
ifneq ($(INSTALLED_VER),)
	$(MAKE) check-deb
endif
ifneq ($(INSTALLED_RPM_VER),)
	$(MAKE) check-rpm
endif
endif

ebuild-install:
ifeq ($(INSTALLED_VER)$(INSTALLED_RPM_VER),)
	$(MAKE) install
endif
