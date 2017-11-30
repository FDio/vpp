# Copyright (c) 2017 Cisco and/or its affiliates.
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

ifneq ($(shell uname),Darwin)
OS_ID        = $(shell grep '^ID=' /etc/os-release | cut -f2- -d= | sed -e 's/\"//g')
endif

TARBALL=$(shell realpath ../../build-root/vpp-latest.tar.xz)

BASENAME=$(shell basename $(TARBALL) | sed -e s/.tar.\*//)
VERSION=$(shell echo $(BASENAME) | cut -f2 -d-)
RELEASE=$(shell echo $(BASENAME) | cut -f3- -d- | sed -e s/-/_/g)
BR=$(shell realpath $(CURDIR)/../../build-root)
RPMBUILD=$(BR)/rpmbuild
PC=%

all: RPM

ifeq ($(filter opensuse,$(OS_ID)),$(OS_ID))
SPEC_FILE='vpp-suse.spec'
else
SPEC_FILE='vpp.spec'
endif

spec:
	@echo $(TARBALL)
	mkdir -p $(RPMBUILD)/{RPMS,SRPMS,BUILD,SOURCES,SPECS}
	cp $(TARBALL) $(RPMBUILD)/SOURCES/vpp-$(VERSION)-$(RELEASE).tar.xz
	cp $(SPEC_FILE) $(RPMBUILD)/SPECS

srpm: spec
	rpmbuild -bs \
	  --define "_topdir $(RPMBUILD)" \
	  --define "_version $(VERSION)" \
	  --define "_release $(RELEASE)" \
	  $(RPMBUILD)/SPECS/$(SPEC_FILE)
	mv $$(find $(RPMBUILD)/SRPMS -name \*.src.rpm -type f) $(BR)

RPM: spec
	rpmbuild -bb \
	  --define "_topdir $(RPMBUILD)" \
	  --define "_version $(VERSION)" \
	  --define "_release $(RELEASE)" \
	  $(RPMBUILD)/SPECS/$(SPEC_FILE)
	mv $$(find $(RPMBUILD)/RPMS -name \*.rpm -type f) $(BR)
