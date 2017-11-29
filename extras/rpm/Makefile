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
OS_VERSION_ID= $(shell grep '^VERSION_ID=' /etc/os-release | cut -f2- -d= | sed -e 's/\"//g')
endif

TARBALL=$(shell realpath ../../build-root/vpp-latest.tar.xz)

BASENAME=$(shell basename $(TARBALL) | sed -e s/.tar.\*//)
VERSION=$(shell echo $(BASENAME) | cut -f2 -d-)
RELEASE=$(shell echo $(BASENAME) | cut -f3- -d- | sed -e s/-/_/g)
PC=%

all: RPM

ifeq ($(filter opensuse,$(OS_ID)),$(OS_ID))
TOPDIR=$(CURDIR)
SPEC_FILE='vpp-suse.spec'
else
TOPDIR=$(PWD)
SPEC_FILE='vpp.spec'
endif

srpm:
	@echo $(TARBALL)
	mkdir -p rpmbuild/{RPMS,SRPMS,BUILD,SOURCES,SPECS}
	cp $(TARBALL) rpmbuild/SOURCES/vpp-$(VERSION)-$(RELEASE).tar.xz
	cp $(SPEC_FILE) rpmbuild/SOURCES
	sed -i '1s/^/$(PC)define _version $(VERSION)\n/' rpmbuild/SOURCES/$(SPEC_FILE)
	sed -i '1s/^/$(PC)define _release $(RELEASE)\n/' rpmbuild/SOURCES/$(SPEC_FILE)
	sed -i '/define _topdir/d' rpmbuild/SOURCES/$(SPEC_FILE)
	rpmbuild -bs \
	  --define "_topdir rpmbuild" \
	  rpmbuild/SOURCES/$(SPEC_FILE)
	mv $$(find rpmbuild/SRPMS -name \*.src.rpm -type f) .

RPM:
	@echo $(TARBALL)
	mkdir -p RPMS SOURCES
	cp $(TARBALL) SOURCES/vpp-$(VERSION)-$(RELEASE).tar.xz
	rpmbuild -bb \
	  --define "_topdir $(TOPDIR)" \
	  --define "_version $(VERSION)" \
	  --define "_release $(RELEASE)" \
	  $(SPEC_FILE)
	mv $$(find RPMS -name \*.rpm -type f) .
