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


TARBALL=$(shell realpath ../../build-root/vpp-latest.tar.xz)

BASENAME=$(shell basename $(TARBALL) | sed -e s/.tar.\*//)
VERSION=$(shell echo $(BASENAME) | cut -f2 -d-)
RELEASE=$(shell echo $(BASENAME) | cut -f3- -d- | sed -e s/-/_/g)

all:
	@echo $(TARBALL)
	mkdir -p SOURCES RPMS
	cp $(TARBALL) SOURCES/vpp-latest.tar.xz
	rpmbuild -bb \
	  --define "_topdir $(PWD)" \
	  --define "_version $(VERSION)" \
	  --define "_release $(RELEASE)" \
	  vpp.spec
	mv $$(find RPMS -name \*.rpm -type f) .
