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

# Pick up per-platform makefile fragments
$(foreach d,$(SOURCE_PATH_BUILD_DATA_DIRS),	\
  $(eval -include $(d)/platforms/*.mk))

.PHONY: install-deb
install-deb: $(patsubst %,%-find-source,$(ROOT_PACKAGES))
	@$(BUILD_ENV) ;							\
	set -eu$(BUILD_DEBUG) ;						\
	$(MAKE) -C $(MU_BUILD_ROOT_DIR)					\
	    $(patsubst %,%-install,					\
	      $(ROOT_PACKAGES))	|| exit 1;				\
									\
	: generate file manifests ;					\
	find $(INSTALL_PREFIX)$(ARCH)/*/bin -type f -print		\
	  | sed -e 's:.*:../& /usr/bin:'				\
	    > deb/debian/vpp.install ;					\
	find $(INSTALL_PREFIX)$(ARCH)/*/lib*  -type f -print		\
	  | egrep -e '*\.so\.*\.*\.*'					\
	  | sed -e 's:.*:../& /usr/lib/x86_64-linux-gnu:'		\
	    > deb/debian/vpp-lib.install ;				\
									\
	: dev package ;							\
	./scripts/find-dev-contents $(INSTALL_PREFIX)$(ARCH)		\
	 deb/debian/vpp-dev.install ;					\
									\
	: dpdk headers ;						\
	./scripts/find-dpdk-contents $(INSTALL_PREFIX)$(ARCH)		\
	 deb/debian/vpp-dpdk-dev.install ;				\
									\
	: bin package needs startup config ; 				\
	echo ../../vpp/conf/startup.conf /etc/vpp 			\
	   >> deb/debian/vpp.install ;					\
									\
	: and sysctl config ; 						\
	echo ../../vpp/conf/80-vpp.conf /etc/sysctl.d 			\
	   >> deb/debian/vpp.install ;					\
									\
	: dev package needs a couple of additions ;			\
        echo ../build-tool-native/vppapigen/vppapigen /usr/bin		\
           >> deb/debian/vpp-dev.install ;				\
									\
	: generate changelog;						\
	./scripts/generate-deb-changelog 				\
									\
	: Go fabricate the actual Debian packages ;			\
	(								\
	cd deb &&							\
	dpkg-buildpackage -us -uc -b					\
	)

.PHONY: install-rpm
install-rpm: $(patsubst %,%-find-source,$(ROOT_PACKAGES))
	@$(BUILD_ENV) ;							\
	set -eu$(BUILD_DEBUG) ;						\
	$(MAKE) -C $(MU_BUILD_ROOT_DIR)					\
	    $(patsubst %,%-install,					\
	      $(ROOT_PACKAGES))	|| exit 1;				\
									\
	cd rpm ;							\
	rpmbuild -bb --define "_topdir $$PWD"  vpp.spec ; 		\
	mv $$(find RPMS -name \*.rpm -type f) ..

