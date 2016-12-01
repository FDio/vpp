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
									\
	: core api definitions ;					\
	./scripts/find-api-core-contents $(INSTALL_PREFIX)$(ARCH)	\
	 deb/debian/vpp.install ;					\
									\
	: need symbolic links in the lib pkg ; 				\
	find $(INSTALL_PREFIX)$(ARCH)/*/lib* \( -type f -o  -type l \)  \
	  -print | egrep -e '*\.so\.*\.*\.*'				\
	  | grep -v plugins\/						\
	  | sed -e 's:.*:../& /usr/lib/x86_64-linux-gnu:'		\
	    > deb/debian/vpp-lib.install ;				\
									\
	: vnet api definitions ;					\
	./scripts/find-api-lib-contents $(INSTALL_PREFIX)$(ARCH)	\
	 deb/debian/vpp-lib.install ;					\
									\
	: dev package ;							\
	./scripts/find-dev-contents $(INSTALL_PREFIX)$(ARCH)		\
	 deb/debian/vpp-dev.install ;					\
									\
	: plugins package ;						\
	./scripts/find-plugins-contents $(INSTALL_PREFIX)$(ARCH)	\
	 deb/debian/vpp-plugins.install ;				\
									\
	: python-api package ;						\
	./scripts/find-python-api-contents $(INSTALL_PREFIX)$(ARCH)	\
	 deb/debian/vpp-python-api.install ;				\
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
	echo ../../vpp-api/java/jvpp/gen/jvpp_gen.py /usr/bin		\
	   >> deb/debian/vpp-dev.install ;				\
	for i in $$(ls ../vpp-api/java/jvpp/gen/jvppgen/*.py); do	\
	   echo ../$${i} /usr/lib/python2.7/dist-packages/jvppgen	\
	       >> deb/debian/vpp-dev.install;				\
	done;								\
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
	mkdir -p SOURCES ;                                              \
	if test -f *.tar.gz ; then mv *.tar.gz SOURCES ; fi ;           \
	rpmbuild -bb --define "_topdir $$PWD" --define			\
		"_install_dir $(INSTALL_PREFIX)$(ARCH)"                 \
		--define "_mu_build_root_dir $(MU_BUILD_ROOT_DIR)"      \
		vpp.spec ;                                              \
	mv $$(find RPMS -name \*.rpm -type f) ..

