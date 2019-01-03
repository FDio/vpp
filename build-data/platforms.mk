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
	  | sed -e 's:.*:../& /usr/bin:' | grep -v vppapigen		\
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
	  | sed -e 's:.*:../& /usr/lib/$(MACHINE)-linux-gnu:'		\
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
	: vpp-api-lua package ;						\
	./scripts/find-vpp-api-lua-contents $(INSTALL_PREFIX)$(ARCH)	\
	 deb/debian/vpp-api-lua.install ;				\
									\
	: vpp-api-java package ;					\
	./scripts/find-vpp-api-java-contents $(INSTALL_PREFIX)$(ARCH)	\
	 deb/debian/vpp-api-java.install ;				\
									\
	: bin package needs startup config ; 				\
	echo ../../src/vpp/conf/startup.conf /etc/vpp 			\
	   >> deb/debian/vpp.install ;					\
									\
	: and sysctl config ; 						\
	echo ../../src/vpp/conf/80-vpp.conf /etc/sysctl.d 		\
	   >> deb/debian/vpp.install ;					\
									\
	: bash completion for vppctl ;					\
	echo ../../src/scripts/vppctl_completion /etc/bash_completion.d	\
	   >> deb/debian/vpp.install ;					\
									\
	: add log directory ;						\
	echo /var/log/vpp/						\
	   >> deb/debian/vpp.dirs ;					\
									\
	: dev package needs a couple of additions ;			\
	echo ../$(INSTALL_PREFIX)$(ARCH)/*/bin/vppapigen /usr/bin	\
	   >> deb/debian/vpp-dev.install ;				\
	echo ../$(INSTALL_PREFIX)$(ARCH)/*/share/vpp/vppapigen_c.py /usr/share/vpp  \
	   >> deb/debian/vpp-dev.install ;				\
	echo ../$(INSTALL_PREFIX)$(ARCH)/*/share/vpp/vppapigen_json.py /usr/share/vpp \
	   >> deb/debian/vpp-dev.install ;				\
	echo ../../extras/japi/java/jvpp/gen/jvpp_gen.py /usr/bin	\
	   >> deb/debian/vpp-dev.install ;				\
	for i in $$(ls ../src/vpp-api/java/jvpp/gen/jvppgen/*.py); do	\
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
	dpkg-buildpackage $($(PLATFORM)_dpkg_build_args) -d -us -uc -b	\
	)

