
# Copyright (c) <current-year> <your-organization>
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

AUTOMAKE_OPTIONS = foreign subdir-objects

AM_CFLAGS = -Wall @DPDK@
AM_LDFLAGS = -module -shared -avoid-version

vppapitestpluginsdir = ${libdir}/vpp_api_test_plugins
vpppluginsdir = ${libdir}/vpp_plugins

vppapitestplugins_LTLIBRARIES = snat_test_plugin.la
vppplugins_LTLIBRARIES = snat_plugin.la

snat_plugin_la_SOURCES = snat/snat.c		\
        snat/in2out.c				\
        snat/out2in.c				\
	snat/snat_plugin.api.h

BUILT_SOURCES = snat/snat.api.h snat/snat.py

SUFFIXES = .api.h .api

%.api.h: %.api
	mkdir -p `dirname $@` ; \
	$(CC) $(CPPFLAGS) -E -P -C -x c $^ \
	| vppapigen --input - --output $@ --show-name $@

%.py: %.api
	$(info Creating Python binding for $@)
	$(CC) $(CPPFLAGS) -E -P -C -x c $<				\
	| vppapigen --input - --python -				\
	| pyvppapigen.py --input - > $@

pyapidir = ${prefix}/vpp_papi_plugins
pyapi_DATA = snat/snat.py

noinst_HEADERS =			\
  snat/snat_all_api_h.h			\
  snat/snat_msg_enum.h			\
  snat/snat.api.h

snat_test_plugin_la_SOURCES = \
  snat/snat_test.c snat/snat_plugin.api.h

# Remove *.la files
install-data-hook:
	@(cd $(vpppluginsdir) && $(RM) $(vppplugins_LTLIBRARIES))
	@(cd $(vppapitestpluginsdir) && $(RM) $(vppapitestplugins_LTLIBRARIES))



#
# Java code generation
#
jvpp_registry_root = ../../vpp-api/java
jvpp_registry_version = 16.12
jsnat_jarfile = jvpp-snat-$(PACKAGE_VERSION).jar
jvpp_package_dir = io/fd/vpp/jvpp/snat
jvpp_root = snat/jvpp
jvpp_target_dir = target
jvpp_target = $(jvpp_root)/$(jvpp_target_dir)
api_file=$(srcdir)/snat/snat.api

lib_LTLIBRARIES = libjvpp_snat.la
libjvpp_snat_la_SOURCES = snat/snat.api.h snat/jvpp_snat.c snat/jvpp/io_fd_vpp_jvpp_snat_JVppSnatImpl.h
libjvpp_snat_la_LIBADD = -lvlibmemoryclient -lvlibapi -lvppinfra \
	              -lpthread -lm -lrt -L$(jvpp_registry_root)/.libs -ljvpp_common
libjvpp_snat_la_LDFLAGS = -module
libjvpp_snat_la_CPPFLAGS = -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux -I../ -I$(srcdir)/../

BUILT_SOURCES += $(jvpp_root)/io_fd_vpp_jvpp_snat_JVppSnatImpl.h

$(jvpp_root)/io_fd_vpp_jvpp_snat_JVppSnatImpl.h: defs_snat_papi.py
	dir=`pwd`;						\
	mkdir -p $(jvpp_target); \
	mkdir -p $(jvpp_root)/$(jvpp_package_dir); 		\
	cd $(jvpp_root)/$(jvpp_package_dir);			\
	mkdir -p dto future callfacade callback notification test; 	\
	@srcdir@/$(jvpp_registry_root)/jvpp/gen/jvpp_gen.py -i $${dir}/defs_snat_papi.py --plugin_name snat;		\
	cd -;							\
	mv -f $(jvpp_root)/$(jvpp_package_dir)/jvpp_snat_gen.h $(jvpp_root)/jvpp_snat_gen.h;							\
	cp $(srcdir)/$(jvpp_root)/$(jvpp_package_dir)/test/*.java $(jvpp_root)/$(jvpp_package_dir)/test/;				\
	cd $(jvpp_root);				\
	$(JAVAC) -classpath .:$(jvpp_target_dir):../../$(jvpp_registry_root)/jvpp-registry-$(jvpp_registry_version).jar -d $(jvpp_target_dir) $(jvpp_package_dir)/*.java \
		$(jvpp_package_dir)/dto/*.java \
		$(jvpp_package_dir)/callback/*.java \
		$(jvpp_package_dir)/notification/*.java \
		$(jvpp_package_dir)/future/*.java 	\
		$(jvpp_package_dir)/callfacade/*.java 	\
		$(jvpp_package_dir)/test/*.java \
		|| (echo "snat jvpp compilation failed: $$?"; exit 1);	\
	$(JAVAH) -classpath .:$(jvpp_target_dir):../../$(jvpp_registry_root)/jvpp-registry-$(jvpp_registry_version).jar -d . io.fd.vpp.jvpp.snat.JVppSnatImpl ;

$(jsnat_jarfile): libjvpp_snat.la
	cp .libs/libjvpp_snat.so.0.0.0 $(jvpp_target);				\
	cd $(jvpp_target);				\
	$(JAR) cfv $(JARFLAGS) ../../../$@ libjvpp_snat.so.0.0.0 $(jvpp_package_dir)/* ; cd ..;

defs_snat_papi.py:
	@echo "  jSnat_sfc API"; \
        vppapigen --input $(api_file) --python defs_snat_papi.py;

all-local: $(jsnat_jarfile)
