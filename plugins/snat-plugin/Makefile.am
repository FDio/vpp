
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

nobase_include_HEADERS = snat/jvpp/org_openvpp_jvpp_snat_JVppSnatImpl.h

jarfile_jsnat_sfc = jsnat-$(PACKAGE_VERSION).jar
# fixme update dirs after package in jvpp is changed from org.openvpp.jvpp to io.fd.vpp
java_packagedir = org/openvpp/jvpp/snat
java_gendir = snat/jvpp
api_file=$(srcdir)/snat/snat.api
#jvpp_gen = jvpp_gen.py

lib_LTLIBRARIES = libjvpp_snat.la
libjvpp_snat_la_SOURCES = snat/snat.api.h snat/jvpp_snat.c snat/jvpp/org_openvpp_jvpp_snat_JVppSnatImpl.h
libjvpp_snat_la_LIBADD = -lvlibmemoryclient -lvlibapi -lsvm -lvppinfra \
	              -lpthread -lm -lrt -ljvpp_common
libjvpp_snat_la_LDFLAGS = -module
libjvpp_snat_la_CPPFLAGS = -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux -I../ -I$(srcdir)/../

BUILT_SOURCES += snat/jvpp/org_openvpp_jvpp_snat_JVppSnatImpl.h

# FIXME!!!! Fix paths to jvpp_gen and jars
# FIXME!!!! How does cleanup work here ?

snat/jvpp/org_openvpp_jvpp_snat_JVppSnatImpl.h: defs_snat_papi.py
	dir=`pwd`;						\
	mkdir -p $(java_gendir)/target; \
	mkdir -p $(java_gendir)/$(java_packagedir); 		\
	cd $(java_gendir)/$(java_packagedir);			\
	mkdir -p dto future callfacade callback notification test; 	\
	@srcdir@/../../vpp-api/java/jvpp/gen/jvpp_gen.py -i $${dir}/defs_snat_papi.py --plugin_name snat --control_ping_class SnatControlPing;		\
	cd -;							\
	mv -f $(java_gendir)/$(java_packagedir)/jvpp_snat_gen.h snat/jvpp/jvpp_snat_gen.h;							\
	cp $(srcdir)/$(java_gendir)/$(java_packagedir)/test/*.java $(java_gendir)/$(java_packagedir)/test/;				\
	cd $(java_gendir);				\
	javac -classpath .:target:../../../../vpp-api/java/jvpp-registry-16.12.jar -d target $(java_packagedir)/*.java \
		$(java_packagedir)/dto/*.java \
		$(java_packagedir)/callback/*.java \
		$(java_packagedir)/notification/*.java \
		$(java_packagedir)/future/*.java 	\
		$(java_packagedir)/callfacade/*.java 	\
		$(java_packagedir)/test/*.java \
		|| (echo "snat/jvpp compilation failed: $$?"; exit 1);	\
	javah -classpath .:target:../../../../vpp-api/java/jvpp-registry-16.12.jar -d . org.openvpp.jvpp.snat.JVppSnatImpl ;

$(jarfile_jsnat_sfc): libjvpp_snat.la
	cp .libs/libjvpp_snat.so.0.0.0 $(java_gendir)/target;				\
	cd $(java_gendir)/target;				\
	jar cfv $(JARFLAGS) ../../../$@ libjvpp_snat.so.0.0.0 $(java_packagedir)/* ; cd ..;

defs_snat_papi.py:
	@echo "  jSnat_sfc API"; \
        vppapigen --input $(api_file) --python defs_snat_papi.py;

all-local: $(jarfile_jsnat_sfc)
