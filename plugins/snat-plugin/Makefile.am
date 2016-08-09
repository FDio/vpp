
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

nobase_include_HEADERS =		\
  snat/jvpp_snat.h

lib_LTLIBRARIES = libjvpp_snat.la

libjvpp_snat_la_SOURCES = snat/jvpp_snat.c snat/jvpp_snat.h jvpp-snat/jvpp_gen.h
libjvpp_snat_la_LIBADD = -lvlibmemoryclient -lvlibapi -lsvm -lvppinfra \
	              -lpthread -lm -lrt
libjvpp_snat_la_LDFLAGS = -module
libjvpp_snat_la_CPPFLAGS = -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux

jarfile_jvpp_snat = jvpp-snat-$(PACKAGE_VERSION).jar
packagedir_jvpp_snat = org/openvpp/jvpp
api_file = $(srcdir)/snat/snat.api

BUILT_SOURCES += jvpp-snat/org_openvpp_jvpp_snat_JVppSnatImpl.h

jvpp-snat/org_openvpp_jvpp_snat_JVppSnatImpl.h: defs_vpp_papi.py
	mkdir -p jvpp-snat/org/openvpp/jvpp/snat/test/; \
	mkdir -p jvpp-snat/target; \
	cp -rf @srcdir@/snat/jvpp/org/openvpp/jvpp/snat/test/* -t jvpp-snat/org/openvpp/jvpp/snat/test/; \
	mkdir dto future callfacade callback notification; \
	@srcdir@/../../vpp-api/java/jvpp/gen/jvpp_gen.py -i defs_vpp_papi.py --plugin_name snat; \
	cp -rf dto future callfacade callback notification *.java -t jvpp-snat/org/openvpp/jvpp/snat/; \
	cp -rf jvpp_gen.h -t jvpp-snat;	\
	rm -rf dto future callfacade callback notification *.java jvpp_gen.h; \
	javac -classpath .:jvpp-snat/target:../../vpp-api/java/jvpp-registry-16.12.jar -d jvpp-snat/target jvpp-snat/org/openvpp/jvpp/snat/*.java \
		jvpp-snat/org/openvpp/jvpp/snat/dto/*.java \
		jvpp-snat/org/openvpp/jvpp/snat/callback/*.java \
		jvpp-snat/org/openvpp/jvpp/snat/notification/*.java \
		jvpp-snat/org/openvpp/jvpp/snat/future/*.java 	\
		jvpp-snat/org/openvpp/jvpp/snat/callfacade/*.java 	\
		jvpp-snat/org/openvpp/jvpp/snat/test/*.java \
		|| (echo "jvpp-snat compilation failed: $$?"; exit 1);
	javah -classpath .:jvpp-snat/target:../../vpp-api/java/jvpp-registry-16.12.jar -d jvpp-snat org.openvpp.jvpp.snat.JVppSnatImpl ;

$(jarfile_jvpp_snat): libjvpp_snat.la
	cp .libs/libjvpp_snat.so.0.0.0 jvpp-snat/target;	\
	cd jvpp-snat/target;	\
	$(JAR) cfv $(JARFLAGS) ../../$@ libjvpp_snat.so.0.0.0 $(packagedir_jvpp_snat)/* ; cd ..;

defs_vpp_papi.py:
	@echo "jVpp API";				\
	vppapigen --input $(api_file) --python defs_vpp_papi.py;