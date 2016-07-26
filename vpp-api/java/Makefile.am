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

AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = -Wall 

noinst_PROGRAMS = 
BUILT_SOURCES =
bin_PROGRAMS = 
CLEANFILES = 
lib_LTLIBRARIES = 


#
# jvpp-registry (connection management + plugin registry)
#

nobase_include_HEADERS =		\
  jvpp-registry/org_openvpp_jvpp_VppJNIConnection.h \
  jvpp-registry/jvpp_registry.h

lib_LTLIBRARIES += libjvpp_registry.la

libjvpp_registry_la_SOURCES = jvpp/jvpp_registry.c
libjvpp_registry_la_LIBADD = -lvlibmemoryclient -lvlibapi -lsvm -lvppinfra \
	              -lpthread -lm -lrt
libjvpp_registry_la_LDFLAGS = -module
libjvpp_registry_la_CPPFLAGS = -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux

jarfile_jvpp_registry = jvpp-registry-$(PACKAGE_VERSION).jar
packagedir_jvpp_registry = org/openvpp/jvpp
jvpp_gen = jvpp_gen.py

BUILT_SOURCES += jvpp-registry/org_openvpp_jvpp_VppJNIConnection.h


jvpp-registry/org_openvpp_jvpp_VppJNIConnection.h:
	@echo " jvpp-registry.jar generation ";				\
	mkdir jvpp-registry;				\
	cp -rf @srcdir@/jvpp/* -t jvpp-registry/;
	$(JAVAC) -classpath . -d . jvpp-registry/org/openvpp/jvpp/*.java \
		jvpp-registry/org/openvpp/jvpp/dto/*.java  \
		jvpp-registry/org/openvpp/jvpp/callback/*.java \
		jvpp-registry/org/openvpp/jvpp/notification/*.java \
		jvpp-registry/org/openvpp/jvpp/future/*.java 	\
		jvpp-registry/org/openvpp/jvpp/test/*.java 	\
		|| (echo "jvpp-registry compilation failed: $$?"; exit 1);	\
	$(JAVAH) -classpath . -d jvpp-registry org.openvpp.jvpp.VppJNIConnection ;

$(jarfile_jvpp_registry): libjvpp_registry.la
	cd .libs ; $(JAR) cf $(JARFLAGS) ../$@ libjvpp_registry.so.0.0.0 ../$(packagedir_jvpp_registry)/* ; cd ..;


#
# jvpp-core (Java wrapper for vpe.api)
#

nobase_include_HEADERS +=		\
  jvpp/jvpp_core.h

lib_LTLIBRARIES += libjvpp_core.la

libjvpp_core_la_SOURCES = jvpp/jvpp_core.c jvpp/jvpp_core.h jvpp-core/jvpp_gen.h
libjvpp_core_la_LIBADD = -lvlibmemoryclient -lvlibapi -lsvm -lvppinfra \
	              -lpthread -lm -lrt
libjvpp_core_la_LDFLAGS = -module
libjvpp_core_la_CPPFLAGS = -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux

jarfile_jvpp_core = jvpp-core-$(PACKAGE_VERSION).jar
packagedir_jvpp_core = org/openvpp/jvpp
api_file = $(prefix)/../vpp/vpp-api/vpe.api

BUILT_SOURCES += jvpp-core/org_openvpp_jvpp_core_JVppCoreImpl.h

# TODO: split jvpp dir into jvpp-registry and jvpp-core and move api/test to jvpp-core

jvpp-core/org_openvpp_jvpp_core_JVppCoreImpl.h: defs_vpp_papi.py
	mkdir -p jvpp-core/org/openvpp/jvpp/core/test/; \
	mkdir -p jvpp-core/target; \
	cp -rf @srcdir@/jvpp/org/openvpp/jvpp/core/test/* -t jvpp-core/org/openvpp/jvpp/core/test/; \
	mkdir dto future callfacade callback notification; \
	./jvpp-registry/gen/jvpp_gen.py -i defs_vpp_papi.py --plugin_name core; \
	cp -rf dto future callfacade callback notification *.java -t jvpp-core/org/openvpp/jvpp/core/; \
	cp -rf jvpp_gen.h -t jvpp-core;	\
	rm -rf dto future callfacade callback notification *.java jvpp_gen.h; \
	$(JAVAC) -classpath .:jvpp-core/target:jvpp-registry-16.09.jar -d jvpp-core/target jvpp-core/org/openvpp/jvpp/core/*.java \
		jvpp-core/org/openvpp/jvpp/core/dto/*.java \
		jvpp-core/org/openvpp/jvpp/core/callback/*.java \
		jvpp-core/org/openvpp/jvpp/core/notification/*.java \
		jvpp-core/org/openvpp/jvpp/core/future/*.java 	\
		jvpp-core/org/openvpp/jvpp/core/callfacade/*.java 	\
		jvpp-core/org/openvpp/jvpp/core/test/*.java \
		|| (echo "jvpp-core compilation failed: $$?"; exit 1);
	$(JAVAH) -classpath .:jvpp-core/target:jvpp-registry-16.09.jar -d jvpp-core org.openvpp.jvpp.core.JVppCoreImpl ;

$(jarfile_jvpp_core): libjvpp_core.la
	cp .libs/libjvpp_core.so.0.0.0 jvpp-core/target;	\
	cd jvpp-core/target;	\
	$(JAR) cfv $(JARFLAGS) ../../$@ libjvpp_core.so.0.0.0 $(packagedir_jvpp_core)/* ; cd ..;

defs_vpp_papi.py:
	@echo "jVpp API";				\
	vppapigen --input $(api_file) --python defs_vpp_papi.py;
        
all-local: $(jarfile_jvpp_registry) $(jarfile_jvpp_core)
