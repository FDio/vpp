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
# jvpp-common
#

nobase_include_HEADERS =		\
  jvpp-common/jvpp_common.h

lib_LTLIBRARIES += libjvpp_common.la

libjvpp_common_la_SOURCES = jvpp-common/jvpp_common.c
libjvpp_common_la_LIBADD = -lvlibmemoryclient -lvlibapi -lsvm -lvppinfra \
	              -lpthread -lm -lrt
libjvpp_common_la_LDFLAGS = -module
libjvpp_common_la_CPPFLAGS = -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux


#
# jvpp-registry (connection management + plugin registry)
#
lib_LTLIBRARIES += libjvpp_registry.la

libjvpp_registry_la_SOURCES = jvpp-registry/jvpp_registry.c
libjvpp_registry_la_LIBADD = -lvlibmemoryclient -lvlibapi -lsvm -lvppinfra \
	              -lpthread -lm -lrt -ljvpp_common
libjvpp_registry_la_LDFLAGS = -module
libjvpp_registry_la_CPPFLAGS = -Ijvpp-registry -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux
EXTRA_libjvpp_registry_la_DEPENDENCIES=libjvpp_common.la

jarfile_jvpp_registry = jvpp-registry-$(PACKAGE_VERSION).jar
packagedir_jvpp_registry = io/fd/vpp/jvpp

BUILT_SOURCES += jvpp-registry/io_fd_vpp_jvpp_VppJNIConnection.h

jvpp_registry_src_files := $(wildcard @srcdir@/jvpp-registry/$(packagedir_jvpp_registry)/*.java) $(wildcard @srcdir@/jvpp-registry/$(packagedir_jvpp_registry)/**/*.java)

jvpp-registry/io_fd_vpp_jvpp_VppJNIConnection.h: $(jvpp_registry_src_files)
	@echo " jvpp-registry.jar generation"
	mkdir -p jvpp-registry/target
	$(JAVAC) -d jvpp-registry/target $(jvpp_registry_src_files)
	$(JAVAH) -force -classpath jvpp-registry/target -d jvpp-registry io.fd.vpp.jvpp.VppJNIConnection
	$(JAVAH) -force -classpath jvpp-registry/target -d jvpp-registry io.fd.vpp.jvpp.JVppRegistryImpl

$(jarfile_jvpp_registry): libjvpp_registry.la
	cp .libs/libjvpp_registry.so.0.0.0 jvpp-registry/target;	\
	$(JAR) cf $(JARFLAGS) $@ -C jvpp-registry/target .;

#
# jvpp-core (Java wrapper for vpe.api)
#
lib_LTLIBRARIES += libjvpp_core.la

libjvpp_core_la_SOURCES = jvpp-core/jvpp_core.c jvpp-core/jvpp_core_gen.h
libjvpp_core_la_LIBADD = -lvlibmemoryclient -lvlibapi -lsvm -lvppinfra \
	              -lpthread -lm -lrt -ljvpp_common
libjvpp_core_la_LDFLAGS = -module
libjvpp_core_la_CPPFLAGS = -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux

jarfile_jvpp_core = jvpp-core-$(PACKAGE_VERSION).jar
packagedir_jvpp_core = io/fd/vpp/jvpp/core

BUILT_SOURCES += jvpp-core/io_fd_vpp_jvpp_core_JVppCoreImpl.h

jvpp-core/io_fd_vpp_jvpp_core_JVppCoreImpl.h:		\
    jvpp-registry/io_fd_vpp_jvpp_VppJNIConnection.h	\
    $(prefix)/../vnet/vnet/af_packet.api.json		\
    $(prefix)/../vnet/vnet/netmap.api.json		\
    $(prefix)/../vnet/vnet/vhost_user.api.json		\
    $(prefix)/../vpp/vpp-api/vpe.api.json		\
    $(prefix)/../vnet/vnet/gre.api.json			\
    $(prefix)/../vnet/vnet/ip.api.json 			\
    $(prefix)/../vnet/vnet/l2tp.api.json		\
    $(prefix)/../vnet/vnet/tap.api.json 		\
    $(prefix)/../vnet/vnet/vxlan.api.json		\
    $(prefix)/../vnet/vnet/vxlan_gpe.api.json	\
    $(prefix)/../vnet/vnet/tap.api.json			\
    $(prefix)/../vnet/vnet/bfd.api.json			\
    $(prefix)/../vnet/vnet/ipsec.api.json
	cp -rf @srcdir@/jvpp-core/* -t jvpp-core/
	mkdir -p jvpp-core/target
	cd jvpp-core \
		&& mkdir -p types dto future callfacade callback notification \
		&& @srcdir@/jvpp/gen/jvpp_gen.py  --plugin_name core \
		    -i $(prefix)/../vpp/vpp-api/vpe.api.json \
		    $(prefix)/../vnet/vnet/af_packet.api.json \
		    $(prefix)/../vnet/vnet/netmap.api.json \
		    $(prefix)/../vnet/vnet/vhost_user.api.json \
		    $(prefix)/../vnet/vnet/gre.api.json \
		    $(prefix)/../vnet/vnet/interface.api.json \
		    $(prefix)/../vnet/vnet/l2.api.json \
		    $(prefix)/../vnet/vnet/l2tp.api.json \
		    $(prefix)/../vnet/vnet/map.api.json \
		    $(prefix)/../vnet/vnet/ip.api.json \
		    $(prefix)/../vnet/vnet/span.api.json \
		    $(prefix)/../vnet/vnet/tap.api.json \
		    $(prefix)/../vnet/vnet/vxlan.api.json \
		    $(prefix)/../vnet/vnet/vxlan_gpe.api.json \
		    $(prefix)/../vnet/vnet/bfd.api.json \
		    $(prefix)/../vnet/vnet/ipsec.api.json \
		&& cp -rf types dto future callfacade callback notification *.java -t $(packagedir_jvpp_core) \
		&& rm -rf types dto future callfacade callback notification *.java

	$(JAVAC) -classpath jvpp-registry/target -d jvpp-core/target jvpp-core/$(packagedir_jvpp_core)/*.java \
		jvpp-core/$(packagedir_jvpp_core)/types/*.java \
		jvpp-core/$(packagedir_jvpp_core)/dto/*.java \
		jvpp-core/$(packagedir_jvpp_core)/callback/*.java \
		jvpp-core/$(packagedir_jvpp_core)/notification/*.java \
		jvpp-core/$(packagedir_jvpp_core)/future/*.java 	\
		jvpp-core/$(packagedir_jvpp_core)/callfacade/*.java 	\
		jvpp-core/$(packagedir_jvpp_core)/test/*.java 	\
		|| (echo "jvpp-core compilation failed: $$?"; exit 1)
	$(JAVAH) -force -classpath jvpp-registry/target:jvpp-core/target -d jvpp-core io.fd.vpp.jvpp.core.JVppCoreImpl

$(jarfile_jvpp_core): libjvpp_core.la
	cp .libs/libjvpp_core.so.0.0.0 jvpp-core/target
	$(JAR) cf $(JARFLAGS) $@ -C jvpp-core/target .

all-local: $(jarfile_jvpp_registry) $(jarfile_jvpp_core)
