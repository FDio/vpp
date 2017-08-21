# Copyright (c) 2016 Cisco and/or its affiliates.
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

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4
AM_LIBTOOLFLAGS = --quiet

AM_CFLAGS = -Wall -I${top_srcdir} -I${top_builddir} \
  -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux \
  -I@top_srcdir@/plugins -I@top_builddir@/plugins

AM_LDFLAGS = -shared -avoid-version -rpath /none -no-undefined

BUILT_SOURCES =
bin_PROGRAMS =
noinst_LTLIBRARIES =
JAR_FILES =
CLEANDIRS =

#
# jvpp-common
#

nobase_include_HEADERS =                \
  jvpp-common/jvpp_common.h

lib_LTLIBRARIES = libjvpp_common.la
libjvpp_common_la_SOURCES = jvpp-common/jvpp_common.c
libjvpp_common_la_LDFLAGS = shared -rpath /none -no-undefined

JVPP_LIBS = \
  libjvpp_common.la \
  $(top_builddir)/libvppinfra.la \
  $(top_builddir)/libvlibmemoryclient.la \
  $(top_builddir)/libsvm.la \
  -lpthread -lm -lrt

#
# jvpp-registry (connection management + plugin registry)
#

noinst_LTLIBRARIES += libjvpp_registry.la

libjvpp_registry_la_SOURCES = jvpp-registry/jvpp_registry.c
libjvpp_registry_la_CPPFLAGS = -Ijvpp-registry
libjvpp_registry_la_LIBADD = $(JVPP_LIBS)
libjvpp_registry_la_DEPENDENCIES = libjvpp_common.la

packagedir_jvpp_registry = io/fd/vpp/jvpp
jvpp_registry_src_files := \
  $(wildcard @srcdir@/jvpp-registry/$(packagedir_jvpp_registry)/*.java) \
  $(wildcard @srcdir@/jvpp-registry/$(packagedir_jvpp_registry)/**/*.java)

BUILT_SOURCES += jvpp-registry/io_fd_vpp_jvpp_VppJNIConnection.h
CLEANDIRS += jvpp-registry/target
JAR_FILES += jvpp-registry-$(PACKAGE_VERSION).jar

jvpp_registry_ok = jvpp-registry/io_fd_vpp_jvpp_VppJNIConnection.h

jvpp-registry/io_fd_vpp_jvpp_VppJNIConnection.h: $(jvpp_registry_src_files)
	@echo "  JAPIGEN  $@"
	@rm -rf jvpp-registry/target
	@mkdir -p jvpp-registry/target
	@$(JAVAC) -d jvpp-registry/target $^
	@$(JAVAH) -force -classpath jvpp-registry/target -d jvpp-registry io.fd.vpp.jvpp.VppJNIConnection
	@$(JAVAH) -force -classpath jvpp-registry/target -d jvpp-registry io.fd.vpp.jvpp.JVppRegistryImpl
	@touch jvpp-registry.ok

define japigen
	@echo "  JAPIGEN  $@"
	@rm -rf jvpp-$(1)/target
	@ @srcdir@/jvpp/gen/jvpp_gen.py --plugin_name $(1) --root_dir jvpp-$(1) \
	  -i $(jvpp_$(1)_json_files) > /dev/null
	@find jvpp-$(1)/target -name \*.java > jvpp-$(1).generated.files
	@find @srcdir@/jvpp-$(1) -name \*.java > jvpp-$(1).static.files
	@$(JAVAC) -classpath jvpp-registry/target \
	  -d jvpp-$(1)/target @jvpp-$(1).generated.files @jvpp-$(1).static.files
	@$(JAVAH) -force \
	  -classpath jvpp-registry/target:jvpp-$(1)/target \
	  -d jvpp-$(1) io.fd.vpp.jvpp.$(1).$(2)
endef

#
# jvpp-core (Java wrapper for vpe.api)
#
noinst_LTLIBRARIES += libjvpp_core.la
libjvpp_core_la_SOURCES = jvpp-core/jvpp_core.c jvpp-core/jvpp_core_gen.h
libjvpp_core_la_CPPFLAGS = -Ijvpp-registry -Ijvpp-core
libjvpp_core_la_LIBADD = $(JVPP_LIBS)
libjvpp_core_la_DEPENDENCIES = libjvpp_common.la

BUILT_SOURCES += jvpp-core/io_fd_vpp_jvpp_core_JVppCoreImpl.h
JAR_FILES += jvpp-core-$(PACKAGE_VERSION).jar
CLEANDIRS += jvpp-core/target
jvpp_core_json_files = $(shell find @top_builddir@/vnet/ -type f -name '*.api.json')
jvpp_core_json_files += @top_builddir@/vpp/api/vpe.api.json

jvpp-core/io_fd_vpp_jvpp_core_JVppCoreImpl.h: $(jvpp_registry_ok) $(jvpp_core_json_files)
	$(call japigen,core,JVppCoreImpl)

#
# ACL Plugin
#
if ENABLE_ACL_PLUGIN
noinst_LTLIBRARIES += libjvpp_acl.la
libjvpp_acl_la_SOURCES = jvpp-acl/jvpp_acl.c
libjvpp_acl_la_CPPFLAGS = -Ijvpp-acl
libjvpp_acl_la_LIBADD = $(JVPP_LIBS)
libjvpp_acl_la_DEPENDENCIES = libjvpp_common.la

BUILT_SOURCES += jvpp-acl/io_fd_vpp_jvpp_acl_JVppAclImpl.h
JAR_FILES += jvpp-acl-$(PACKAGE_VERSION).jar
CLEANDIRS += jvpp-acl/target

jvpp_acl_json_files = @top_builddir@/plugins/acl/acl.api.json

jvpp-acl/io_fd_vpp_jvpp_acl_JVppAclImpl.h: $(jvpp_registry_ok) $(jvpp_acl_json_files)
	$(call japigen,acl,JVppAclImpl)
endif

#
# GTPU Plugin
#
if ENABLE_GTPU_PLUGIN
noinst_LTLIBRARIES += libjvpp_gtpu.la
libjvpp_gtpu_la_SOURCES = jvpp-gtpu/jvpp_gtpu.c
libjvpp_gtpu_la_CPPFLAGS = -Ijvpp-gtpu
libjvpp_gtpu_la_LIBADD = $(JVPP_LIBS)
libjvpp_gtpu_la_DEPENDENCIES = libjvpp_common.la

BUILT_SOURCES += jvpp-gtpu/io_fd_vpp_jvpp_gtpu_JVppGtpuImpl.h
JAR_FILES += jvpp-gtpu-$(PACKAGE_VERSION).jar
CLEANDIRS += jvpp-gtpu/target

jvpp_gtpu_json_files = @top_builddir@/plugins/gtpu/gtpu.api.json

jvpp-gtpu/io_fd_vpp_jvpp_gtpu_JVppGtpuImpl.h: $(jvpp_registry_ok) $(jvpp_gtpu_json_files)
	$(call japigen,gtpu,JVppGtpuImpl)
endif

#
# PPPOE Plugin
#
if ENABLE_PPPOE_PLUGIN
noinst_LTLIBRARIES += libjvpp_pppoe.la
libjvpp_pppoe_la_SOURCES = jvpp-pppoe/jvpp_pppoe.c
libjvpp_pppoe_la_CPPFLAGS = -Ijvpp-pppoe
libjvpp_pppoe_la_LIBADD = $(JVPP_LIBS)
libjvpp_pppoe_la_DEPENDENCIES = libjvpp_common.la

BUILT_SOURCES += jvpp-pppoe/io_fd_vpp_jvpp_pppoe_JVppPppoeImpl.h
JAR_FILES += jvpp-pppoe-$(PACKAGE_VERSION).jar
CLEANDIRS += jvpp-pppoe/target

jvpp_pppoe_json_files = @top_builddir@/plugins/pppoe/pppoe.api.json

jvpp-pppoe/io_fd_vpp_jvpp_pppoe_JVppPppoeImpl.h: $(jvpp_registry_ok) $(jvpp_pppoe_json_files)
	$(call japigen,pppoe,JVppPppoeImpl)
endif

#
# NAT Plugin
#
if ENABLE_NAT_PLUGIN
noinst_LTLIBRARIES += libjvpp_nat.la
libjvpp_nat_la_SOURCES = jvpp-nat/jvpp_nat.c
libjvpp_nat_la_CPPFLAGS = -Ijvpp-nat
libjvpp_nat_la_LIBADD = $(JVPP_LIBS)
libjvpp_nat_la_DEPENDENCIES = libjvpp_common.la

BUILT_SOURCES += jvpp-nat/io_fd_vpp_jvpp_nat_JVppNatImpl.h
JAR_FILES += jvpp-nat-$(PACKAGE_VERSION).jar
CLEANDIRS += jvpp-nat/target

jvpp_nat_json_files = @top_builddir@/plugins/nat/nat.api.json

jvpp-nat/io_fd_vpp_jvpp_nat_JVppNatImpl.h: $(jvpp_registry_ok) $(jvpp_nat_json_files)
	$(call japigen,nat,JVppNatImpl)
endif

#
# iOAM Trace Plugin
#
if ENABLE_IOAM_PLUGIN
noinst_LTLIBRARIES += libjvpp_ioamtrace.la
libjvpp_ioamtrace_la_SOURCES = jvpp-ioamtrace/jvpp_ioam_trace.c
libjvpp_ioamtrace_la_LIBADD = $(JVPP_LIBS)
libjvpp_ioamtrace_la_DEPENDENCIES = libjvpp_common.la

BUILT_SOURCES += jvpp-ioamtrace/io_fd_vpp_jvpp_ioamtrace_JVppIoamtraceImpl.h
JAR_FILES += jvpp-ioamtrace-$(PACKAGE_VERSION).jar
CLEANDIRS += jvpp-ioamtrace/target

jvpp_ioamtrace_json_files = @top_builddir@/plugins/ioam/lib-trace/trace.api.json

jvpp-ioamtrace/io_fd_vpp_jvpp_ioamtrace_JVppIoamtraceImpl.h: $(jvpp_registry_ok) $(jvpp_ioamtrace_json_files)
	$(call japigen,ioamtrace,JVppIoamtraceImpl)

#
# iOAM POT Plugin
#
noinst_LTLIBRARIES += libjvpp_ioampot.la
libjvpp_ioampot_la_SOURCES = jvpp-ioampot/jvpp_ioam_pot.c
libjvpp_ioampot_la_LIBADD = $(JVPP_LIBS)
libjvpp_ioampot_la_DEPENDENCIES = libjvpp_common.la

BUILT_SOURCES += jvpp-ioampot/io_fd_vpp_jvpp_ioampot_JVppIoampotImpl.h
JAR_FILES += jvpp-ioampot-$(PACKAGE_VERSION).jar
CLEANDIRS += jvpp-ioampot/target

jvpp_ioampot_json_files = @top_builddir@/plugins/ioam/lib-pot/pot.api.json

jvpp-ioampot/io_fd_vpp_jvpp_ioampot_JVppIoampotImpl.h: $(jvpp_registry_ok) $(jvpp_ioampot_json_files)
	$(call japigen,ioampot,JVppIoampotImpl)

#
# iOAM Export Plugin
#
noinst_LTLIBRARIES += libjvpp_ioamexport.la
libjvpp_ioamexport_la_SOURCES = jvpp-ioamexport/jvpp_ioam_export.c
libjvpp_ioamexport_la_LIBADD = $(JVPP_LIBS)
libjvpp_ioamexport_la_DEPENDENCIES = libjvpp_common.la

BUILT_SOURCES += jvpp-ioamexport/io_fd_vpp_jvpp_ioamexport_JVppIoamexportImpl.h
JAR_FILES += jvpp-ioamexport-$(PACKAGE_VERSION).jar
CLEANDIRS += jvpp-ioamexport/target

jvpp_ioamexport_json_files = @top_builddir@/plugins/ioam/export/ioam_export.api.json

jvpp-ioamexport/io_fd_vpp_jvpp_ioamexport_JVppIoamexportImpl.h: $(jvpp_registry_ok) $(jvpp_ioamexport_json_files)
	$(call japigen,ioamexport,JVppIoamexportImpl)
endif

#
# JAR creation
#
jvpp-%-$(PACKAGE_VERSION).jar: libjvpp_%.la
	@echo "  JAR      $@"
	@cp .libs/libjvpp_$*.so jvpp-$*/target
	@$(JAR) cf $(JARFLAGS) $@ -C jvpp-$*/target .

jardir = $(prefix)/share/java
jar_DATA = $(JAR_FILES)

all-local: $(JAR_FILES)

#
# Cleanup
#
CLEANFILES = jvpp-registry.ok $(JAR_FILES) $(BUILT_SOURCES) *.files */*.h

clean-local:
	rm -rf $(CLEANDIRS)
