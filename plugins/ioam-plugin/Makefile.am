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

AM_CFLAGS = -Wall
AM_LDFLAGS = -module -shared -avoid-version

########################################
# iOAM Proof of Transit
########################################

ioam_pot_plugin_la_SOURCES =			\
	ioam/lib-pot/pot_util.c			\
	ioam/encap/ip6_ioam_pot.c		\
	ioam/lib-pot/pot_util.h			\
	ioam/lib-pot/math64.h			\
	ioam/lib-pot/pot_api.c

BUILT_SOURCES =					\
	ioam/lib-pot/pot.api.h			\
	ioam/lib-pot/pot.api.json

SUFFIXES = .api.h .api

%.api.h: %.api
	mkdir -p `dirname $@` ; \
	$(CC) $(CPPFLAGS) -E -P -C -x c $^ \
	| vppapigen --input - --output $@ --show-name $@

%.api.json: %.api
	@echo "  JSON APIGEN  " $@ ;				\
	mkdir -p `dirname $@` ;					\
	$(CC) $(CPPFLAGS) -E -P -C -x c $^			\
	| vppapigen --input - --json $@

apidir = $(prefix)/ioam/
api_DATA =					\
	ioam/lib-pot/pot.api.json		\
	ioam/lib-trace/trace.api.json		\
	ioam/export/ioam_export.api.json

noinst_HEADERS =				\
  ioam/lib-pot/pot_all_api_h.h			\
  ioam/lib-pot/pot_msg_enum.h			\
  ioam/lib-pot/pot.api.h			\
  ioam/lib-pot/pot_util.h			\
  ioam/lib-pot/math64.h

ioam_pot_test_plugin_la_SOURCES =		\
	ioam/lib-pot/pot_test.c			\
	ioam/lib-pot/pot_plugin.api.h

vppapitestpluginsdir = ${libdir}/vpp_api_test_plugins
vpppluginsdir = ${libdir}/vpp_plugins

vppapitestplugins_LTLIBRARIES = ioam_pot_test_plugin.la
vppplugins_LTLIBRARIES = ioam_pot_plugin.la

########################################
# iOAM trace export for IPv6
########################################

ioam_export_plugin_la_SOURCES =   \
ioam/export/ioam_export.c         \
ioam/export/node.c                \
ioam/export/ioam_export.api.h     \
ioam/export/ioam_export_thread.c

BUILT_SOURCES +=				\
	ioam/export/ioam_export.api.h		\
	ioam/export/ioam_export.api.json

noinst_HEADERS +=                       \
  ioam/export/ioam_export_all_api_h.h   \
  ioam/export/ioam_export_msg_enum.h    \
  ioam/export/ioam_export.api.h

ioam_export_test_plugin_la_SOURCES =  \
  ioam/export/ioam_export_test.c      \
  ioam/export/ioam_export_plugin.api.h

vppapitestplugins_LTLIBRARIES += ioam_export_test_plugin.la
vppplugins_LTLIBRARIES += ioam_export_plugin.la

########################################
# iOAM Trace
########################################
libioam_trace_plugin_la_SOURCES =		\
	ioam/lib-trace/trace_util.c		\
	ioam/encap/ip6_ioam_trace.c		\
	ioam/lib-trace/trace_util.h		\
	ioam/lib-trace/trace_api.c

BUILT_SOURCES +=				\
	ioam/lib-trace/trace.api.h		\
	ioam/lib-trace/trace.api.json

noinst_HEADERS +=                       \
  ioam/export/ioam_export_all_api_h.h   \
  ioam/lib-trace/trace_all_api_h.h	\
  ioam/lib-trace/trace_msg_enum.h	\
  ioam/lib-trace/trace.api.h		\
  ioam/lib-trace/trace_util.h

ioam_trace_test_plugin_la_SOURCES =		\
	ioam/lib-trace/trace_test.c		\
	ioam/lib-trace/trace_plugin.api.h

vppapitestplugins_LTLIBRARIES += ioam_trace_test_plugin.la
vppplugins_LTLIBRARIES += libioam_trace_plugin.la

########################################
# VxLAN-GPE
########################################
libioam_vxlan_gpe_plugin_la_SOURCES =			\
	ioam/lib-vxlan-gpe/ioam_encap.c			\
	ioam/lib-vxlan-gpe/ioam_decap.c			\
	ioam/lib-vxlan-gpe/ioam_transit.c		\
	ioam/lib-vxlan-gpe/ioam_pop.c			\
	ioam/lib-vxlan-gpe/vxlan_gpe_api.c		\
	ioam/lib-vxlan-gpe/vxlan_gpe_ioam_trace.c	\
	ioam/lib-vxlan-gpe/vxlan_gpe_ioam.c		\
	ioam/export-vxlan-gpe/vxlan_gpe_ioam_export.c	\
	ioam/export-vxlan-gpe/vxlan_gpe_node.c		\
	ioam/export-vxlan-gpe/vxlan_gpe_ioam_export.api.h\
	ioam/export-vxlan-gpe/vxlan_gpe_ioam_export_thread.c

BUILT_SOURCES +=				\
	ioam/lib-vxlan-gpe/vxlan_gpe.api.h		\
	ioam/lib-vxlan-gpe/vxlan_gpe.api.json		\
	ioam/export-vxlan-gpe/vxlan_gpe_ioam_export.api.h		\
	ioam/export-vxlan-gpe/vxlan_gpe_ioam_export.api.json

noinst_HEADERS +=                       \
  ioam/export/ioam_export_all_api_h.h   \
  ioam/lib-vxlan-gpe/vxlan_gpe_all_api_h.h			\
  ioam/lib-vxlan-gpe/vxlan_gpe_msg_enum.h			\
  ioam/lib-vxlan-gpe/vxlan_gpe.api.h			\
  ioam/lib-vxlan-gpe/vxlan_gpe_ioam_util.h			\
  ioam/lib-vxlan-gpe/vxlan_gpe_ioam_packet.h                    \
  ioam/lib-vxlan-gpe/vxlan_gpe_ioam.h		\
  ioam/export-vxlan-gpe/vxlan_gpe_ioam_export_all_api_h.h       \
  ioam/export-vxlan-gpe/vxlan_gpe_ioam_export_msg_enum.h        \
  ioam/export-vxlan-gpe/vxlan_gpe_ioam_export.api.h

ioam_vxlan_gpe_test_plugin_la_SOURCES =		\
	ioam/lib-vxlan-gpe/vxlan_gpe_test.c			\
	ioam/lib-vxlan-gpe/vxlan_gpe_plugin.api.h

libioam_vxlan_gpe_plugin_la_LIBADD = libioam_trace_plugin.la

vppapitestplugins_LTLIBRARIES += ioam_vxlan_gpe_test_plugin.la
vppplugins_LTLIBRARIES += libioam_vxlan_gpe_plugin.la

vxlan_gpe_ioam_export_test_plugin_la_SOURCES =          \
  ioam/export-vxlan-gpe/vxlan_gpe_ioam_export_test.c      \
  ioam/export-vxlan-gpe/vxlan_gpe_ioam_export_plugin.api.h

vppapitestplugins_LTLIBRARIES += vxlan_gpe_ioam_export_test_plugin.la

########################################
# iOAM E2E plugin
########################################

ioam_e2e_plugin_la_SOURCES =                \
	ioam/encap/ip6_ioam_e2e.c               \
	ioam/encap/ip6_ioam_seqno.c             \
	ioam/encap/ip6_ioam_seqno_analyse.c

noinst_HEADERS +=                    \
	ioam/encap/ip6_ioam_e2e.h        \
	ioam/encap/ip6_ioam_seqno.h

vppplugins_LTLIBRARIES += ioam_e2e_plugin.la

# Remove *.la files
install-data-hook:
	@(cd $(vpppluginsdir) && $(RM) $(vppplugins_LTLIBRARIES))
	@(cd $(vppapitestpluginsdir) && $(RM) $(vppapitestplugins_LTLIBRARIES))


#
# Java code generation
#
jvpp_registry_root = ../../vpp-api/java
jvpp_registry_version = 17.01
jioam_trace_jarfile = jvpp-ioam-trace-$(PACKAGE_VERSION).jar
jvpp_trace_package_dir = io/fd/vpp/jvpp/ioamtrace
jvpp_root = ioam/jvpp
jvpp_target_dir = target
jvpp_target = $(jvpp_root)/$(jvpp_target_dir)
trace_api_file=$(srcdir)/ioam/lib-trace/trace.api


lib_LTLIBRARIES = libjvpp_ioamtrace.la
libjvpp_ioamtrace_la_SOURCES = ioam/lib-trace/trace.api.h ioam/lib-trace/jvpp_ioam_trace.c ioam/jvpp/io_fd_vpp_jvpp_ioam_trace_JVppIoamTraceImpl.h
libjvpp_ioamtrace_la_LIBADD = -lvlibmemoryclient -lvlibapi -lvppinfra \
	              -lpthread -lm -lrt -L$(jvpp_registry_root)/.libs -ljvpp_common
libjvpp_ioamtrace_la_LDFLAGS = -module
libjvpp_ioamtrace_la_CPPFLAGS = -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux -I../ -I$(srcdir)/../

BUILT_SOURCES += $(jvpp_root)/io_fd_vpp_jvpp_ioamtrace_JVppIoamtraceImpl.h

$(jvpp_root)/io_fd_vpp_jvpp_ioamtrace_JVppIoamtraceImpl.h: ioam_trace.api.json
	dir=`pwd`;						\
	mkdir -p $(jvpp_target); \
	mkdir -p $(jvpp_root)/$(jvpp_trace_package_dir); 		\
	cd $(jvpp_root)/$(jvpp_trace_package_dir);			\
	mkdir -p dto future callfacade callback notification test; 	\
	@srcdir@/$(jvpp_registry_root)/jvpp/gen/jvpp_gen.py -i $${dir}/ioam_trace.api.json --plugin_name ioamtrace;		\
	cd -;							\
	mv -f $(jvpp_root)/$(jvpp_trace_package_dir)/jvpp_ioamtrace_gen.h $(jvpp_root)/jvpp_ioam_trace_gen.h;							\
	cp $(srcdir)/$(jvpp_root)/$(jvpp_trace_package_dir)/test/*.java $(jvpp_root)/$(jvpp_trace_package_dir)/test/;				\
	cd $(jvpp_root);				\
	$(JAVAC) -classpath .:$(jvpp_target_dir):../../$(jvpp_registry_root)/jvpp-registry-$(jvpp_registry_version).jar -d $(jvpp_target_dir) $(jvpp_trace_package_dir)/*.java \
		$(jvpp_trace_package_dir)/dto/*.java \
		$(jvpp_trace_package_dir)/callback/*.java \
		$(jvpp_trace_package_dir)/notification/*.java \
		$(jvpp_trace_package_dir)/future/*.java 	\
		$(jvpp_trace_package_dir)/callfacade/*.java 	\
		$(jvpp_trace_package_dir)/test/*.java \
		|| (echo "ioam trace jvpp compilation failed: $$?"; exit 1);	\
	$(JAVAH) -classpath .:$(jvpp_target_dir):../../$(jvpp_registry_root)/jvpp-registry-$(jvpp_registry_version).jar -d . io.fd.vpp.jvpp.ioamtrace.JVppIoamtraceImpl ;

$(jioam_trace_jarfile): libjvpp_ioamtrace.la
	cp .libs/libjvpp_ioamtrace.so.0.0.0 $(jvpp_target);				\
	cd $(jvpp_target);				\
	$(JAR) cfv $(JARFLAGS) ../../../$@ libjvpp_ioamtrace.so.0.0.0 $(jvpp_trace_package_dir)/* ; cd ..;

ioam_trace.api.json:
	@echo "  jIoam_trace API"; \
        vppapigen --input $(trace_api_file) --json ioam_trace.api.json;

all-local: $(jioam_trace_jarfile)


jioam_pot_jarfile = jvpp-ioam-pot-$(PACKAGE_VERSION).jar
jvpp_pot_package_dir = io/fd/vpp/jvpp/ioampot
pot_api_file=$(srcdir)/ioam/lib-pot/pot.api


lib_LTLIBRARIES += libjvpp_ioampot.la
libjvpp_ioampot_la_SOURCES = ioam/lib-pot/pot.api.h ioam/lib-pot/jvpp_ioam_pot.c ioam/jvpp/io_fd_vpp_jvpp_ioam_pot_JVppIoamPotImpl.h
libjvpp_ioampot_la_LIBADD = -lvlibmemoryclient -lvlibapi -lvppinfra \
	              -lpthread -lm -lrt -L$(jvpp_registry_root)/.libs -ljvpp_common
libjvpp_ioampot_la_LDFLAGS = -module
libjvpp_ioampot_la_CPPFLAGS = -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux -I../ -I$(srcdir)/../

BUILT_SOURCES += $(jvpp_root)/io_fd_vpp_jvpp_ioampot_JVppIoampotImpl.h

$(jvpp_root)/io_fd_vpp_jvpp_ioampot_JVppIoampotImpl.h: ioam_pot.api.json
	dir=`pwd`;						\
	mkdir -p $(jvpp_target); \
	mkdir -p $(jvpp_root)/$(jvpp_pot_package_dir); 		\
	cd $(jvpp_root)/$(jvpp_pot_package_dir);			\
	mkdir -p dto future callfacade callback notification test; 	\
	@srcdir@/$(jvpp_registry_root)/jvpp/gen/jvpp_gen.py -i $${dir}/ioam_pot.api.json --plugin_name ioampot;		\
	cd -;							\
	mv -f $(jvpp_root)/$(jvpp_pot_package_dir)/jvpp_ioampot_gen.h $(jvpp_root)/jvpp_ioam_pot_gen.h;							\
	cp $(srcdir)/$(jvpp_root)/$(jvpp_pot_package_dir)/test/*.java $(jvpp_root)/$(jvpp_pot_package_dir)/test/;				\
	cd $(jvpp_root);				\
	$(JAVAC) -classpath .:$(jvpp_target_dir):../../$(jvpp_registry_root)/jvpp-registry-$(jvpp_registry_version).jar -d $(jvpp_target_dir) $(jvpp_pot_package_dir)/*.java \
		$(jvpp_pot_package_dir)/dto/*.java \
		$(jvpp_pot_package_dir)/callback/*.java \
		$(jvpp_pot_package_dir)/notification/*.java \
		$(jvpp_pot_package_dir)/future/*.java 	\
		$(jvpp_pot_package_dir)/callfacade/*.java 	\
		$(jvpp_pot_package_dir)/test/*.java \
		|| (echo "ioam pot jvpp compilation failed: $$?"; exit 1);	\
	$(JAVAH) -classpath .:$(jvpp_target_dir):../../$(jvpp_registry_root)/jvpp-registry-$(jvpp_registry_version).jar -d . io.fd.vpp.jvpp.ioampot.JVppIoampotImpl ;

$(jioam_pot_jarfile): libjvpp_ioampot.la
	cp .libs/libjvpp_ioampot.so.0.0.0 $(jvpp_target);				\
	cd $(jvpp_target);				\
	$(JAR) cfv $(JARFLAGS) ../../../$@ libjvpp_ioampot.so.0.0.0 $(jvpp_pot_package_dir)/* ; cd ..;

ioam_pot.api.json:
	@echo "  jIoam_pot API"; \
        vppapigen --input $(pot_api_file) --json ioam_pot.api.json;

all-local: $(jioam_pot_jarfile)

jioam_export_jarfile = jvpp-ioam-export-$(PACKAGE_VERSION).jar
jvpp_export_package_dir = io/fd/vpp/jvpp/ioamexport
export_api_file=$(srcdir)/ioam/export/ioam_export.api


lib_LTLIBRARIES += libjvpp_ioamexport.la
libjvpp_ioamexport_la_SOURCES = ioam/export/export.api.h ioam/export/jvpp_ioam_export.c ioam/jvpp/io_fd_vpp_jvpp_ioam_export_JVppIoamexportImpl.h
libjvpp_ioamexport_la_LIBADD = -lvlibmemoryclient -lvlibapi -lvppinfra \
	              -lpthread -lm -lrt -L$(jvpp_registry_root)/.libs -ljvpp_common
libjvpp_ioamexport_la_LDFLAGS = -module
libjvpp_ioamexport_la_CPPFLAGS = -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux -I../ -I$(srcdir)/../

BUILT_SOURCES += $(jvpp_root)/io_fd_vpp_jvpp_ioamexport_JVppIoamexportImpl.h

$(jvpp_root)/io_fd_vpp_jvpp_ioamexport_JVppIoamexportImpl.h: ioam_export.api.json
	dir=`pwd`;						\
	mkdir -p $(jvpp_target); \
	mkdir -p $(jvpp_root)/$(jvpp_export_package_dir); 		\
	cd $(jvpp_root)/$(jvpp_export_package_dir);			\
	mkdir -p dto future callfacade callback notification test; 	\
	@srcdir@/$(jvpp_registry_root)/jvpp/gen/jvpp_gen.py -i $${dir}/ioam_export.api.json --plugin_name ioamexport;		\
	cd -;							\
	mv -f $(jvpp_root)/$(jvpp_export_package_dir)/jvpp_ioamexport_gen.h $(jvpp_root)/jvpp_ioam_export_gen.h;							\
	cp $(srcdir)/$(jvpp_root)/$(jvpp_export_package_dir)/test/*.java $(jvpp_root)/$(jvpp_export_package_dir)/test/;				\
	cd $(jvpp_root);				\
	$(JAVAC) -classpath .:$(jvpp_target_dir):../../$(jvpp_registry_root)/jvpp-registry-$(jvpp_registry_version).jar -d $(jvpp_target_dir) $(jvpp_export_package_dir)/*.java \
		$(jvpp_export_package_dir)/dto/*.java \
		$(jvpp_export_package_dir)/callback/*.java \
		$(jvpp_export_package_dir)/notification/*.java \
		$(jvpp_export_package_dir)/future/*.java 	\
		$(jvpp_export_package_dir)/callfacade/*.java 	\
		$(jvpp_export_package_dir)/test/*.java \
		|| (echo "ioam export jvpp compilation failed: $$?"; exit 1);	\
	$(JAVAH) -classpath .:$(jvpp_target_dir):../../$(jvpp_registry_root)/jvpp-registry-$(jvpp_registry_version).jar -d . io.fd.vpp.jvpp.ioamexport.JVppIoamexportImpl ;

$(jioam_export_jarfile): libjvpp_ioamexport.la
	cp .libs/libjvpp_ioamexport.so.0.0.0 $(jvpp_target);				\
	cd $(jvpp_target);				\
	$(JAR) cfv $(JARFLAGS) ../../../$@ libjvpp_ioamexport.so.0.0.0 $(jvpp_export_package_dir)/* ; cd ..;

ioam_export.api.json:
	@echo "  jIoam_export API"; \
        vppapigen --input $(export_api_file) --json ioam_export.api.json;

all-local: $(jioam_export_jarfile)
