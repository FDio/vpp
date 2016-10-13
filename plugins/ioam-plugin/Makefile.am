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
	ioam/lib-pot/pot.api.h ioam/lib-pot/pot.py

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
pyapi_DATA = ioam/lib-pot/pot.py

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
# iOAM trace export
########################################

ioam_export_plugin_la_SOURCES =   \
ioam/export/ioam_export.c         \
ioam/export/node.c                \
ioam/export/ioam_export.api.h     \
ioam/export/ioam_export_thread.c

BUILT_SOURCES += ioam/export/ioam_export.api.h

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
ioam_trace_plugin_la_SOURCES =			\
	ioam/lib-trace/trace_util.c			\
	ioam/encap/ip6_ioam_trace.c		\
	ioam/lib-trace/trace_util.h			\
	ioam/lib-trace/trace_api.c

BUILT_SOURCES +=					\
	ioam/lib-trace/trace.api.h ioam/lib-trace/trace.py

pyapi_DATA += ioam/lib-trace/trace.py

noinst_HEADERS +=                       \
  ioam/export/ioam_export_all_api_h.h   \
  ioam/lib-trace/trace_all_api_h.h			\
  ioam/lib-trace/trace_msg_enum.h			\
  ioam/lib-trace/trace.api.h			\
  ioam/lib-trace/trace_util.h

ioam_trace_test_plugin_la_SOURCES =		\
	ioam/lib-trace/trace_test.c			\
	ioam/lib-trace/trace_plugin.api.h

vppapitestplugins_LTLIBRARIES += ioam_trace_test_plugin.la
vppplugins_LTLIBRARIES += ioam_trace_plugin.la



# Remove *.la files
install-data-hook:
	@(cd $(vpppluginsdir) && $(RM) $(vppplugins_LTLIBRARIES))
	@(cd $(vppapitestpluginsdir) && $(RM) $(vppapitestplugins_LTLIBRARIES))


#
# Java code generation
#
jvpp_registry_root = ../../vpp-api/java
jvpp_registry_version = 16.12
jioam_trace_jarfile = jvpp-ioam-trace-$(PACKAGE_VERSION).jar
jvpp_package_dir = io/fd/vpp/jvpp/ioamtrace
jvpp_root = ioam/jvpp
jvpp_target_dir = target
jvpp_target = $(jvpp_root)/$(jvpp_target_dir)
api_file=$(srcdir)/ioam/lib-trace/trace.api


lib_LTLIBRARIES = libjvpp_ioamtrace.la
libjvpp_ioamtrace_la_SOURCES = ioam/lib-trace/trace.api.h ioam/lib-trace/jvpp_ioam_trace.c ioam/jvpp/io_fd_vpp_jvpp_ioam_trace_JVppIoamTraceImpl.h
libjvpp_ioamtrace_la_LIBADD = -lvlibmemoryclient -lvlibapi -lvppinfra \
	              -lpthread -lm -lrt -L$(jvpp_registry_root)/.libs -ljvpp_common
libjvpp_ioamtrace_la_LDFLAGS = -module
libjvpp_ioamtrace_la_CPPFLAGS = -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux -I../ -I$(srcdir)/../

BUILT_SOURCES += $(jvpp_root)/io_fd_vpp_jvpp_ioamtrace_JVppIoamtraceImpl.h

$(jvpp_root)/io_fd_vpp_jvpp_ioamtrace_JVppIoamtraceImpl.h: defs_ioam_trace_papi.py
	dir=`pwd`;						\
	mkdir -p $(jvpp_target); \
	mkdir -p $(jvpp_root)/$(jvpp_package_dir); 		\
	cd $(jvpp_root)/$(jvpp_package_dir);			\
	mkdir -p dto future callfacade callback notification test; 	\
	@srcdir@/$(jvpp_registry_root)/jvpp/gen/jvpp_gen.py -i $${dir}/defs_ioam_trace_papi.py --plugin_name ioamtrace --control_ping_class IoamTraceControlPing;		\
	cd -;							\
	mv -f $(jvpp_root)/$(jvpp_package_dir)/jvpp_ioamtrace_gen.h $(jvpp_root)/jvpp_ioam_trace_gen.h;							\
	cp $(srcdir)/$(jvpp_root)/$(jvpp_package_dir)/test/*.java $(jvpp_root)/$(jvpp_package_dir)/test/;				\
	cd $(jvpp_root);				\
	$(JAVAC) -classpath .:$(jvpp_target_dir):../../$(jvpp_registry_root)/jvpp-registry-$(jvpp_registry_version).jar -d $(jvpp_target_dir) $(jvpp_package_dir)/*.java \
		$(jvpp_package_dir)/dto/*.java \
		$(jvpp_package_dir)/callback/*.java \
		$(jvpp_package_dir)/notification/*.java \
		$(jvpp_package_dir)/future/*.java 	\
		$(jvpp_package_dir)/callfacade/*.java 	\
		$(jvpp_package_dir)/test/*.java \
		|| (echo "ioam trace jvpp compilation failed: $$?"; exit 1);	\
	$(JAVAH) -classpath .:$(jvpp_target_dir):../../$(jvpp_registry_root)/jvpp-registry-$(jvpp_registry_version).jar -d . io.fd.vpp.jvpp.ioamtrace.JVppIoamtraceImpl ;

$(jioam_trace_jarfile): libjvpp_ioamtrace.la
	cp .libs/libjvpp_ioamtrace.so.0.0.0 $(jvpp_target);				\
	cd $(jvpp_target);				\
	$(JAR) cfv $(JARFLAGS) ../../../$@ libjvpp_ioamtrace.so.0.0.0 $(jvpp_package_dir)/* ; cd ..;

defs_ioam_trace_papi.py:
	@echo "  jIoam_trace API"; \
        vppapigen --input $(api_file) --python defs_ioam_trace_papi.py;

all-local: $(jioam_trace_jarfile)
