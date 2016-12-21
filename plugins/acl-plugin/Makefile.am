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

AUTOMAKE_OPTIONS = foreign subdir-objects

AM_CFLAGS = -Wall
AM_LDFLAGS = -module -shared -avoid-version

vppapitestpluginsdir = ${libdir}/vpp_api_test_plugins
vpppluginsdir = ${libdir}/vpp_plugins

vppapitestplugins_LTLIBRARIES = acl_test_plugin.la
vppplugins_LTLIBRARIES = acl_plugin.la

acl_plugin_la_SOURCES =				\
	acl/acl.c				\
	acl/node_in.c				\
	acl/node_out.c				\
	acl/l2sess.c				\
	acl/l2sess_node.c			\
	acl/l2sess.h				\
	acl/acl_plugin.api.h

BUILT_SOURCES = acl/acl.api.h acl/acl.api.json

SUFFIXES = .api.h .api .api.json

#
# ACL API
#
%.api.h: %.api
	mkdir -p `dirname $@` ; \
	$(CC) $(CPPFLAGS) -E -P -C -x c $^ \
	| vppapigen --input - --output $@ --show-name $@

%.api.json: %.api
	@echo "  JSON APIGEN  " $@ ;                            \
	mkdir -p `dirname $@` ;                                 \
	$(CC) $(CPPFLAGS) -E -P -C -x c $^                      \
	| vppapigen --input - --json $@

apidir = $(prefix)/acl
api_DATA = acl/acl.api.json

noinst_HEADERS =				\
  acl/acl_all_api_h.h				\
  acl/acl_msg_enum.h				\
  acl/acl.api.h

acl_test_plugin_la_SOURCES = acl/acl_test.c acl/acl_plugin.api.h

# Remove *.la files
install-data-hook:
	@(cd $(vpppluginsdir) && $(RM) $(vppplugins_LTLIBRARIES))
	@(cd $(vppapitestpluginsdir) && $(RM) $(vppapitestplugins_LTLIBRARIES))

#
# Java code generation
#
jvpp_registry_root = ../../vpp-api/java
jvpp_registry_version = 17.04
jacl_jarfile = jvpp-acl-$(PACKAGE_VERSION).jar
jvpp_package_dir = io/fd/vpp/jvpp/acl
jvpp_root = acl/jvpp
jvpp_target_dir = target
jvpp_target = $(jvpp_root)/$(jvpp_target_dir)

lib_LTLIBRARIES = libjvpp_acl.la
libjvpp_acl_la_SOURCES = acl/acl.api.h acl/jvpp_acl.c acl/jvpp/io_fd_vpp_jvpp_acl_JVppAclImpl.h
libjvpp_acl_la_LIBADD = -lvlibmemoryclient -lvlibapi -lvppinfra \
	              -lpthread -lm -lrt -L$(jvpp_registry_root)/.libs -ljvpp_common
libjvpp_acl_la_LDFLAGS = -module
libjvpp_acl_la_CPPFLAGS = -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux -I../ -I$(srcdir)/../

BUILT_SOURCES += $(jvpp_root)/io_fd_vpp_jvpp_acl_JVppAclImpl.h

$(jvpp_root)/io_fd_vpp_jvpp_acl_JVppAclImpl.h: acl/acl.api.json
	dir=`pwd`;						\
	mkdir -p $(jvpp_target); \
	mkdir -p $(jvpp_root)/$(jvpp_package_dir); 		\
	cd $(jvpp_root)/$(jvpp_package_dir);			\
	mkdir -p types dto future callfacade callback notification test; 	\
	@srcdir@/$(jvpp_registry_root)/jvpp/gen/jvpp_gen.py -i $${dir}/acl/acl.api.json --plugin_name acl;		\
	cd -;							\
	mv -f $(jvpp_root)/$(jvpp_package_dir)/jvpp_acl_gen.h $(jvpp_root)/jvpp_acl_gen.h;							\
	cp $(srcdir)/$(jvpp_root)/$(jvpp_package_dir)/test/*.java $(jvpp_root)/$(jvpp_package_dir)/test/;				\
	cd $(jvpp_root);				\
	$(JAVAC) -classpath .:$(jvpp_target_dir):../../$(jvpp_registry_root)/jvpp-registry-$(jvpp_registry_version).jar -d $(jvpp_target_dir) $(jvpp_package_dir)/*.java \
		$(jvpp_package_dir)/types/*.java \
		$(jvpp_package_dir)/dto/*.java \
		$(jvpp_package_dir)/callback/*.java \
		$(jvpp_package_dir)/notification/*.java \
		$(jvpp_package_dir)/future/*.java 	\
		$(jvpp_package_dir)/callfacade/*.java 	\
		$(jvpp_package_dir)/test/*.java \
		|| (echo "acl jvpp compilation failed: $$?"; exit 1);	\
	$(JAVAH) -classpath .:$(jvpp_target_dir):../../$(jvpp_registry_root)/jvpp-registry-$(jvpp_registry_version).jar -d . io.fd.vpp.jvpp.acl.JVppAclImpl ;

$(jacl_jarfile): libjvpp_acl.la
	cp .libs/libjvpp_acl.so.0.0.0 $(jvpp_target);				\
	cd $(jvpp_target);				\
	$(JAR) cfv $(JARFLAGS) ../../../$@ libjvpp_acl.so.0.0.0 $(jvpp_package_dir)/* ; cd ..;

all-local: $(jacl_jarfile)
