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

BUILT_SOURCES = acl/acl.api.h

SUFFIXES = .api.h .api

#
# ACL API
#
%.api.h: %.api
	mkdir -p $(dir $@) ; \
	$(CC) $(CPPFLAGS) -E -P -C -x c $^ \
	| vppapigen --input - --output $@ --show-name $@

apidir = $(prefix)/acl
api_DATA = acl/acl.api

noinst_HEADERS =				\
  acl/acl_all_api_h.h				\
  acl/acl_msg_enum.h				\
  acl/acl.api.h

acl_test_plugin_la_SOURCES = acl/acl_test.c acl/acl_plugin.api.h

# Remove *.la files
install-data-hook:
	@(cd $(vpppluginsdir) && $(RM) $(vppplugins_LTLIBRARIES))
	@(cd $(vppapitestpluginsdir) && $(RM) $(vppapitestplugins_LTLIBRARIES))
