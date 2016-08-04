# Copyright (c) 2016 Cisco Systems, Inc.
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

vppapitestplugins_LTLIBRARIES = lb_test_plugin.la
vppplugins_LTLIBRARIES = lb_plugin.la

lb_plugin_la_SOURCES = lb/lb.c lb/node.c lb/cli.c lb/util.c lb/refcount.c lb/api.c

SUFFIXES = .api.h .api

%.api.h: %.api
	mkdir -p `dirname $@` ; \
	$(CC) $(CPPFLAGS) -E -P -C -x c $^ \
	| vppapigen --input - --output $@ --show-name $@

noinst_HEADERS = lb/lb.h lb/util.h lb/refcount.h  lb/lbhash.h lb/lb.api.h

lb_test_plugin_la_SOURCES = \
  lb/lb_test.c lb/lb_plugin.api.h

# Remove *.la files
install-data-hook:
	@(cd $(vpppluginsdir) && $(RM) $(vppplugins_LTLIBRARIES))
	@(cd $(vppapitestpluginsdir) && $(RM) $(vppapitestplugins_LTLIBRARIES))
