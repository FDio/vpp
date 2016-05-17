
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

# netcp_test_plugin.la
# netcp/netcp_plugin.api.h 

vppapitestpluginsdir = ${libdir}/vpp_api_test_plugins
vpppluginsdir = ${libdir}/vpp_plugins

vppapitestplugins_LTLIBRARIES = # netcp_test_plugin.la
vppplugins_LTLIBRARIES = netcp_plugin.la

netcp_plugin_la_SOURCES = netcp/netcp.c  \
        netcp/node.c netcp/util.c

# BUILT_SOURCES = netcp/netcp.api.h

# SUFFIXES = .api.h .api

# %.api.h: %.api
#	mkdir -p `dirname $@` ; \
#	$(CC) $(CPPFLAGS) -E -P -C -x c $^ \
#	| vppapigen --input - --output $@ --show-name $@

# noinst_HEADERS =			\
#  netcp/netcp_all_api_h.h			\
#  netcp/netcp_msg_enum.h			\
#  netcp/netcp.api.h

# netcp_test_plugin_la_SOURCES = \
#  netcp/netcp_test.c netcp/netcp_plugin.api.h
# netcp_test_plugin_la_LDFLAGS = -module


#	@(cd $(vppapitestpluginsdir) && $(RM) $(vppapitestplugins_LTLIBRARIES))

install-data-hook:
	@(cd $(vpppluginsdir) && $(RM) $(vppplugins_LTLIBRARIES))
