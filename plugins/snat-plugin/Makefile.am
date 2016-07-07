
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

BUILT_SOURCES = snat/snat.api.h

SUFFIXES = .api.h .api

%.api.h: %.api
	mkdir -p `dirname $@` ; \
	$(CC) $(CPPFLAGS) -E -P -C -x c $^ \
	| vppapigen --input - --output $@ --show-name $@

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
