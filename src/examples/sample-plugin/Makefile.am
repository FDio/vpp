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

AM_CFLAGS = -Wall -I${top_srcdir} -I${top_builddir}
AM_LDFLAGS = -module -shared -avoid-version
AM_LIBTOOLFLAGS = --quiet
SUFFIXES = .api.h .api .api.json
API_FILES =
BUILT_SOURCES =
vppplugins_LTLIBRARIES =
vppapitestplugins_LTLIBRARIES =
noinst_HEADERS =
nobase_apiinclude_HEADERS =
ACLOCAL_AMFLAGS = -I m4

vppapitestpluginsdir = ${libdir}/vpp_api_test_plugins
vpppluginsdir = ${libdir}/vpp_plugins

include sample.am

%.api.h: %.api
	mkdir -p `dirname $@` ; \
	$(CC) $(CPPFLAGS) -E -P -C -x c $^ \
	| vppapigen --input - --output $@ --show-name $@

%.api.json: %.api
	@echo "  JSON APIGEN  " $@ ;				\
	mkdir -p `dirname $@` ;					\
	$(CC) $(CPPFLAGS) -E -P -C -x c $^			\
	| vppapigen --input - --json $@

apidir = $(prefix)/api/plugins
apiincludedir = ${includedir}/vpp_plugins

api_DATA = \
	$(patsubst %.api,%.api.json,$(API_FILES))

BUILT_SOURCES += \
	$(patsubst %.api,%.api.h,$(API_FILES))


# Remove *.la files
install-data-hook:
	@(cd $(vpppluginsdir) && $(RM) $(vppplugins_LTLIBRARIES))
	@(cd $(vppapitestpluginsdir) && $(RM) $(vppapitestplugins_LTLIBRARIES))

CLEANFILES = $(BUILT_SOURCES)
