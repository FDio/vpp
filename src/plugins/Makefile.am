
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
nobase_include_HEADERS =

vppapitestpluginsdir = ${libdir}/vpp_api_test_plugins
vpppluginsdir = ${libdir}/vpp_plugins

if ENABLE_ACL_PLUGIN
include acl.am
endif

if ENABLE_DPDK_PLUGIN
include dpdk.am
endif

if ENABLE_FLOWPROBE_PLUGIN
include flowprobe.am
endif


if ENABLE_GTPU_PLUGIN
include gtpu.am
endif

if ENABLE_ILA_PLUGIN
include ila.am
endif

if ENABLE_IOAM_PLUGIN
include ioam.am
endif

if ENABLE_IXGE_PLUGIN
include ixge.am
endif

if ENABLE_LB_PLUGIN
include lb.am
endif

if ENABLE_MEMIF_PLUGIN
include memif.am
endif

if ENABLE_PPPOE_PLUGIN
include pppoe.am
endif

if ENABLE_SIXRD_PLUGIN
include sixrd.am
endif

if ENABLE_NAT_PLUGIN
include nat.am
endif

include ../suffix-rules.mk

# Remove *.la files
install-data-hook:
	@-(cd $(vpppluginsdir) && $(RM) $(vppplugins_LTLIBRARIES))
	@-(cd $(vppapitestpluginsdir) && $(RM) $(vppapitestplugins_LTLIBRARIES))

###############################################################################
# API
###############################################################################

apidir = $(prefix)/share/vpp/api/plugins
apiincludedir = ${includedir}/vpp_plugins

api_DATA = \
	$(patsubst %.api,%.api.json,$(API_FILES))

BUILT_SOURCES += \
	$(patsubst %.api,%.api.h,$(API_FILES))

CLEANFILES = $(BUILT_SOURCES) $(api_DATA)
