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
ACLOCAL_AMFLAGS = -I m4

PRE_DATA_SIZE = @PRE_DATA_SIZE@
SUBDIRS =
SUFFIXES = .api.h .api .api.json
API_FILES =
BUILT_SOURCES =

AM_CFLAGS = -Wall @DPDK@ @DPDK_CRYPTO@ @IPSEC@ @IPV6SR@
dist_bin_SCRIPTS =

include vppinfra.am
include vppapigen.am

if !WITH_TOOLS_ONLY
include vlib.am
include svm.am
include vlib-api.am
include vnet.am
include vpp.am
include vpp-api-python.am
include vat.am

vpppluginsdir = ${libdir}/vpp_plugins
vppapitestpluginsdir = ${libdir}/vpp_api_test_plugins
vppplugins_LTLIBRARIES =
vppapitestplugins_LTLIBRARIES =
noinst_HEADERS =

if ENABLE_sixrd_PLUGIN
include plugins/sixrd-plugin/sixrd.am
endif

if ENABLE_ila_PLUGIN
include plugins/ila-plugin/ila.am
endif

if ENABLE_flowperpkt_PLUGIN
include plugins/flowperpkt-plugin/flowperpkt.am
endif

include $(top_srcdir)/suffix-rules.mk

# Set the suffix list
apidir = $(prefix)/share/vpp/api

api_DATA = \
	$(patsubst %.api,%.api.json,$(API_FILES))

BUILT_SOURCES += \
	$(patsubst %.api,%.api.json,$(API_FILES)) \
	$(patsubst %.api,%.api.h,$(API_FILES))

# Remove *.la files
install-data-hook:
	@(cd $(vpppluginsdir) && $(RM) $(vppplugins_LTLIBRARIES))
	@(cd $(vppapitestpluginsdir) && $(RM) $(vppapitestplugins_LTLIBRARIES))

endif # if !WITH_TOOLS_ONLY
