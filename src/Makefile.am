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

PRE_DATA_SIZE = @PRE_DATA_SIZE@
SUBDIRS =

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
include vat.am

# To add a new plugin subdirectory:
#
# add a stanza here:
# if ENABLE_new_PLUGIN
# SUBDIRS += new-plugin
# endif
#
# Also: add PLUGIN(new) to configure.ac

vpppluginsdir = ${libdir}/vpp_plugins
#vppapitestpluginsdir = ${libdir}/vpp_api_test_plugins
#vppapitestplugins_LTLIBRARIES =
vppplugins_LTLIBRARIES =
noinst_HEADERS =

# if ENABLE_sample_PLUGIN
# SUBDIRS += plugins/sample-plugin
# endif

if ENABLE_sixrd_PLUGIN
include plugins/sixrd-plugin/sixrd.am
endif

# if ENABLE_ioam_PLUGIN
# SUBDIRS += plugins/ioam-plugin
# endif

# if ENABLE_vcgn_PLUGIN
# SUBDIRS += plugins/vcgn-plugin
# endif

#if ENABLE_snat_PLUGIN
#include plugins/snat-plugin/snat.am
#endif

#if ENABLE_ila_PLUGIN
#SUBDIRS += plugins/ila-plugin
#endif

# if ENABLE_lb_PLUGIN
# SUBDIRS += plugins/lb-plugin
# endif

# if ENABLE_flowperpkt_PLUGIN
# SUBDIRS += plugins/flowperpkt-plugin
# endif

# if ENABLE_acl_PLUGIN
# SUBDIRS += plugins/acl-plugin
# endif

include $(top_srcdir)/suffix-rules.mk

# Remove *.la files
install-data-hook:
	@(cd $(vpppluginsdir) && $(RM) $(vppplugins_LTLIBRARIES))
	@(cd $(vppapitestpluginsdir) && $(RM) $(vppapitestplugins_LTLIBRARIES))

endif # if !WITH_TOOLS_ONLY
