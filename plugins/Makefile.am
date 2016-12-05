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

# To add a new plugin subdirectory:
#
# add a stanza here:
# if ENABLE_new_PLUGIN
# SUBDIRS += new-plugin
# endif
#
# Also: add PLUGIN(new) to configure.ac

SUBDIRS =

if ENABLE_sample_PLUGIN
SUBDIRS += sample-plugin
endif

if ENABLE_sixrd_PLUGIN
SUBDIRS += sixrd-plugin
endif

if ENABLE_ioam_PLUGIN
SUBDIRS += ioam-plugin
endif

if ENABLE_vcgn_PLUGIN
SUBDIRS += vcgn-plugin
endif

if ENABLE_snat_PLUGIN
SUBDIRS += snat-plugin
endif

if ENABLE_ila_PLUGIN
SUBDIRS += ila-plugin
endif

if ENABLE_lb_PLUGIN
SUBDIRS += lb-plugin
endif

if ENABLE_flowperpkt_PLUGIN
SUBDIRS += flowperpkt-plugin
endif

if ENABLE_acl_PLUGIN
SUBDIRS += acl-plugin
endif
