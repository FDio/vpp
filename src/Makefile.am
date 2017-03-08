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

###############################################################################
# Global Defines
###############################################################################

AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
AM_LIBTOOLFLAGS = --quiet

AM_CFLAGS = -Wall

SUBDIRS = .
SUFFIXES = .api.h .api .api.json
API_FILES =
noinst_HEADERS =
dist_bin_SCRIPTS =
lib_LTLIBRARIES =
BUILT_SOURCES =
CLEANFILES =
install-data-local:
	@echo "Building vppctl command list..."
	@DIR_SEARCH="$(srcdir)" ; \
	DIR_EXCLUDE="examples" ; \
	GREP_TIME=`time (grep -wIr "\.path = " $$DIR_SEARCH --exclude-dir=$$DIR_EXCLUDE \
	| cut -d '"' -f2 | sort -u > $(srcdir)/scripts/vppctl-cmd-list) 2>&1` ; \
	GREP_TIME=`echo $$GREP_TIME | awk '{print $$2}'` ; \
	echo "Command list built, Time taken: $$GREP_TIME"

###############################################################################
# Components
###############################################################################

include vppinfra.am
include vppapigen.am

if ENABLE_PERFTOOL
include perftool.am
endif

if ENABLE_G2
include g2.am
endif

if ENABLE_SVM
include svm.am
endif

if ENABLE_VLIB
include vlib.am
endif

if ENABLE_SVM
if ENABLE_VLIB
include vlib-api.am
include vnet.am
include vpp.am
include vpp-api-test.am
include uri.am

SUBDIRS += plugins

if ENABLE_PAPI
include vpp-api.am
SUBDIRS += vpp-api/python
endif

if ENABLE_JAPI
SUBDIRS += vpp-api/java
endif

###############################################################################
# API
###############################################################################

include suffix-rules.mk

# Set the suffix list
apidir = $(prefix)/share/vpp/api/core

api_DATA = \
	$(patsubst %.api,%.api.json,$(API_FILES))

BUILT_SOURCES += \
	$(patsubst %.api,%.api.h,$(API_FILES))

endif # if ENABLE_VLIB
endif # if ENABLE_SVM

CLEANFILES += $(BUILT_SOURCES) $(api_DATA)
