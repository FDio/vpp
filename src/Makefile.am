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

AM_CFLAGS = -Wall

SUBDIRS = .
SUFFIXES = .api.h .api .api.json
API_FILES =
noinst_HEADERS =
dist_bin_SCRIPTS =
lib_LTLIBRARIES =
BUILT_SOURCES =

###############################################################################
# DPDK
###############################################################################

if WITH_DPDK
if ENABLE_DPDK_SHARED
DPDK_LD_FLAGS = -Wl,--whole-archive,-ldpdk,--no-whole-archive
else
DPDK_LD_FLAGS = -Wl,--whole-archive,-l:libdpdk.a,--no-whole-archive
endif
if WITH_DPDK_CRYPTO
DPDK_LD_ADD = -L$(AESNI_MULTI_BUFFER_LIB_PATH) -lIPSec_MB
endif
if WITH_DPDK_MLX5_PMD
DPDK_LD_FLAGS += -libverbs -lmlx5 -lnuma
endif
else
DPDK_LD_FLAGS =
DPDK_LD_ADD =
endif

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

SUBDIRS += vpp-api/python plugins

###############################################################################
# API
###############################################################################

include suffix-rules.mk

# Set the suffix list
apidir = $(prefix)/share/vpp/api/core

api_DATA = \
	$(patsubst %.api,%.api.json,$(API_FILES))

BUILT_SOURCES += \
	$(patsubst %.api,%.api.json,$(API_FILES)) \
	$(patsubst %.api,%.api.h,$(API_FILES))

endif # if ENABLE_VLIB
endif # if ENABLE_SVM
