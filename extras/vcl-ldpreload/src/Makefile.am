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

AM_CFLAGS = -Wall -fstack-protector -fPIC -Werror -g -DFORTIFY_SOURCE=2
AM_LDFLAGS = -shared

if VPP_DEBUG
AM_CFLAGS += -O0 -DCLIB_DEBUG
vpp_build = vpp_debug-native
else
AM_CFLAGS += -O2
vpp_build = vpp-native
endif

if VCL_LDPRELOAD_DEBUG
AM_CFLAGS += -ggdb '-DVCOM_DEBUG=1'
else
AM_CFLAGS += -Wall '-DVCOM_DEBUG=0'
endif

if VPP_DIR_SET
vpp_install_dir = @VPP_DIR@/build-root/install-$(vpp_build)/vpp
AM_CFLAGS += -I$(vpp_install_dir)/include/
AM_LDFLAGS += -L$(vpp_install_dir)/lib64/
endif


AM_LDFLAGS += -lvppcom -lvppinfra

SUBDIRS = .
noinst_HEADERS =
dist_bin_SCRIPTS =
lib_LTLIBRARIES =
BUILT_SOURCES =
CLEANFILES =


###############################################################################
# Components
###############################################################################

include libvcl-ldpreload.am


