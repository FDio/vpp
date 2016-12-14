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

AM_CFLAGS = -Wall @DPDK@ @DPDK_CRYPTO@ @IPSEC@ @VCGN@ @IPV6SR@ @APICLI@

noinst_PROGRAMS = 
BUILT_SOURCES =
bin_PROGRAMS = 
CLEANFILES = 

bin_PROGRAMS += vpp

vpp_SOURCES =					\
  vnet/main.c					\
  app/vpe_cli.c					\
  app/version.c					\
  oam/oam.c					\
  stats/stats.c

vpp_SOURCES +=					\
  vpp-api/api.c					\
  vpp-api/custom_dump.c				\
  vpp-api/json_format.c

if WITH_APICLI
  vpp_SOURCES +=				\
  vpp-api/api_format.c				\
  vpp-api/api_main.c				
endif


# comment out to disable stats upload to gmond 

vpp_SOURCES +=					\
  vpp-api/gmon.c	

nobase_include_HEADERS =			\
  vpp-api/vpe_all_api_h.h			\
  vpp-api/vpe_msg_enum.h			\
  vpp-api/vpe.api.h

# install the API definition, so we can produce java bindings, etc.

apidir = $(prefix)/vpp-api
api_DATA = vpp-api/vpe.api.json

BUILT_SOURCES += vpp-api/vpe.api.h app/version.h vpp-api/vpe.api.json

app/version.o:	app/version.h

.PHONY:	app/version.h

app/version.h:
	@echo "  VERSION " $@ 
	@echo "#define VPP_BUILD_DATE \"$$(date)\"" > $@
	@echo "#define VPP_BUILD_USER \"$$(whoami)\"" >> $@
	@echo "#define VPP_BUILD_HOST \"$$(hostname)\"" >> $@
	@echo "#define VPP_BUILD_TOPDIR \"$$(git rev-parse --show-toplevel)\"" 	>> $@
	@echo "#define VPP_BUILD_VER \"$$(../../scripts/version)\"" >> $@

# Generate a plugin configuration script. Misconfiguring a
# plugin can cause very subtle problems.

bin_SCRIPTS = vpp_plugin_configure

BUILT_SOURCES += vpp_plugin_configure

.PHONY: vpp_plugin_configure

if WITH_DPDK
PLUGIN_DPDK_ARG="--with-dpdk"
else
PLUGIN_DPDK_ARG=""
endif

vpp_plugin_configure:
	@echo "PLUGIN CONFIGURE " $@ 
	@echo "#!/bin/bash" > $@
	@echo " " >> $@
	@echo "set +eu" >> $@
	@echo " " >> $@
	@echo "if [ -f ./configure ] ; then" >> $@
	@echo "    CFLAGS='$(CFLAGS) $(AM_CFLAGS) -I/usr/include/vpp-dpdk' ./configure --with-plugin-toolkit $(PLUGIN_DPDK_ARG)" >> $@
	@echo "else" >> $@
	@echo "    if [ -f ../configure ] ; then" >> $@
	@echo "        CFLAGS='$(CFLAGS) $(AM_CFLAGS) -I/usr/include/vpp-dpdk' ../configure --with-plugin-toolkit $(PLUGIN_DPDK_ARG)" >> $@
	@echo "    else" >> $@
	@echo "        echo Couldnt find ./configure or ../configure " >> $@
	@echo "        exit 1" >> $@
	@echo "    fi" >> $@
	@echo "fi" >> $@

vpp_LDADD = -lvlibapi -lvlibmemory  -lvlib_unix -lvlib

vpp_LDADD += -lvnet

vpp_LDADD += -lsvm -lsvmdb -lrt

vpp_LDADD += -lvnetplugin

if WITH_DPDK
vpp_LDFLAGS = -Wl,--whole-archive
if ENABLE_DPDK_SHARED
vpp_LDFLAGS += -ldpdk
else
vpp_LDFLAGS += -l:libdpdk.a
endif
vpp_LDFLAGS += -Wl,--no-whole-archive
if WITH_DPDK_CRYPTO
vpp_LDADD += -L$(AESNI_MULTI_BUFFER_LIB_PATH) -lIPSec_MB
endif
endif

vpp_LDADD += -lvppinfra -lm -lpthread -ldl

if WITH_IPV6SR
  vpp_LDADD += -lcrypto
endif

# Set the suffix list
SUFFIXES = .api.h .api .api.json

# The actual %.api.h rule is in .../build-data/packages/suffix-rules.mk
# and requires a symbolic link at the top of the vpp source tree

include $(top_srcdir)/suffix-rules.mk

noinst_PROGRAMS += test_client

test_client_SOURCES = vpp-api/test_client.c
test_client_LDADD = -lvlibmemoryclient -lvlibapi -lsvm -lvppinfra \
	-lpthread -lm -lrt

noinst_PROGRAMS += test_client test_ha

test_ha_SOURCES = vpp-api/test_ha.c
test_ha_LDADD = -lvlibmemoryclient -lvlibapi -lsvmdb -lsvm -lvppinfra \
		-lpthread -lm -lrt


noinst_PROGRAMS += summary_stats_client

summary_stats_client_SOURCES = vpp-api/summary_stats_client.c
summary_stats_client_LDADD = -lvlibmemoryclient -lvlibapi -lsvm -lvppinfra \
	-lpthread -lm -lrt

bin_PROGRAMS += vpp_get_metrics

vpp_get_metrics_SOURCES = vpp-api/vpp_get_metrics.c
vpp_get_metrics_LDADD = -lsvmdb -lsvm -lvppinfra \
		-lpthread -lm -lrt
