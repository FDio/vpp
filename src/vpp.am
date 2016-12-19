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

bin_PROGRAMS += vpp

vpp_SOURCES =					\
  app/vnet/main.c				\
  app/app/vpe_cli.c				\
  app/app/version.c				\
  app/oam/oam.c					\
  app/stats/stats.c

vpp_SOURCES +=					\
  app/api/api.c					\
  app/api/custom_dump.c				\
  app/api/json_format.c

if WITH_APICLI
  vpp_SOURCES +=				\
  app/api/api_format.c				\
  app/api/api_main.c
endif

# comment out to disable stats upload to gmond

vpp_CFLAGS = @APICLI@
vpp_SOURCES +=					\
  app/api/gmon.c

nobase_include_HEADERS +=			\
  app/api/vpe_all_api_h.h			\
  app/api/vpe_msg_enum.h			\
  app/api/vpe.api.h

API_FILES += app/api/vpe.api

BUILT_SOURCES += app/app/version.h

app/app/version.o:	app/app/version.h

.PHONY:	app/app/version.h

app/app/version.h:
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

vpp_LDADD = \
  libvlibapi.la \
  libvlibmemory.la \
  libvlib_unix.la \
  libvlib.la \
  libvnet.la \
  libsvm.la \
  libsvmdb.la \
  libvnetplugin.la \
  -lrt

vpp_LDFLAGS = $(DPDK_LD_FLAGS)
vpp_LDADD += libvppinfra.la -lm -lpthread -ldl $(DPDK_LD_ADD)

if WITH_IPV6SR
  vpp_LDADD += -lcrypto
endif

noinst_PROGRAMS += test_client

test_client_SOURCES = \
  app/api/test_client.c

test_client_LDADD = \
  libvlibmemoryclient.la \
  libvlibapi.la \
  libsvm.la \
  libvppinfra.la \
  -lpthread -lm -lrt

noinst_PROGRAMS += test_client test_ha

test_ha_SOURCES = \
  app/api/test_ha.c

test_ha_LDADD = \
  libvlibmemoryclient.la \
  libvlibapi.la \
  libsvmdb.la \
  libsvm.la \
  libvppinfra.la \
  -lpthread -lm -lrt

noinst_PROGRAMS += summary_stats_client

summary_stats_client_SOURCES = \
  app/api/summary_stats_client.c

summary_stats_client_LDADD = \
  libvlibmemoryclient.la \
  libvlibapi.la \
  libsvm.la \
  libvppinfra.la \
  -lpthread -lm -lrt

bin_PROGRAMS += vpp_get_metrics

vpp_get_metrics_SOURCES = \
  app/api/vpp_get_metrics.c

vpp_get_metrics_LDADD = \
  libsvmdb.la \
  libsvm.la \
  libvppinfra.la \
  -lpthread -lm -lrt

# vi:syntax=automake
