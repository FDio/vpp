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

AM_CFLAGS = -Wall @DPDK@ @IPSEC@ @VCGN@ @IPV6SR@

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
  api/api.c					\
  api/custom_dump.c

# comment out to disable stats upload to gmond 

vpp_SOURCES +=					\
  api/gmon.c	

nobase_include_HEADERS =			\
  api/vpe_all_api_h.h				\
  api/vpe_msg_enum.h				\
  api/vpe.api.h

# install the API definition, so we can produce java bindings, etc.

apidir = $(prefix)/api
api_DATA = api/vpe.api

BUILT_SOURCES += api/vpe.api.h app/version.h

app/version.o:	app/version.h

.PHONY:	app/version.h

app/version.h:
	@echo "  VERSION " $@ 
	@echo "#define VPP_BUILD_DATE \"$$(date)\"" > $@
	@echo "#define VPP_BUILD_USER \"$$(whoami)\"" >> $@
	@echo "#define VPP_BUILD_HOST \"$$(hostname)\"" >> $@
	@echo "#define VPP_BUILD_TOPDIR \"$$(git rev-parse --show-toplevel)\"" 	>> $@
	@echo "#define VPP_BUILD_VER \"$$(../../scripts/version)\"" >> $@

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
endif

vpp_LDADD += -lvppinfra -lm -lpthread -ldl

if WITH_IPV6SR
  vpp_LDADD += -lcrypto
endif

SUFFIXES = .api.h .api

%.api.h: %.api
	@echo "  APIGEN  " $@ ;					\
	mkdir -p `dirname $@` ;					\
	$(CC) $(CPPFLAGS) -E -P -C -x c $^			\
	| vppapigen --input - --output $@ --show-name $@


noinst_PROGRAMS += test_client

test_client_SOURCES = api/test_client.c
test_client_LDADD = -lvlibmemoryclient -lvlibapi -lsvm -lvppinfra \
	-lpthread -lm -lrt

noinst_PROGRAMS += test_client test_ha

test_ha_SOURCES = api/test_ha.c
test_ha_LDADD = -lvlibmemoryclient -lvlibapi -lsvmdb -lsvm -lvppinfra \
		-lpthread -lm -lrt



noinst_PROGRAMS += summary_stats_client

summary_stats_client_SOURCES = api/summary_stats_client.c
summary_stats_client_LDADD = -lvlibmemoryclient -lvlibapi -lsvm -lvppinfra \
	-lpthread -lm -lrt
