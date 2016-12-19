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

libvatplugin_la_SOURCES = \
  tools/vpp-api-test/plugin_api.c

lib_LTLIBRARIES += libvatplugin.la

bin_PROGRAMS += vpp_api_test vpp_json_test vpp_restart

vpp_api_test_SOURCES = \
  tools/vpp-api-test/api_format.c 	\
  tools/vpp-api-test/main.c		\
  tools/vpp-api-test/plugin.c		\
  tools/vpp-api-test/vat.h		\
  tools/vpp-api-test/json_format.h	\
  tools/vpp-api-test/json_format.c

vpp_json_test_SOURCES = \
  tools/vpp-api-test/json_format.h	\
  tools/vpp-api-test/json_format.c	\
  tools/vpp-api-test/json_test.c

vpp_api_test_LDFLAGS = $(DPDK_LD_FLAGS)
vpp_api_test_LDADD = \
  libvnet.la \
  libvlib.la \
  libvlib_unix.la \
  libvlibmemoryclient.la		\
  libsvm.la				\
  libvatplugin.la			\
  libvppinfra.la 			\
  libvlibapi.la				\
  $(DPDK_LD_ADD)			\
  -lpthread -lm -lrt -ldl -lcrypto

vpp_json_test_LDADD = libvppinfra.la -lm

nobase_include_HEADERS += \
  tools/vpp-api-test/vat.h 		\
  tools/vpp-api-test/json_format.h

vpp_restart_SOURCES =  \
  tools/vpp-api-test/restart.c
vpp_restart_LDADD = \
  libsvmdb.la				\
  libsvm.la				\
  libvppinfra.la			\
  -lpthread -lrt

dist_bin_SCRIPTS += scripts/vppctl

# vi:syntax=automake
