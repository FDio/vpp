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

AM_CFLAGS = -Wall -I@TOOLKIT_INCLUDE@

libsixrd_plugin_la_SOURCES =			\
	sixrd/sixrd.c				\
	sixrd/ip4_sixrd.c			\
	sixrd/ip6_sixrd.c

nobase_include_HEADERS =			\
	sixrd/sixrd.h

libsixrd_plugin_la_LDFLAGS = -module

BUILT_SOURCES =

lib_LTLIBRARIES = libsixrd_plugin.la

if WITH_PLUGIN_TOOLKIT
install-data-hook:
	mkdir /usr/lib/vpp_plugins || true
	mkdir /usr/lib/vpp_api_test_plugins || true
	cp -L $(prefix)/lib/libsixrd_plugin.so /usr/lib/vpp_plugins
endif
