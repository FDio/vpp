# Copyright (c) 2017 Cisco and/or its affiliates.
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

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4
AM_LIBTOOLFLAGS = --quiet

AM_CFLAGS = @CPU_FLAGS@ -Wall -I${top_srcdir} -I${top_builddir} -I. -I$(top_srcdir)/vpp-api/

AM_LDFLAGS = -shared -avoid-version -rpath /none -no-undefined

bin_PROGRAMS =
noinst_LTLIBRARIES =
CLEANDIRS =

vapi/%.api.vapi.h: %.api.json vapi_c_gen.py vapi_json_parser.py
	@echo "  VAPI C GEN $< " $@ ;			\
	mkdir -p `dirname $@` ;				\
        $(top_srcdir)/vpp-api/vapi/vapi_c_gen.py --prefix=vapi $<

vapi/%.api.vapi.hpp: %.api.json vapi_cpp_gen.py vapi_c_gen.py vapi_json_parser.py
	@echo "  VAPI CPP GEN $< " $@ ;			\
	mkdir -p `dirname $@` ;				\
        $(top_srcdir)/vpp-api/vapi/vapi_cpp_gen.py --prefix=vapi --gen-h-prefix=vapi $<

%.api.json:
	find $(top_builddir) -name '$@' | xargs ln -s

BUILT_SOURCES = $(shell find $(top_builddir) -name '*.api.json' | xargs -n1 basename) \
  $(patsubst %.api.json,vapi/%.api.vapi.h,$(JSON_FILES)) \
  $(patsubst %.api.json,vapi/%.api.vapi.hpp,$(JSON_FILES))

vapi.c: $(BUILT_SOURCES)

JSON_FILES = $(wildcard *.api.json)

lib_LTLIBRARIES = libvapiclient.la

libvapiclient_la_SOURCES = vapi.c

libvapiclient_la_DEPENDENCIES = libvapiclient.map

libvapiclient_la_LIBADD = -lpthread -lm -lrt \
  $(top_builddir)/libvppinfra.la \
  $(top_builddir)/libvlibmemoryclient.la \
  $(top_builddir)/libsvm.la

libvapiclient_la_LDFLAGS = \
  -Wl,-L$(top_builddir)/.libs,--whole-archive,--no-whole-archive \
  -Wl,--version-script=$(srcdir)/libvapiclient.map,-lrt

libvapiclient_la_CPPFLAGS = -I. -I$(top_builddir)/vpp-api/vapi

vapiincludedir = $(includedir)/vapi

vapiinclude_HEADERS = vapi.h \
  vapi.hpp \
  vapi_dbg.h \
  vapi_common.h \
  vapi_internal.h \
  $(patsubst %.api.json,vapi/%.api.vapi.h,$(JSON_FILES)) \
  $(patsubst %.api.json,vapi/%.api.vapi.hpp,$(JSON_FILES))

# vi:syntax=automake
