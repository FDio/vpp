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
ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = -Wall

BUILT_SOURCES =
bin_PROGRAMS =
CLEANFILES =
lib_LTLIBRARIES =
noinst_PROGRAMS = test_pneum
nobase_include_HEADERS = pneum/pneum.h

#
# Python / C extension
#
lib_LTLIBRARIES += vpp_api.la
vpp_api_la_SOURCES = pneum/pneum.c vpp_papi/pneum_wrap.c
vpp_api_la_LIBADD = -lvlibmemoryclient -lvlibapi -lsvm -lvppinfra -lpthread -lm -lrt
vpp_api_la_LDFLAGS = -module $(shell python-config --ldflags)
vpp_api_la_CPPFLAGS = $(shell python-config --includes)

# Kept around for setuptools based install.
lib_LTLIBRARIES += libpneum.la
libpneum_la_SOURCES = pneum/pneum.c setup.py
libpneum_la_LIBADD = -lvlibmemoryclient -lvlibapi -lsvm -lvppinfra -lpthread -lm -lrt
libpneum_la_LDFLAGS = -module
libpneum_la_CPPFLAGS =

#
# Core VPP API
#
BUILT_SOURCES +=					\
	$(prefix)/../vpp/vpp-api/vpe.py			\
	$(prefix)/../vlib-api/vlibmemory/memclnt.py

%.py: %.api
	$(info Creating Python binding for $@)
	$(CC) $(CPPFLAGS) -E -P -C -x c $<	\
	| vppapigen --input - --python -	\
	| pyvppapigen.py --input - > $@

#
# TODO: Support both Python 2 and 3.
install-exec-local:
	cd $(srcdir); \
	mkdir -p $(prefix)/lib/python2.7/site-packages; \
	PYTHONUSERBASE=$(prefix) python setup.py install --user

#
# Test client
#
noinst_PROGRAMS += test_pneum
test_pneum_SOURCES = pneum/pneum.c pneum/test_pneum.c
test_pneum_LDADD = -lvlibmemoryclient -lvlibapi -lsvm -lvppinfra -lpthread -lm -lrt
