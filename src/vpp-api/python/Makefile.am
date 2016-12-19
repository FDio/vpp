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

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = -Wall -I${top_srcdir} -I${top_builddir}

BUILT_SOURCES =
bin_PROGRAMS =
CLEANFILES =
lib_LTLIBRARIES =
noinst_PROGRAMS =
nobase_include_HEADERS = pneum/pneum.h

#
# Python / C extension
#
lib_LTLIBRARIES += libpneum.la
libpneum_la_SOURCES = pneum/pneum.c
libpneum_la_LIBADD = \
  $(top_builddir)/libvppinfra.la \
  $(top_builddir)/libvlibmemoryclient.la \
  $(top_builddir)/libvlibapi.la \
  $(top_builddir)/libsvm.la \
  -lpthread -lm -lrt

libpneum_la_LDFLAGS = -module
libpneum_la_CPPFLAGS =

# TODO: Support both Python 2 and 3.
install-exec-local:
	cd $(srcdir);							\
	mkdir -p $(prefix)/lib/python2.7/site-packages; 		\
	PYTHONUSERBASE=$(prefix)					\
	python setup.py build_ext -L $(prefix)/lib64 \
	-I $(prefix)/include/ install --user

#
# Test client
#
noinst_PROGRAMS += test_pneum
test_pneum_SOURCES = pneum/pneum.c pneum/test_pneum.c
test_pneum_LDADD = \
  $(top_builddir)/libvppinfra.la \
  $(top_builddir)/libvlibmemoryclient.la \
  $(top_builddir)/libvlibapi.la \
  $(top_builddir)/libsvm.la \
  -lpthread -lm -lrt


