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

noinst_PROGRAMS += test_pneum
nobase_include_HEADERS += vpp-api/python/pneum/pneum.h

#
# Python / C extension
#
lib_LTLIBRARIES += libpneum.la
libpneum_la_SOURCES = vpp-api/python/pneum/pneum.c
libpneum_la_LIBADD = \
	libvlibmemoryclient.la		\
	libvlibapi.la			\
	libsvm.la			\
	libvppinfra.la			\
	-lpthread -lm -lrt

libpneum_la_LDFLAGS = -module
libpneum_la_CPPFLAGS =

# TODO: Support both Python 2 and 3.
install-exec-local:
	cd $(srcdir)/vpp-api/python;					\
	mkdir -p $(prefix)/lib/python2.7/site-packages; 		\
	PYTHONUSERBASE=$(prefix)					\
	python setup.py build_ext -L $(prefix)/lib64			\
	-I $(prefix)/include/ install --user

#
# Test client
#
test_pneum_SOURCES = \
	vpp-api/python/pneum/pneum.c		\
	vpp-api/python/pneum/test_pneum.c

test_pneum_LDADD = \
	libvlibmemoryclient.la			\
	libvlibapi.la				\
	libsvm.la				\
	libvppinfra.la				\
	-lpthread -lm -lrt

# vi:syntax=automake
