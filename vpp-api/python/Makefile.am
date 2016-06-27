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
# Python binding
#
lib_LTLIBRARIES += libpneum.la
libpneum_la_SOURCES = pneum/pneum.c
libpneum_la_LIBADD = -lvlibmemoryclient -lvlibapi -lsvm -lvppinfra -lpthread -lm -lrt
libpneum_la_LDFLAGS = -module
libpneum_la_CPPFLAGS =

BUILT_SOURCES += vpp_papi.py

vpp_papi.py: $(prefix)/../vpp/vpp-api/vpe.api pneum/api-gen.py
	@echo "  PYTHON API";                                            	  \
	$(CC) $(CPPFLAGS) -E -P -C -x c $<			                  \
	| vppapigen --input - --python defs_$@;                                   \
	echo "#include <vpp-api/vpe_msg_enum.h>"                                      \
	| $(CC) $(CPPFLAGS) -E -P -x c - | grep VL_API                            \
	| @srcdir@/pneum/api-gen.py -i defs_$@ > @srcdir@/vpp_papi/$@

#
# Test client
#
noinst_PROGRAMS += test_pneum
test_pneum_SOURCES = pneum/pneum.c pneum/test_pneum.c
test_pneum_LDADD = -lvlibmemoryclient -lvlibapi -lsvm -lvppinfra -lpthread -lm -lrt
