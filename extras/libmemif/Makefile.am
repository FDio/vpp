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

AUTOMAKE_OPTIONS = foreign subdir-objects

ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = -g -DMEMIF_DBG -DICMP_DBG

SRCS_C := $(shell find . -name "*.c" )
SRCS_H := $(shell find . -name "*.h" )

.PHONY: release
release:
	$(MAKE) AM_CPPFLAGS="-O3"

.PHONY: doc
doc:
	@echo Building doxygen documentation...
	doxygen doxygen.conf
	@echo Doxygen documentation built in docs directory.

.PHONY: fixstyle
fixstyle:
	@echo Fixing code style...
	indent $(SRCS_C) $(SRCS_H)
	@echo Code style fixed!

#
# unit_test
#
unit_test_SOURCES = test/unit_test.c \
                    test/main_test.c \
                    test/socket_test.c \
                    src/main.c \
                    src/socket.c
# macro MEMIF_UNIT_TEST -> compile functions without static keyword
# and declare them in header files, so they can be called from unit tests
unit_test_CPPFLAGS = $(AM_CPPFLAGS) -Itest -Isrc -DMEMIF_UNIT_TEST -g $(CHECK_CFLAGS)
unit_test_LDADD = $(CHECK_LIBS)

#
# main lib
#
libmemif_la_SOURCES = src/main.c src/socket.c
libmemif_la_CPPFLAGS = $(AM_CPPFLAGS) -Isrc

#
# ICMP responder example
#
icmpr_SOURCES = examples/icmp_responder/main.c examples/icmp_responder/icmp_proto.c
icmpr_LDADD = libmemif.la
icmpr_CPPFLAGS = $(AM_CPPFLAGS) -Isrc -Iexamples/icmp_responder

#
# ICMP responder libmemif event polling example
#
icmpr_epoll_SOURCES = examples/icmp_responder-epoll/main.c \
                    examples/icmp_responder/icmp_proto.c
icmpr_epoll_LDADD = libmemif.la -lpthread
icmpr_epoll_CPPFLAGS = $(AM_CPPFLAGS) -Isrc -Iexamples/icmp_responder

#
# ICMP responder multi-thread example
#
icmpr_mt_SOURCES = examples/icmp_responder-mt/main.c \
                      examples/icmp_responder/icmp_proto.c
icmpr_mt_LDADD = libmemif.la -lpthread
icmpr_mt_CPPFLAGS = $(AM_CPPFLAGS) -Isrc -Iexamples/icmp_responder

noinst_PROGRAMS = icmpr icmpr-epoll icmpr-mt

include_HEADERS = src/libmemif.h src/memif.h

lib_LTLIBRARIES = libmemif.la

if USE_CHECK
check_PROGRAMS = unit_test
TESTS = $(check_PROGRAMS)
endif
