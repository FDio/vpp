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
AM_CFLAGS = -Wall 

bin_PROGRAMS = c2cpel cpelatency cpeldump cpelinreg cpelstate

lib_LTLIBRARIES = libcperf.la

libcperf_la_SOURCES = delsvec.c linreg.c props.c cpel_util.c

TOOL_LIBS = libcperf.la -lvppinfra -lm

c2cpel_SOURCE = c2cpel.c
c2cpel_LDADD = $(TOOL_LIBS)

cpelatency_SOURCE = cpelatency.c
cpelatency_LDADD = $(TOOL_LIBS)

cpeldump_SOURCE = cpeldump.c
cpeldump_LDADD = $(TOOL_LIBS)

cpelinreg_SOURCE = cpelinreg.c
cpelinreg_LDADD = $(TOOL_LIBS)

cpelstate_SOURCE = cpelstate.c
cpelstate_LDADD = $(TOOL_LIBS)






