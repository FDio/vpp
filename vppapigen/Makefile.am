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

AUTOMAKE_OPTIONS = foreign

bin_PROGRAMS = vppapigen
bin_SCRIPTS =

BUILT_SOURCES = gram.h

gram.h: gram.y
	$(YACC) -d @srcdir@/gram.y
	mv y.tab.h gram.h
	rm y.tab.c

vppapigen_SOURCES = gram.y lex.c node.c
vppapigen_CPPFLAGS =
vppapigen_LDADD = -lvppinfra
vppapigen_LDFLAGS = -static
