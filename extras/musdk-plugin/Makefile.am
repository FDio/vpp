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

AM_CFLAGS = -Wall -I/opt/musdk/include
AM_LDFLAGS = -module -shared -avoid-version -L/opt/musdk/lib

vpppluginsdir = ${libdir}/vpp_plugins

vppplugins_LTLIBRARIES = musdk_plugin.la

musdk_plugin_la_SOURCES = \
	musdk.c				\
	ppv2/cli.c			\
	ppv2/format.c			\
	ppv2/input.c			\
	ppv2/output.c			\
	ppv2/ppv2.c

#musdk_plugin_la_LDFLAGS = $(AM_LDFLAGS) -Wl,-lmusdk
musdk_plugin_la_LDFLAGS = $(AM_LDFLAGS) -Wl,-l:libmusdk.a
#-Wl,--whole-archive,-l:libdpdk.a,--no-whole-archive

# Remove *.la files
install-data-hook:
	@(cd $(vpppluginsdir) && $(RM) $(vppplugins_LTLIBRARIES))

CLEANFILES = $(BUILT_SOURCES)
