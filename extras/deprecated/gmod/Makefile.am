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

AM_CFLAGS = -Wall 

lib_LTLIBRARIES = libgmodvpp.la

libgmodvpp_la_SOURCES = gmod/mod_vpp.c

libgmodvpp_la_LDFLAGS = -module -avoid-version

libgmodvpp_la_LIBADD = -lsvm -lsvmdb -lvppinfra -lapr-1

gconfdir = $(prefix)/etc/conf.d
gconf_DATA = gmod/vpp.conf
