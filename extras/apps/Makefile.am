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

AM_CFLAGS = -Wall

SRCS_C := $(shell find . -name "*.c" )
SRCS_H := $(shell find . -name "*.h" )

.PHONY: fixstyle
fixstyle:
	@echo Fixing code style...
	indent $(SRCS_C) $(SRCS_H)
	@echo Code style fixed!

#
# Socket client and server apps
#
socket_echo_client_SOURCES = src/socket_echo_client.c
socket_echo_client_LDADD = -lvppinfra
socket_echo_client_CFLAGS = $(AM_CPPFLAGS) -Isrc

socket_echo_server_SOURCES = src/socket_echo_server.c
socket_echo_server_LDADD = -lvppinfra
socket_echo_server_CFLAGS = $(AM_CPPFLAGS) -Isrc

noinst_PROGRAMS = socket_echo_client socket_echo_server

