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

lib_LTLIBRARIES = libvlibapi.la libvlibmemory.la libvlibmemoryclient.la \
	          libvlibsocket.la

libvlibapi_la_SOURCES = 			\
	vlibapi/api.h				\
        vlibapi/api_helper_macros.h		\
	vlibapi/api_shared.c			\
	vlibapi/node_serialize.c

nobase_include_HEADERS = vlibapi/api.h vlibapi/api_helper_macros.h

libvlibmemory_la_SOURCES =			\
	vlibmemory/api.h			\
	vlibmemory/memclnt.api			\
	vlibmemory/memory_shared.c		\
	vlibmemory/memory_vlib.c		\
	vlibmemory/vl_memory_api_h.h		\
	vlibmemory/vl_memory_msg_enum.h		\
	vlibmemory/unix_shared_memory_queue.c	\
	vlibmemory/unix_shared_memory_queue.h 

libvlibmemoryclient_la_SOURCES = 		\
	vlibmemory/api.h			\
	vlibmemory/memclnt.api			\
	vlibmemory/memory_shared.c		\
	vlibmemory/memory_client.c		\
	vlibmemory/vl_memory_api_h.h		\
	vlibmemory/vl_memory_msg_enum.h		\
	vlibmemory/unix_shared_memory_queue.c	\
	vlibmemory/unix_shared_memory_queue.h 

nobase_include_HEADERS +=			\
	vlibmemory/api.h			\
	vlibmemory/vl_memory_api_h.h		\
	vlibmemory/vl_memory_msg_enum.h		\
	vlibmemory/unix_shared_memory_queue.h 	\
	vlibmemory/memclnt.api.h

libvlibsocket_la_SOURCES =			\
	vlibsocket/api.h			\
	vlibsocket/sockclnt.api			\
	vlibsocket/sockclnt_vlib.c		\
	vlibsocket/socksvr_vlib.c		\
	vlibsocket/vl_socket_api_h.h		\
	vlibsocket/vl_socket_msg_enum.h

nobase_include_HEADERS +=			\
	vlibsocket/api.h			\
	vlibsocket/vl_socket_api_h.h		\
	vlibsocket/vl_socket_msg_enum.h		\
	vlibsocket/sockclnt.api.h

BUILT_SOURCES =					\
	vlibsocket/sockclnt.api.h		\
	vlibmemory/memclnt.api.h		\
	vlibmemory/memclnt.api.json

SUFFIXES = .api.h .api .api.json

# The actual %.api.h rule is in .../build-data/packages/suffix-rules.mk
# and requires a symbolic link at the top of the vnet source tree

include $(top_srcdir)/suffix-rules.mk

# install the API definition, so we can produce java bindings, etc.
apidir = $(prefix)/vlibmemory
api_DATA = vlibmemory/memclnt.api.json
