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

AM_CFLAGS = -Wall @DPDK@

PRE_DATA_SIZE=@PRE_DATA_SIZE@

lib_LTLIBRARIES = libvlib.la

BUILT_SOURCES = vlib/config.h

vlib/config.h:
	echo "#define __PRE_DATA_SIZE" $(PRE_DATA_SIZE) > $@

libvlib_la_SOURCES =				\
  vlib/cli.c					\
  vlib/cli.h					\
  vlib/config.h					\
  vlib/counter.c				\
  vlib/error.c					\
  vlib/format.c					\
  vlib/i2c.c					\
  vlib/init.c					\
  vlib/main.c					\
  vlib/mc.c					\
  vlib/node.c					\
  vlib/node_cli.c				\
  vlib/node_format.c				\
  vlib/pci/pci.c				\
  vlib/pci/linux_pci.c				\
  vlib/threads.c				\
  vlib/trace.c

if WITH_DPDK
  libvlib_la_SOURCES += vlib/dpdk_buffer.c
else
  libvlib_la_SOURCES += vlib/buffer.c
endif

nobase_include_HEADERS =			\
  vlib/buffer_funcs.h				\
  vlib/buffer_node.h				\
  vlib/buffer.h					\
  vlib/cli.h					\
  vlib/cli_funcs.h				\
  vlib/config.h					\
  vlib/counter.h				\
  vlib/defs.h					\
  vlib/error_funcs.h				\
  vlib/error.h					\
  vlib/format_funcs.h				\
  vlib/global_funcs.h				\
  vlib/i2c.h					\
  vlib/init.h					\
  vlib/main.h					\
  vlib/mc.h					\
  vlib/node_funcs.h				\
  vlib/node.h					\
  vlib/physmem.h				\
  vlib/pci/pci.h				\
  vlib/pci/pci_config.h				\
  vlib/threads.h				\
  vlib/trace_funcs.h				\
  vlib/trace.h					\
  vlib/vlib.h

lib_LTLIBRARIES += libvlib_unix.la

libvlib_unix_la_SOURCES =			\
  vlib/unix/cj.c				\
  vlib/unix/cli.c				\
  vlib/unix/input.c				\
  vlib/unix/main.c				\
  vlib/unix/mc_socket.c				\
  vlib/unix/plugin.c				\
  vlib/unix/plugin.h				\
  vlib/unix/physmem.c				\
  vlib/unix/util.c

nobase_include_HEADERS +=			\
  vlib/unix/cj.h				\
  vlib/unix/mc_socket.h				\
  vlib/unix/physmem.h				\
  vlib/unix/plugin.h				\
  vlib/unix/unix.h
    
if !WITH_DPDK
noinst_PROGRAMS = vlib_unix 

vlib_unix_SOURCES =				\
  example/main_stub.c				\
  example/mc_test.c

vlib_unix_LDADD = libvlib_unix.la libvlib.la \
	          -lvppinfra -lpthread -lm -ldl -lrt
endif
