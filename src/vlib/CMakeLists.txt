# Copyright (c) 2018 Cisco and/or its affiliates.
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

option(VPP_BUFFER_FAULT_INJECTOR "Include the buffer fault injector" OFF)

##############################################################################
# Generate vlib/config.h
##############################################################################
if(VPP_BUFFER_FAULT_INJECTOR)
  set(BUFFER_ALLOC_FAULT_INJECTOR 1 CACHE STRING "fault injector on")
else()
  set(BUFFER_ALLOC_FAULT_INJECTOR 0 CACHE STRING "fault injector off")
endif()

if(VPP_PLATFORM_BUFFER_ALIGN)
  set(VLIB_BUFFER_ALIGN ${VPP_PLATFORM_BUFFER_ALIGN})
else()
  set(VLIB_BUFFER_ALIGN ${VPP_CACHE_LINE_SIZE})
endif()

set(PRE_DATA_SIZE 128 CACHE STRING "Buffer headroom size.")

if (CMAKE_BUILD_TYPE_UC STREQUAL "DEBUG")
  set(_ss 16)
else()
  set(_ss 15)
endif()
set(VLIB_PROCESS_LOG2_STACK_SIZE
 ${_ss}
 CACHE
 STRING "Process node default stack size (log2)"
)

configure_file(
  ${CMAKE_SOURCE_DIR}/vlib/config.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/config.h
)
install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/config.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/vlib
  COMPONENT vpp-dev
)

##############################################################################
# vlib shared library
##############################################################################

if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
set(PLATFORM_SOURCES
  linux/pci.c
  linux/vfio.c
  linux/vmbus.c
)

set(PLATFORM_HEADERS
  linux/vfio.h
)
elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "FreeBSD")
set(PLATFORM_SOURCES
  freebsd/pci.c
)
endif()

set(VLIB_LIBS vppinfra svm ${CMAKE_DL_LIBS} ${EPOLL_LIB})

vpp_find_path(LIBIBERTY_INCLUDE_DIR libiberty/demangle.h)
vpp_find_library(LIBIBERTY_LIB NAMES iberty libiberty)

if (LIBIBERTY_INCLUDE_DIR AND LIBUNWIND_LIB)
  message(STATUS "libiberty found at ${LIBIBERTY_LIB}")
  list(APPEND VLIB_LIBS ${LIBIBERTY_LIB})
  add_definitions(-DHAVE_LIBIBERTY)
else()
  message(WARNING "libiberty not found - stack trace demangle disabled")
endif()

add_vpp_library(vlib
  SOURCES
  buffer.c
  buffer_funcs.c
  cli.c
  counter.c
  drop.c
  error.c
  file.c
  format.c
  handoff_trace.c
  init.c
  log.c
  main.c
  node.c
  node_cli.c
  node_format.c
  node_init.c
  pci/pci.c
  pci/pci_types_api.c
  physmem.c
  punt.c
  punt_node.c
  stats/cli.c
  stats/collector.c
  stats/format.c
  stats/init.c
  stats/provider_mem.c
  stats/stats.c
  threads.c
  threads_cli.c
  time.c
  trace.c
  unix/cli.c
  unix/main.c
  unix/plugin.c
  unix/util.c
  vmbus/vmbus.c
  dma/dma.c
  dma/cli.c
  ${PLATFORM_SOURCES}

  MULTIARCH_SOURCES
  buffer_funcs.c
  drop.c
  punt_node.c
  node_init.c

  INSTALL_HEADERS
  buffer_funcs.h
  buffer.h
  buffer_node.h
  cli.h
  counter.h
  counter_types.h
  defs.h
  dma/dma.h
  error_funcs.h
  error.h
  file.h
  format_funcs.h
  global_funcs.h
  init.h
  log.h
  main.h
  node_funcs.h
  node.h
  pci/pci_config.h
  pci/pci.h
  pci/pci_types_api.h
  physmem_funcs.h
  physmem.h
  punt.h
  stats/shared.h
  stats/stats.h
  threads.h
  time.h
  trace_funcs.h
  trace.h
  tw_funcs.h
  unix/mc_socket.h
  unix/plugin.h
  unix/unix.h
  vlib.h
  vmbus/vmbus.h
  ${PLATFORM_HEADERS}

  API_FILES
  pci/pci_types.api

  LINK_LIBRARIES ${VLIB_LIBS}

  DEPENDS api_headers
)
