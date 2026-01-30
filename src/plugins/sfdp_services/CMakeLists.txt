# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Cisco Systems, Inc.
#

#include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(sfdp_services_sources
  plugin.c
  base/tcp-check/node.c
  base/tcp-check/tcp_check.c
  base/tcp-check/format.c
  base/tcp-check/cli.c
  base/tcp-check/api.c

  base/l4-lifecycle/node.c

  base/nat/nat.c
  base/nat/cli.c
  base/nat/api.c
  base/nat/format.c
  base/nat/fastpath_node.c
  base/nat/slowpath_node.c
  base/nat/external_input_node.c

  base/interface_input/interface_input.c
  base/interface_input/cli.c
  base/interface_input/api.c
  base/interface_input/node.c

  acl/acl_sample.c
  acl/cli.c
  acl/node.c

  dot1q/dot1q.c

  geneve/gateway.c
  geneve/cli.c
  geneve/api.c
  geneve/geneve_input/node.c
  geneve/geneve_output/node.c

  reass/reass.c
  reass/sv_reass_node.c
  #reass/full_reass_node.c
)

set(sfdp_services_multiarch_sources
  base/tcp-check/node.c
  base/l4-lifecycle/node.c
  base/interface_input/node.c
  acl/node.c
  geneve/geneve_input/node.c
  geneve/geneve_output/node.c
  dot1q/dot1q.c
  reass/sv_reass_node.c
  #reass/full_reass_node.c
)

# Check for libdaq installation for snort service
find_path(LIBDAQ_INCLUDE_DIR NAMES daq_module_api.h daq_dlt.h daq_version.h)
find_library(LIBDAQ_LINK_LIBRARY NAMES libdaq.a)

file(STRINGS ${LIBDAQ_INCLUDE_DIR}/daq_version.h daq_version)
foreach(l ${daq_version})
  if (l MATCHES "^#define[\t ]*DAQ_")
    STRING(REGEX REPLACE "^#define[\t ]*([A-Z1-9_]+)[\t ]*(.+)" "\\1;\\2" v "${l}")
    list(GET v 0 name)
    list(GET v 1 value)
    set(${name} ${value})
  endif()
endforeach()

set(DAQ_VER "${DAQ_VERSION_MAJOR}.${DAQ_VERSION_MINOR}.${DAQ_VERSION_PATCH}")

if (LIBDAQ_INCLUDE_DIR AND ${DAQ_VER} VERSION_GREATER_EQUAL "3.0.21")
  list(APPEND sfdp_services_sources
    snort/snort.c
    snort/snort_input.c
    snort/snort_output.c
  )

  list(APPEND sfdp_services_multiarch_sources
    snort/snort_input.c
    snort/snort_output.c
  )
endif()

add_vpp_plugin(sfdp_services
  SOURCES
  ${sfdp_services_sources}

  MULTIARCH_SOURCES
  ${sfdp_services_multiarch_sources}

  API_FILES
  base/nat/nat.api
  base/tcp-check/tcp_check.api
  base/interface_input/interface_input.api
  geneve/gateway.api
)
