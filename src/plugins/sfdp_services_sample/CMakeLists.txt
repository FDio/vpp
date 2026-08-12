# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cisco Systems, Inc.

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_vpp_plugin(sfdp_services_sample
  SOURCES
  node.c
  parser.c
  parser_input.c
  plugin.c

  MULTIARCH_SOURCES
  node.c
  parser.c
)
