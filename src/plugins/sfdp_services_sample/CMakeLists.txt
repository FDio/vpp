# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cisco Systems, Inc.

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_vpp_plugin(sfdp_services_sample
  SOURCES
  services_sample/node.c
  plugin.c

  MULTIARCH_SOURCES
  services_sample/node.c
)
