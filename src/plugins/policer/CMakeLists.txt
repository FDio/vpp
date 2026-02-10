# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.

add_vpp_library(policer
  SOURCES
  policer.c
  xlate.c

  INSTALL_HEADERS
  policer.h
)

add_vpp_plugin(policer
  SOURCES
  ip4_punt.c
  ip6_punt.c
  policer_node.c
  policer_api.c
  policer_cli.c

  MULTIARCH_SOURCES
  ip4_punt.c
  ip6_punt.c
  policer_node.c

  INSTALL_HEADERS
  ip_punt.h

  LINK_LIBRARIES
  policer

  API_FILES
  policer.api
  policer_types.api
)

add_vpp_plugin(policer_unittest
  SOURCES
  test/policer_unittest.c

  LINK_LIBRARIES
  policer
)
