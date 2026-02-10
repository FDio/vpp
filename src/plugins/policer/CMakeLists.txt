# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.

add_vpp_plugin(policer
  SOURCES
  ip4_punt.c
  ip6_punt.c
  policer_node.c
  policer_api.c
  policer_cli.c
  policer_op.c
  xlate.c
  plugin.c

  MULTIARCH_SOURCES
  ip4_punt.c
  ip6_punt.c
  policer_node.c

  INSTALL_HEADERS
  policer.h
  ip_punt.h

  API_FILES
  policer.api
  policer_types.api
)
