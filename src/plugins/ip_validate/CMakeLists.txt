# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cisco and/or its affiliates.

add_vpp_plugin(ip_validate
  SOURCES
  ip_validate.c
  ip4_validate_node.c
  ip6_validate_node.c

  API_FILES
  ip_validate.api
)
