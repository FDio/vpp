# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Cisco Systems, Inc.

add_vpp_plugin(ttl_fixup
  SOURCES
  ttl_fixup.c
  ttl_fixup_node.c

  MULTIARCH_SOURCES
  ttl_fixup_node.c

  API_FILES
  ttl_fixup.api

  INSTALL_HEADERS
  ttl_fixup.h
)
