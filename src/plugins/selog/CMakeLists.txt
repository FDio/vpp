# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Cisco Systems, Inc.
#

add_vpp_plugin(selog
  SOURCES
  selog.c
  api.c
  cli.c

  API_FILES
  selog.api

  INSTALL_HEADERS
  selog.h
  selog_shared.h
)