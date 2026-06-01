# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.

add_vpp_plugin(tracepath
  SOURCES
  tracepath.c
  tracepath_api.c
  plugin.c

  API_FILES
  tracepath.api

  INSTALL_HEADERS
  tracepath.h

  COMPONENT
  vpp-plugin-devtools
)
