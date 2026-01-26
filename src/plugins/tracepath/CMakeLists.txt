# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2025 Cisco Systems, Inc.

add_vpp_plugin(tracepath
  SOURCES
  tracepath.c
  plugin.c

  INSTALL_HEADERS
  tracepath.h

  COMPONENT
  vpp-plugin-devtools
)
