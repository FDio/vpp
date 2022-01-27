# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022 Cisco Systems, Inc.
include_directories(${CMAKE_SOURCE_DIR}/vpp-api ${CMAKE_CURRENT_BINARY_DIR}/../../vpp-api)
add_vpp_plugin(apifromplugin
  SOURCES
  apifromplugin.c

  LINK_LIBRARIES vapiclient
  )
