# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2021 Cisco Systems, Inc.

vpp_find_path(VPPCLICK_INCLUDE_DIR NAMES click/vppclick.h)

if (NOT VPPCLICK_INCLUDE_DIR)
  message(WARNING "-- vppclick headers not found - click plugin disabled")
  return()
endif()

vpp_plugin_find_library(click VPPCLICK_LIB libvppclick.so)

if (NOT VPPCLICK_LIB)
  message(WARNING "click plugin - libvppclick library not found - click plugin disabled")
  return()
endif()


include_directories(${VPPCLICK_INCLUDE_DIR})

add_vpp_plugin(click
  SOURCES
  cli.c
  main.c
  node.c
  file.c
  packet.c

  LINK_LIBRARIES
  ${VPPCLICK_LIB}
)
