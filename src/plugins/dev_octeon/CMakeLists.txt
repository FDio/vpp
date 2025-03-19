# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022 Cisco Systems, Inc.

if (NOT VPP_PLATFORM_NAME STREQUAL "octeon10" AND NOT VPP_PLATFORM_NAME STREQUAL "octeon9")
  return()
endif()

# Find OCTEON roc files
vpp_find_path(OCTEON_ROC_DIR PATH_SUFFIXES octeon-roc NAMES platform.h)
vpp_plugin_find_library(dev-octeon OCTEON_ROC_LIB "libocteon-roc.a")

if (NOT OCTEON_ROC_DIR)
  message("OCTEON ROC files not found - Marvell OCTEON device plugin disabled")
  return()
endif()

if (NOT OCTEON_ROC_LIB)
  message("OCTEON ROC library (libocteon-roc.a) not found - Marvell OCTEON device plugin disabled")
  return ()
endif()

include_directories (${OCTEON_ROC_DIR}/)

if (VPP_PLATFORM_NAME STREQUAL "octeon9")
   add_compile_definitions(PLATFORM_OCTEON9)
endif()

add_vpp_plugin(dev_octeon
  SOURCES
  init.c
  format.c
  port.c
  queue.c
  roc_helper.c
  rx_node.c
  tx_node.c
  flow.c
  counter.c
  crypto.c

  MULTIARCH_SOURCES
  rx_node.c
  tx_node.c

  LINK_LIBRARIES
  ${OCTEON_ROC_LIB}

  COMPONENT
  vpp-plugin-octeon
)

