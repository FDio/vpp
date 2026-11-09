# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022-2026 Cisco Systems, Inc.

# Shared by the octeon_net and octeon_crypto drivers. Expanded in the caller's
# scope, so return() leaves the calling driver's CMakeLists.txt.
macro(octeon_driver_prereqs name)
  if (NOT VPP_PLATFORM_NAME STREQUAL "octeon10" AND NOT VPP_PLATFORM_NAME STREQUAL "octeon9")
    return()
  endif()

  # Find OCTEON roc files
  vpp_find_path(OCTEON_ROC_DIR PATH_SUFFIXES octeon-roc NAMES platform.h)
  vpp_driver_find_library(${name} OCTEON_ROC_LIB "libocteon-roc.a")

  if (NOT OCTEON_ROC_DIR)
    message("OCTEON ROC files not found - Marvell ${name} driver disabled")
    return()
  endif()

  if (NOT OCTEON_ROC_LIB)
    message("OCTEON ROC library (libocteon-roc.a) not found - Marvell ${name} driver disabled")
    return ()
  endif()

  include_directories (${OCTEON_ROC_DIR}/)

  if (VPP_PLATFORM_NAME STREQUAL "octeon9")
    add_compile_definitions(PLATFORM_OCTEON9)
  endif()

  set(OCTEON_COMMON_DIR ${CMAKE_CURRENT_LIST_DIR}/../../common/octeon)
  set(OCTEON_COMMON_SOURCES
    ${OCTEON_COMMON_DIR}/octeon_common.c
    ${OCTEON_COMMON_DIR}/roc_helper.c
  )
endmacro()
