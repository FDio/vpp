# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022-2026 Cisco Systems, Inc.

include(${CMAKE_CURRENT_LIST_DIR}/../../common/octeon/octeon.cmake)
octeon_driver_prereqs(octeon_crypto)

add_vpp_driver(octeon_crypto
  SOURCES
  init.c
  crypto.c
  ${OCTEON_COMMON_SOURCES}

  INCLUDE_DIRECTORIES
  ${OCTEON_COMMON_DIR}

  LINK_LIBRARIES
  ${OCTEON_ROC_LIB}
)
