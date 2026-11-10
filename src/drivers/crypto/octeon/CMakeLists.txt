# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022-2026 Cisco Systems, Inc.

include(${CMAKE_CURRENT_LIST_DIR}/../../common/octeon/octeon.cmake)
octeon_driver_prereqs(octeon_cpt)

add_vpp_driver(octeon_cpt
  SOURCES
  init.c
  key.c
  algs.c
  deq.c
  enq.c
  format.c
  queue.c
  session.c
  ${OCTEON_COMMON_SOURCES}

  MULTIARCH_SOURCES
  deq.c
  enq.c

  INCLUDE_DIRECTORIES
  ${OCTEON_COMMON_DIR}

  LINK_LIBRARIES
  ${OCTEON_ROC_LIB}
)
