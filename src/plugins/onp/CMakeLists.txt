# Copyright (c) 2021 Marvell.
# SPDX-License-Identifier: Apache-2.0
# https://spdx.org/licenses/Apache-2.0.html
#

if (NOT ${CMAKE_SYSTEM_PROCESSOR} MATCHES "aarch64")
    message ("Marvell OCTEON Native plugin (onp) is disabled on non Aarch64 targets")
    return ()
endif()

##############################################################################
# Find ONP roc files
##############################################################################
vpp_find_path(ONP_ROC_DIR PATH_SUFFIXES onp-roc NAMES platform.h)

if (NOT ONP_ROC_DIR)
	message(WARNING "-- ONP ROC files not found - Marvell OCTEON Native plugin (onp) plugin disabled")
  return()
endif()

include_directories (${ONP_ROC_DIR}/)
add_subdirectory (${ONP_ROC_DIR} drv)

set(ONP_DRV_SRCS
  drv/modules/pktio/pktio_cn10k.c
  drv/modules/pktio/pktio_cnxk.c
  drv/modules/pktio/pktio_flow.c

  drv/modules/pool/pool_cn10k.c
  drv/modules/pool/pool_cnxk.c

  drv/modules/pci/pci.c
)


add_vpp_library(onp-drv
  SOURCES ${ONP_DRV_SRCS}

  MULTIARCH_SOURCES
  drv/modules/pktio/pktio_cn10k.c

  LINK_LIBRARIES
  onp-roc
)

add_vpp_plugin(onp
  SOURCES
  onp.c
  cli.c
  api/api.c

  pool/buffer.c
  pool/cli.c

  pktio/cli.c
  pktio/pktio.c
  pktio/format.c
  pktio/input.c
  pktio/output.c

  MULTIARCH_SOURCES
  pktio/input.c
  pktio/output.c

  LINK_LIBRARIES
  onp-drv

  API_FILES
  api/types.api
  api/onp.api

  API_TEST_SOURCES
  api/api_test.c
)

install(FILES onp-startup.conf DESTINATION etc/vpp/ COMPONENT vpp-plugin-onp)
