# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022 Cisco Systems, Inc.


find_path(MUSDK_INCLUDE_DIR NAMES mv_std.h)
find_library(MUSDK_LIB NAMES libmusdk.a)

if(NOT MUSDK_INCLUDE_DIR OR NOT MUSDK_LIB)
  message(WARNING "Marvell MUSDK not found - dev_armada plugin disabled")
  return()
endif()

get_filename_component(MUSDK_LIB_DIR ${MUSDK_LIB} DIRECTORY)
set(MUSDK_LINK_FLAGS "-Wl,--whole-archive,${MUSDK_LIB_DIR}/libmusdk.a,--no-whole-archive")

add_vpp_plugin(dev_armada
  SOURCES
  plugin.c
  pp2/counters.c
  pp2/init.c
  pp2/format.c
  pp2/port.c
  pp2/queue.c
  pp2/rx.c
  pp2/tx.c

  LINK_FLAGS
  ${MUSDK_LINK_FLAGS}
)
include_directories(${MUSDK_INCLUDE_DIR})

