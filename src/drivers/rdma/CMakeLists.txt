# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022 Cisco Systems, Inc.

vpp_find_path(IBVERBS_INCLUDE_DIR NAMES infiniband/verbs.h)

if (NOT IBVERBS_INCLUDE_DIR)
  message(WARNING "-- rdma headers not found - rdma plugin disabled")
  return()
endif()

vpp_plugin_find_library(rdma IBVERBS_LIB libibverbs.a)

if (NOT IBVERBS_LIB)
  message(WARNING "rdma plugin - ibverbs not found - rdma plugin disabled")
  return()
endif()

set(CMAKE_REQUIRED_FLAGS "-fPIC -shared -pthread -Wno-unused-command-line-argument ${IBVERBS_LIB}")
set(CMAKE_REQUIRED_INCLUDES "${IBVERBS_INCLUDE_DIR}")
set(CMAKE_REQUIRED_LIBRARIES "c") # force linkage by including libc explicitely
CHECK_C_SOURCE_COMPILES("
#include <infiniband/verbs.h>
int main(void)
{
    return 0 != ibv_get_device_list(0);
}" IBVERBS_COMPILES_CHECK)

if (NOT IBVERBS_COMPILES_CHECK)
  message(WARNING "rdma plugins - no working ibverbs found - rdma plugin disabled")
  return()
endif()

add_vpp_driver(dev_rdma
  SOURCES
  common.c
  flow.c
  format.c
  init.c
  port.c
  queue.c
  rx_node.c
  tx_node.c
  plugin.c

  MULTIARCH_SOURCES
  rx_node.c
  tx_node.c

  INCLUDE_DIRECTORIES
  ${IBVERBS_INCLUDE_DIR}

  LINK_LIBRARIES
  ${IBVERBS_LIB}
)
