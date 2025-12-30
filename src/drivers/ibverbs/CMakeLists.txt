# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022 Cisco Systems, Inc.

vpp_find_path(IBVERBS_INCLUDE_DIR NAMES infiniband/verbs.h)

if (NOT IBVERBS_INCLUDE_DIR)
  message(WARNING "-- ibverbs headers not found - ibverbs driver disabled")
  return()
endif()

vpp_driver_find_library(ibverbs IBVERBS_LIB libibverbs.a)
vpp_driver_find_library(ibverbs MLX4_LIB libmlx4.a)
vpp_driver_find_library(ibverbs MLX5_LIB libmlx5.a)

if (NOT IBVERBS_LIB OR NOT MLX4_LIB OR NOT MLX5_LIB)
  message(WARNING "ibverbs driver - ibverbs/mlx4/mlx5 not found - ibverbs driver disabled")
  return()
endif()

string_append(IBVERBS_LINK_FLAGS "-Wl,--whole-archive,${MLX4_LIB},${MLX5_LIB},--no-whole-archive -Wl,--exclude-libs,ALL")

set(CMAKE_REQUIRED_FLAGS "-fPIC -shared -pthread -Wno-unused-command-line-argument ${IBVERBS_LINK_FLAGS} ${IBVERBS_LIB}")
set(CMAKE_REQUIRED_INCLUDES "${IBVERBS_INCLUDE_DIR}")
set(CMAKE_REQUIRED_LIBRARIES "c") # force linkage by including libc explicitely
CHECK_C_SOURCE_COMPILES("
#include <infiniband/verbs.h>
int main(void)
{
    return 0 != ibv_get_device_list(0);
}" IBVERBS_COMPILES_CHECK)

if (NOT IBVERBS_COMPILES_CHECK)
  message(WARNING "ibverbs driver - no working ibverbs found - ibverbs driver disabled")
  return()
endif()

add_vpp_driver(ibverbs
  SOURCES
  common.c
  flow.c
  format.c
  init.c
  port.c
  queue.c
  rx_node.c
  tx_node.c

  MULTIARCH_SOURCES
  rx_node.c
  tx_node.c

  INCLUDE_DIRECTORIES
  ${IBVERBS_INCLUDE_DIR}

  LINK_FLAGS
  "${IBVERBS_LINK_FLAGS}"

  LINK_LIBRARIES
  ${IBVERBS_LIB}
)
