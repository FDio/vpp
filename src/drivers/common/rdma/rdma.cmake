# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Damjan Marion

# Shared by the ibverbs and mlx5 drivers. Expanded in the caller's
# scope, so return() leaves the calling driver's CMakeLists.txt.
macro(rdma_driver_prereqs name)
  vpp_find_path(IBVERBS_INCLUDE_DIR NAMES infiniband/verbs.h)

  if (NOT IBVERBS_INCLUDE_DIR)
    message(WARNING "-- rdma headers not found - ${name} driver disabled")
    return()
  endif()

  vpp_driver_find_library(${name} IBVERBS_LIB libibverbs.a)
  vpp_driver_find_library(${name} MLX4_LIB libmlx4.a)
  vpp_driver_find_library(${name} MLX5_LIB libmlx5.a)

  if (NOT IBVERBS_LIB OR NOT MLX4_LIB OR NOT MLX5_LIB)
    message(WARNING "${name} driver - ibverbs/mlx4/mlx5 not found - ${name} driver disabled")
    return()
  endif()

  string_append(RDMA_LINK_FLAGS "-Wl,--whole-archive,${MLX4_LIB},${MLX5_LIB},--no-whole-archive -Wl,--exclude-libs,ALL")

  set(CMAKE_REQUIRED_FLAGS "-fPIC -shared -pthread -Wno-unused-command-line-argument ${RDMA_LINK_FLAGS} ${IBVERBS_LIB}")
  set(CMAKE_REQUIRED_INCLUDES "${IBVERBS_INCLUDE_DIR}")
  set(CMAKE_REQUIRED_LIBRARIES "c")
  CHECK_C_SOURCE_COMPILES("
#include <infiniband/verbs.h>
int main(void)
{
    return 0 != ibv_get_device_list(0);
}" IBVERBS_COMPILES_CHECK)

  unset(CMAKE_REQUIRED_FLAGS)
  unset(CMAKE_REQUIRED_INCLUDES)
  unset(CMAKE_REQUIRED_LIBRARIES)

  if (NOT IBVERBS_COMPILES_CHECK)
    message(WARNING "${name} driver - no working ibverbs found - ${name} driver disabled")
    return()
  endif()

  set(RDMA_COMMON_DIR ${CMAKE_CURRENT_LIST_DIR}/../../common/rdma)
  set(RDMA_COMMON_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/../../common)
  set(RDMA_COMMON_SOURCES
    ${RDMA_COMMON_DIR}/flow.c
    ${RDMA_COMMON_DIR}/format.c
    ${RDMA_COMMON_DIR}/port.c
    ${RDMA_COMMON_DIR}/queue.c
    ${RDMA_COMMON_DIR}/rss.c
  )
endmacro()
