# Copyright (c) 2018 Intel and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

message(STATUS "Looking for Hyperscan")
find_path(HYPERSCAN_INCLUDE_DIR NAMES hs/hs.h)
find_library(HYPERSCAN_LIB1 NAMES hs)
find_library(HYPERSCAN_LIB2 NAMES hs_runtime)
set (HYPERSCAN_LIB ${HYPERSCAN_LIB1} ${HYPERSCAN_LIB2})

if(HYPERSCAN_INCLUDE_DIR AND HYPERSCAN_LIB)
  include_directories(${HYPERSCAN_INCLUDE_DIR})
  add_vpp_plugin(dpi
    SOURCES
    dpi.api
    dpi.c
    dpi_api.c
    dpi_cli.c
    dpi_node.c
    protocols/dpi_ssl.c

    API_FILES
    dpi.api

    INSTALL_HEADERS
    dpi.h

    LINK_LIBRARIES
    ${HYPERSCAN_LIB}
  )
  message(STATUS "Found Hyperscan in ${HYPERSCAN_INCLUDE_DIR}")
else()
  message(WARNING "-- Hyperscan not found - dpi_plugin disabled")
endif()

