# Copyright (c) 2018 Cisco and/or its affiliates.
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

if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64.*|AARCH64.*)")
  return()
endif()

find_path(MUSDK_INCLUDE_DIR NAMES mv_std.h)
find_library(MUSDK_LIB NAMES libmusdk.a)

if(MUSDK_INCLUDE_DIR AND MUSDK_LIB)
  get_filename_component(MUSDK_LIB_DIR ${MUSDK_LIB} DIRECTORY)
  set(MUSDK_LINK_FLAGS "-Wl,--whole-archive,${MUSDK_LIB_DIR}/libmusdk.a,--no-whole-archive")
  add_vpp_plugin(marvell
    SOURCES
    plugin.c
    pp2/cli.c
    pp2/format.c
    pp2/input.c
    pp2/output.c
    pp2/pp2.c

    LINK_FLAGS
    ${MUSDK_LINK_FLAGS}
  )
  include_directories(${MUSDK_INCLUDE_DIR})
  message(STATUS "Found Marvel MUSDK in ${MUSDK_INCLUDE_DIR}")
else()
  message(WARNING "Marvell MUSDK not found - marvell_plugin disabled")
endif()
