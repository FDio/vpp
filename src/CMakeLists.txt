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

cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(vpp C)

include(CheckCCompilerFlag)
include(cmake/message.cmake)
include(cmake/cpu.cmake)
include(cmake/ccache.cmake)

##############################################################################
# VPP Version
##############################################################################
execute_process(
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND scripts/version
  OUTPUT_VARIABLE VPP_VERSION
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
string(REPLACE "-" ";" VPP_LIB_VERSION ${VPP_VERSION})
list(GET VPP_LIB_VERSION 0 VPP_LIB_VERSION)

##############################################################################
# build config
##############################################################################
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_C_FLAGS_COMMON "-DFORTIFY_SOURCE=2 -fstack-protector-all -Werror")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${CMAKE_C_FLAGS_COMMON} -DCLIB_DEBUG")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} ${CMAKE_C_FLAGS_COMMON}")

check_c_compiler_flag("-Wno-address-of-packed-member" compiler_flag_no_address_of_packed_member)
if (compiler_flag_no_address_of_packed_member)
  add_definitions(-Wno-address-of-packed-member)
endif()

##############################################################################
# install config
##############################################################################
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${VPP_LIB_DIR_NAME}")
set(CMAKE_INSTALL_MESSAGE NEVER)

include_directories (
	${CMAKE_SOURCE_DIR}
	${CMAKE_BINARY_DIR}
	${CMAKE_BINARY_DIR}/include
)
set(CMAKE_INSTALL_DEFAULT_COMPONENT_NAME "vpp")

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

include(cmake/memfd.cmake)
include(cmake/api.cmake)
include(cmake/library.cmake)
include(cmake/exec.cmake)
include(cmake/plugin.cmake)

##############################################################################
# subdirs - order matters
##############################################################################
if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
  find_package(OpenSSL REQUIRED)
  set(SUBDIRS
    vppinfra svm vlib vlibmemory vlibapi vnet vpp vat vcl plugins
    vpp-api tools/vppapigen tools/g2 tools/elftool tools/perftool)
elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")
  set(SUBDIRS vppinfra)
else()
  message(FATAL_ERROR "Unsupported system: ${CMAKE_SYSTEM_NAME}")
endif()

foreach(DIR ${SUBDIRS})
  add_subdirectory(${DIR})
endforeach()

include(cmake/pack.cmake)
##############################################################################
# detect if we are inside git repo and add configure dependency
##############################################################################
execute_process(
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND git rev-parse --show-toplevel
  OUTPUT_VARIABLE VPP_GIT_TOPLEVEL_DIR
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

if (VPP_GIT_TOPLEVEL_DIR)
  set_property(
    DIRECTORY APPEND PROPERTY
    CMAKE_CONFIGURE_DEPENDS ${VPP_GIT_TOPLEVEL_DIR}/.git/index
  )
endif()

##############################################################################
# print configuration
##############################################################################
message(STATUS "Configuration:")
pr("VPP version" "${VPP_VERSION}")
pr("VPP library version" "${VPP_LIB_VERSION}")
pr("GIT toplevel dir" "${VPP_GIT_TOPLEVEL_DIR}")
pr("C flags" "${CMAKE_C_FLAGS}")
pr("Linker flags" "${CMAKE_LINKER_FLAGS}")
pr("Target processor" "${CMAKE_SYSTEM_PROCESSOR}")
pr("Build type" "${CMAKE_BUILD_TYPE}")
pr("Install prefix" "${CMAKE_INSTALL_PREFIX}")

