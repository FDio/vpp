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
include(cmake/misc.cmake)
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
# cross compiling
##############################################################################
if(CMAKE_CROSSCOMPILING)
  set(CMAKE_IGNORE_PATH
    /usr/lib/${CMAKE_HOST_SYSTEM_PROCESSOR}-linux-gnu/
    /usr/lib/${CMAKE_HOST_SYSTEM_PROCESSOR}-linux-gnu/lib/
  )
endif()
set(CMAKE_C_COMPILER_TARGET ${CMAKE_SYSTEM_PROCESSOR}-linux-gnu)

##############################################################################
# build config
##############################################################################
check_c_compiler_flag("-Wno-address-of-packed-member"
		      compiler_flag_no_address_of_packed_member)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

if (CMAKE_BUILD_TYPE)
  set(CMAKE_C_FLAGS "-g -fPIC ${CMAKE_C_FLAGS}")
  set(CMAKE_C_FLAGS "-fstack-protector-all ${CMAKE_C_FLAGS}")
  set(CMAKE_C_FLAGS "-Werror ${CMAKE_C_FLAGS}")
  set(CMAKE_C_FLAGS "-DFORTIFY_SOURCE=2 ${CMAKE_C_FLAGS}")
endif()

if (compiler_flag_no_address_of_packed_member)
  set(CMAKE_C_FLAGS "-Wno-address-of-packed-member ${CMAKE_C_FLAGS}")
endif()

set(CMAKE_C_FLAGS_RELEASE "-O2 ${CMAKE_C_FLAGS_RELEASE}")
set(CMAKE_C_FLAGS_DEBUG "-O0 -DCLIB_DEBUG ${CMAKE_C_FLAGS_DEBUG}")
set(CMAKE_LINKER_FLAGS_RELEASE "-pie -Wl,-z,now ${CMAKE_LINKER_FLAGS_RELEASE}")
string(TOUPPER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_UC)

##############################################################################
# install config
##############################################################################
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
set(CMAKE_INSTALL_MESSAGE NEVER)

include_directories (
	${CMAKE_SOURCE_DIR}
	${CMAKE_BINARY_DIR}
	${CMAKE_BINARY_DIR}/include
)
set(CMAKE_INSTALL_DEFAULT_COMPONENT_NAME "vpp")

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

include(cmake/syscall.cmake)
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
    vpp-api tools/vppapigen tools/g2 tools/elftool tools/perftool cmake pkg
    tools/appimage
  )
elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")
  set(SUBDIRS vppinfra)
else()
  message(FATAL_ERROR "Unsupported system: ${CMAKE_SYSTEM_NAME}")
endif()

foreach(DIR ${SUBDIRS})
  add_subdirectory(${DIR})
endforeach()

##############################################################################
# detect if we are inside git repo and add configure dependency
##############################################################################
execute_process(
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND git rev-parse --show-toplevel
  OUTPUT_VARIABLE VPP_GIT_TOPLEVEL_DIR
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET
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
pr("Build type" "${CMAKE_BUILD_TYPE}")
pr("C flags" "${CMAKE_C_FLAGS}${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UC}}")
pr("Linker flags" "${CMAKE_LINKER_FLAGS}${CMAKE_LINKER_FLAGS_${CMAKE_BUILD_TYPE_UC}}")
pr("Host processor" "${CMAKE_HOST_SYSTEM_PROCESSOR}")
pr("Target processor" "${CMAKE_SYSTEM_PROCESSOR}")
pr("Prefix path" "${CMAKE_PREFIX_PATH}")
pr("Install prefix" "${CMAKE_INSTALL_PREFIX}")
