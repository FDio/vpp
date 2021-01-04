# Copyright (c) 2017 Cisco and/or its affiliates.
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

project(memif)
set(CMAKE_C_STANDARD 11)

include(CheckCCompilerFlag)
include(CheckFunctionExists)

if (NOT CMAKE_BUILD_TYPE)
  message(STATUS "No build type selected, default to Release")
  set(CMAKE_BUILD_TYPE "Release")
endif ()

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -DMEMIF_DBG -DICMP_DBG")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/lib)
set(CMAKE_INSTALL_MESSAGE NEVER)

find_package(Threads REQUIRED)
include_directories(${CMAKE_THREADS_INCLUDE_DIRS})

check_function_exists(memfd_create HAVE_MEMFD_CREATE)
if(${HAVE_MEMFD_CREATE})
  add_definitions(-DHAVE_MEMFD_CREATE)
endif()

include_directories(src)

add_subdirectory(src)
add_subdirectory(examples)

##############################################################################
# Packaging
##############################################################################

# parse /etc/os-release
file(READ "/etc/os-release" os_version)
string(REPLACE "\n" ";" os_version ${os_version})
foreach(_ver ${os_version})
  string(REPLACE "=" ";" _ver ${_ver})
  list(GET _ver 0 _name)
  list(GET _ver 1 _value)
  set(OS_${_name} ${_value})
endforeach()

  # extract version from git
execute_process(
  COMMAND git describe --long --match v*
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE VER
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
string(REGEX REPLACE "v(.*)-([0-9]+)-(g[0-9a-f]+)" "\\1;\\2;\\3" VER ${VER})
list(GET VER 0 tag)
list(GET VER 1 commit_num)
list(GET VER 2 commit_name)

#define DEB and RPM version numbers
if(${commit_num} EQUAL 0)
  set(deb_ver "${tag}")
  set(rpm_ver "${tag}")
else()
  if (DEFINED ENV{BUILD_NUMBER})
    set(deb_ver "${tag}~${commit_num}-${commit_name}~b$ENV{BUILD_NUMBER}")
    set(rpm_ver "${tag}~${commit_num}_${commit_name}~b$ENV{BUILD_NUMBER}")
  else()
    set(deb_ver "${tag}~${commit_num}-${commit_name}")
    set(rpm_ver "${tag}~${commit_num}_${commit_name}")
  endif()
endif()

set(CPACK_PACKAGE_NAME "memif")
set(CPACK_STRIP_FILES OFF)
set(CPACK_PACKAGE_VENDOR "fd.io")
set(CPACK_COMPONENTS_IGNORE_GROUPS 1)
set(CPACK_${CPACK_GENERATOR}_COMPONENT_INSTALL ON)
set(CPACK_${type}_PACKAGE_DESCRIPTION "memif Shared Memory Interface")
set(CPACK_${type}_PACKAGE_RELEASE 1)

if(OS_ID_LIKE MATCHES "debian")
  set(CPACK_GENERATOR "DEB")
  set(type "DEBIAN")
  set(CPACK_PACKAGE_VERSION "${deb_ver}")
  set(CPACK_DEBIAN_PACKAGE_MAINTAINER "VPP Team")
  execute_process(
    COMMAND dpkg --print-architecture
    OUTPUT_VARIABLE CPACK_DEBIAN_PACKAGE_ARCHITECTURE
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  set(CPACK_PACKAGE_FILE_NAME ${CPACK_PACKAGE_NAME}_${CPACK_PACKAGE_VERSION}_${CPACK_DEBIAN_PACKAGE_ARCHITECTURE})
elseif(OS_ID_LIKE MATCHES "rhel")
  set(CPACK_GENERATOR "RPM")
  set(type "RPM")
  set(CPACK_PACKAGE_VERSION "${rpm_ver}")
  execute_process(
    COMMAND uname -m
    OUTPUT_VARIABLE CPACK_RPM_PACKAGE_ARCHITECTURE
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  set(CPACK_PACKAGE_FILE_NAME ${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}.${CPACK_RPM_PACKAGE_ARCHITECTURE})
endif()

if(CPACK_GENERATOR)
  include(CPack)
else()
  message(ERROR "CPACK_GENERATOR must be set")
endif()

