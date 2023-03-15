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

cmake_minimum_required(VERSION 3.13)

set(CMAKE_C_COMPILER_NAMES clang gcc cc)

project(vpp C)

if(NOT DEFINED CMAKE_INSTALL_LIBDIR AND EXISTS "/etc/debian_version")
  set(CMAKE_INSTALL_LIBDIR "lib/${CMAKE_LIBRARY_ARCHITECTURE}")
endif()

include(CheckCCompilerFlag)
include(CheckIPOSupported)
include(GNUInstallDirs)
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
# compiler specifics
##############################################################################

set(MIN_SUPPORTED_CLANG_C_COMPILER_VERSION 9.0.0)
set(MIN_SUPPORTED_GNU_C_COMPILER_VERSION 9.0.0)

if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
  if (CMAKE_C_COMPILER_VERSION VERSION_LESS MIN_SUPPORTED_CLANG_C_COMPILER_VERSION)
    set(COMPILER_TOO_OLD TRUE)
  endif()
elseif(CMAKE_C_COMPILER_ID STREQUAL "GNU")
  if (CMAKE_C_COMPILER_VERSION VERSION_LESS MIN_SUPPORTED_GNU_C_COMPILER_VERSION)
    set(COMPILER_TOO_OLD TRUE)
  endif()
  set(GCC_STRING_OVERFLOW_WARNING_DISABLE_VERSION 10.0.0)
  if (CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL GCC_STRING_OVERFLOW_WARNING_DISABLE_VERSION)
    add_compile_options(-Wno-stringop-overflow)
  endif()
else()
  message(WARNING "WARNING: Unsupported C compiler `${CMAKE_C_COMPILER_ID}` is used")
  set (PRINT_MIN_C_COMPILER_VER TRUE)
endif()
if (COMPILER_TOO_OLD)
  message(WARNING "WARNING: C compiler version is too old and it's usage may result")
  message(WARNING "         in sub-optimal binaries or lack of support for specific CPU types.")
  set (PRINT_MIN_C_COMPILER_VER TRUE)
endif()

if (PRINT_MIN_C_COMPILER_VER)
  string (APPEND _t "Supported C compilers are ")
  string (APPEND _t "Clang ${MIN_SUPPORTED_CLANG_C_COMPILER_VERSION} or higher ")
  string (APPEND _t "and GNU ${MIN_SUPPORTED_GNU_C_COMPILER_VERSION} or higher.")
  message(WARNING "         ${_t}")
  unset (_t)
endif()

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
set(VPP_RUNTIME_DIR ${CMAKE_INSTALL_BINDIR} CACHE STRING "Relative runtime directory path")
set(VPP_LIBRARY_DIR ${CMAKE_INSTALL_LIBDIR} CACHE STRING "Relative library directory path")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${VPP_RUNTIME_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${VPP_LIBRARY_DIR})
set(VPP_BINARY_DIR ${CMAKE_BINARY_DIR}/CMakeFiles)
set(PYENV PYTHONPYCACHEPREFIX=${CMAKE_BINARY_DIR}/CMakeFiles/__pycache__)

if (CMAKE_BUILD_TYPE)
  add_compile_options(-g -Werror -Wall)
  add_link_options(-Wl,-z,relro,-z,now)
endif()

if (compiler_flag_no_address_of_packed_member)
  add_compile_options(-Wno-address-of-packed-member)
endif()

string(TOLOWER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_LC)
string(TOUPPER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_UC)

set(CMAKE_C_FLAGS_RELEASE "")
set(CMAKE_C_FLAGS_DEBUG "")

if (${CMAKE_BUILD_TYPE_LC} MATCHES "release")
  add_compile_options(-O3 -fstack-protector -fno-common)
  add_compile_definitions(_FORTIFY_SOURCE=2)
elseif (${CMAKE_BUILD_TYPE_LC} MATCHES "debug")
  add_compile_options(-O0 -fstack-protector -fno-common)
  add_compile_definitions(CLIB_DEBUG)
elseif (${CMAKE_BUILD_TYPE_LC} MATCHES "coverity")
  add_compile_options(-O0)
  add_compile_definitions(__COVERITY__)
elseif (${CMAKE_BUILD_TYPE_LC} MATCHES "gcov")
  add_compile_options(-O0 -fprofile-arcs -ftest-coverage)
  add_compile_definitions(CLIB_DEBUG CLIB_GCOV)
endif()

set(BUILD_TYPES release debug coverity gcov)
string(REPLACE ";" " " BUILD_TYPES_STR "${BUILD_TYPES}")
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY
	     HELPSTRING "Build type - valid options are: ${BUILD_TYPES_STR}")

##############################################################################
# link time optimizations
##############################################################################
if (CMAKE_BUILD_TYPE_UC STREQUAL "RELEASE")
  check_ipo_supported(RESULT _result)
  if (_result)
    option(VPP_USE_LTO "Link time optimization of release binaries" ON)
  endif()
endif()

if(VPP_USE_LTO)
  check_c_compiler_flag("-Wno-stringop-overflow"
		        compiler_flag_no_stringop_overflow)
endif()
##############################################################################
# sanitizers
##############################################################################

option(VPP_ENABLE_SANITIZE_ADDR "Enable Address Sanitizer" OFF)
set(VPP_SANITIZE_ADDR_OPTIONS
  "unmap_shadow_on_exit=1:disable_coredump=0:abort_on_error=1:detect_leaks=0"
  CACHE
  STRING "Address sanitizer arguments"
)

if (VPP_ENABLE_SANITIZE_ADDR)
  add_compile_options(-fsanitize=address)
  add_link_options(-fsanitize=address)
endif (VPP_ENABLE_SANITIZE_ADDR)

##############################################################################
# trajectory trace
##############################################################################

option(VPP_ENABLE_TRAJECTORY_TRACE "Build vpp with trajectory tracing enabled" OFF)
if(VPP_ENABLE_TRAJECTORY_TRACE)
  add_compile_definitions(VLIB_BUFFER_TRACE_TRAJECTORY=1)
endif()

##############################################################################
# unittest with clang ode coverage
##############################################################################

if("${CMAKE_VERSION}" VERSION_GREATER_EQUAL "3.13" AND "${CMAKE_C_COMPILER_ID}" MATCHES "(Apple)?[Cc]lang")
  option(VPP_BUILD_TESTS_WITH_COVERAGE "Build unit tests with code coverage" OFF)
endif()

##############################################################################
# install config
##############################################################################
option(VPP_SET_RPATH "Set rpath for resulting binaries and libraries." ON)
if(VPP_SET_RPATH)
  set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${VPP_LIBRARY_DIR}")
endif()
set(CMAKE_INSTALL_MESSAGE NEVER)

include_directories (
	${CMAKE_SOURCE_DIR}
	${VPP_BINARY_DIR}
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
option(VPP_HOST_TOOLS_ONLY "Build only host tools" OFF)
if(VPP_HOST_TOOLS_ONLY)
  set(SUBDIRS tools/vppapigen cmake)
elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
  find_package(OpenSSL)
  set(SUBDIRS
    vppinfra svm vlib vlibmemory vlibapi vnet vpp vat vat2 vcl vpp-api
    plugins tools/vppapigen tools/g2 tools/perftool cmake pkg
    tools/appimage
  )
elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")
  set(SUBDIRS vppinfra)
else()
  message(FATAL_ERROR "Unsupported system: ${CMAKE_SYSTEM_NAME}")
endif()

foreach(DIR ${SUBDIRS})
  add_subdirectory(${DIR} ${VPP_BINARY_DIR}/${DIR})
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
# custom targets
##############################################################################

add_custom_target(run
  COMMAND ./${VPP_RUNTIME_DIR}/vpp -c startup.conf
  COMMENT "Starting VPP..."
  USES_TERMINAL
)

add_custom_target(debug
  COMMAND gdb --args ./${VPP_RUNTIME_DIR}/vpp -c startup.conf
  COMMENT "Starting VPP in the debugger..."
  USES_TERMINAL
)

add_custom_target(config
  COMMAND ccmake ${CMAKE_BINARY_DIR}
  COMMENT "Starting Configuration TUI..."
  USES_TERMINAL
)

foreach(bt ${BUILD_TYPES})
  add_custom_target(set-build-type-${bt}
    COMMAND cmake -DCMAKE_BUILD_TYPE:STRING=${bt} .
    COMMENT "Changing build type to ${bt}"
    USES_TERMINAL
  )
endforeach()

mark_as_advanced(CLEAR
  CMAKE_C_FLAGS
  CMAKE_C_COMPILER
  CMAKE_EXPORT_COMPILE_COMMANDS
  CMAKE_INSTALL_PREFIX
  CMAKE_LINKER
  CMAKE_SHARED_LINKER_FLAGS
  CMAKE_VERBOSE_MAKEFILE
)

##############################################################################
# print configuration
##############################################################################
message(STATUS "Configuration:")
pr("VPP version" ${VPP_VERSION})
pr("VPP library version" ${VPP_LIB_VERSION})
pr("GIT toplevel dir" ${VPP_GIT_TOPLEVEL_DIR})
pr("Build type" ${CMAKE_BUILD_TYPE})
pr("C compiler" "${CMAKE_C_COMPILER} (${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION})")
pr("C flags" ${CMAKE_C_FLAGS}${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UC}})
pr("Linker flags (apps)" ${CMAKE_EXE_LINKER_FLAGS} ${CMAKE_EXE_LINKER_FLAGS_${CMAKE_BUILD_TYPE_UC}})
pr("Linker flags (libs)" ${CMAKE_SHARED_LINKER_FLAGS} ${CMAKE_SHARED_LINKER_FLAGS_${CMAKE_BUILD_TYPE_UC}})
pr("Host processor" ${CMAKE_HOST_SYSTEM_PROCESSOR})
pr("Target processor" ${CMAKE_SYSTEM_PROCESSOR})
pr("Prefix path" ${CMAKE_PREFIX_PATH})
pr("Install prefix" ${CMAKE_INSTALL_PREFIX})
pr("Library dir" ${VPP_LIBRARY_DIR})
pr("Multiarch variants" ${MARCH_VARIANTS_NAMES})
