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

##############################################################################
# Highlight WARNING and ERROR messages
##############################################################################
function(message)
  list(GET ARGV 0 type)
  string(ASCII 27 esc)
  set(red "${esc}[1;31m")
  set(yellow "${esc}[1;33m")
  set(reset "${esc}[m")
  if(type STREQUAL FATAL_ERROR OR type STREQUAL SEND_ERROR)
    list(REMOVE_AT ARGV 0)
    _message(${type} "${red}${ARGV}${reset}")
  elseif(type STREQUAL WARNING)
    list(REMOVE_AT ARGV 0)
    _message(STATUS "${yellow}${ARGV}${reset}")
  elseif(type STREQUAL STATUS)
    list(REMOVE_AT ARGV 0)
    _message(STATUS "${ARGV}")
  else()
    _message(${ARGV})
  endif()
endfunction()

##############################################################################
# CPU optimizations and multiarch support
##############################################################################
if(CMAKE_SYSTEM_PROCESSOR MATCHES "amd64.*|x86_64.*|AMD64.*")
  set(CMAKE_C_FLAGS "-march=corei7 -mtune=corei7-avx ${CMAKE_C_FLAGS}")
  check_c_compiler_flag("-march=core-avx2" AVX2)
  if(AVX2)
    list(APPEND MARCH_VARIANTS "avx2\;-march=core-avx2 -mtune=core-avx2")
  endif()
  check_c_compiler_flag("-march=skylake-avx512" AVX512)
  if(AVX512)
    list(APPEND MARCH_VARIANTS "avx512\;-march=skylake-avx512 -mtune=skylake-avx512")
  endif()
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64.*|AARCH64.*)")
  set(CMAKE_C_FLAGS "-march=armv8-a+crc ${CMAKE_C_FLAGS}")
endif()

macro(vpp_library_set_multiarch_sources lib)
  foreach(V ${MARCH_VARIANTS})
    list(GET V 0 VARIANT)
    list(GET V 1 VARIANT_FLAGS)
    set(l ${lib}_${VARIANT})
    add_library(${l} OBJECT ${ARGN})
    set_target_properties(${l} PROPERTIES POSITION_INDEPENDENT_CODE ON)
    target_compile_options(${l} PUBLIC "-DCLIB_MARCH_VARIANT=${VARIANT}")
    separate_arguments(VARIANT_FLAGS)
    target_compile_options(${l} PUBLIC ${VARIANT_FLAGS})
    target_sources(${lib} PRIVATE $<TARGET_OBJECTS:${l}>)
  endforeach()
endmacro()

##############################################################################
# build config
##############################################################################
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_C_FLAGS_COMMON "-DFORTIFY_SOURCE=2 -fstack-protector-all -Werror")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${CMAKE_C_FLAGS_COMMON} -DCLIB_DEBUG")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} ${CMAKE_C_FLAGS_COMMON}")

##############################################################################
# ccache
##############################################################################
option(VPP_USE_CCACHE "Use ccache compiler cache." ON)
if(VPP_USE_CCACHE)
  find_program(CCACHE_FOUND ccache)
  message(STATUS "Looking for ccache")
  if(CCACHE_FOUND)
    message(STATUS "Looking for ccache - found")
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
  else(CCACHE_FOUND)
    message(STATUS "Looking for ccache - not found")
  endif(CCACHE_FOUND)
endif(VPP_USE_CCACHE)

##############################################################################
# install config
##############################################################################
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
set(CMAKE_INSTALL_MESSAGE NEVER)

message(STATUS "CMAKE_C_FLAGS: ${CMAKE_C_FLAGS}")
message(STATUS "We are on a ${CMAKE_SYSTEM_NAME} system")
message(STATUS "The host processor is ${CMAKE_HOST_SYSTEM_PROCESSOR}")

include_directories (
	${CMAKE_SOURCE_DIR}
	${CMAKE_BINARY_DIR}
	${CMAKE_BINARY_DIR}/include
)
set(CMAKE_INSTALL_DEFAULT_COMPONENT_NAME "vpp")

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

##############################################################################
# Check for memfd_create headers and libs
##############################################################################
check_c_source_compiles("
  #define _GNU_SOURCE
  #include <sys/mman.h>
  int main() { return memfd_create (\"/dev/false\", 0); }
" HAVE_MEMFD_CREATE)

if (HAVE_MEMFD_CREATE)
    add_definitions(-DHAVE_MEMFD_CREATE)
endif()

##############################################################################
# API
##############################################################################
function(vpp_generate_api_c_header file)
  set (output_name ${CMAKE_CURRENT_BINARY_DIR}/${file}.h)
  get_filename_component(output_dir ${output_name} DIRECTORY)
  add_custom_command (OUTPUT ${output_name}
    COMMAND mkdir -p ${output_dir}
    COMMAND ${CMAKE_SOURCE_DIR}/tools/vppapigen/vppapigen
    ARGS --includedir ${CMAKE_SOURCE_DIR} --input ${CMAKE_CURRENT_SOURCE_DIR}/${file} --output ${output_name}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${file}
    COMMENT "Generating API header ${output_name}"
  )
endfunction()

function(vpp_generate_api_json_header file dir)
  set (output_name ${CMAKE_CURRENT_BINARY_DIR}/${file}.json)
  get_filename_component(output_dir ${output_name} DIRECTORY)
  add_custom_command (OUTPUT ${output_name}
    COMMAND mkdir -p ${output_dir}
    COMMAND ${CMAKE_SOURCE_DIR}/tools/vppapigen/vppapigen
    ARGS --includedir ${CMAKE_SOURCE_DIR} --input ${CMAKE_CURRENT_SOURCE_DIR}/${file} JSON --output ${output_name}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${file}
    COMMENT "Generating API header ${output_name}"
  )
  install(FILES ${output_name} DESTINATION share/vpp/api/${dir}/)
endfunction()

##############################################################################
# generate the .h and .json files for a .api file
#  @param file - the name of the .api
#  @param dir  - the install directory under ROOT/share/vpp/api to place the
#                generated .json file
##############################################################################
function(vpp_generate_api_header file dir)
    vpp_generate_api_c_header (${file})
    vpp_generate_api_json_header (${file} ${dir})
endfunction()

function(vpp_add_api_files target)
  unset(header_files)
  foreach(file ${ARGN})
    vpp_generate_api_header (${file} core)
    list (APPEND header_files ${file}.h ${file}.json)
  endforeach()
  add_custom_target(${target} DEPENDS ${header_files})
endfunction()

add_custom_target(api_headers
  DEPENDS vlibmemory_api_headers vnet_api_headers vpp_api_headers
)

##############################################################################
# header files
##############################################################################
function (vpp_add_header_files path)
  foreach(file ${ARGN})
    get_filename_component(dir ${file} DIRECTORY)
    install(FILES ${file} DESTINATION include/${path}/${dir})
  endforeach()
endfunction()

##############################################################################
# subdirs
##############################################################################
foreach (DIR vppinfra svm vlib vlibmemory vnet vpp vpp-api vat vcl plugins)
  add_subdirectory(${DIR})
endforeach ()

##############################################################################
# DEB Packaging
##############################################################################
set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "VPP Team")
set(CPACK_PACKAGE_NAME "vpp")
set(CPACK_PACKAGE_VENDOR "fd.io")
set(CPACK_PACKAGE_VERSION "18.08")
set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_COMPONENTS_IGNORE_GROUPS 1)
set(CPACK_DEBIAN_VPP_PACKAGE_NAME "vpp")
set(CPACK_DEBIAN_VPP_FILE_NAME "vpp.deb")
set(CPACK_DEBIAN_DEV_PACKAGE_NAME "vpp-dev")
set(CPACK_DEBIAN_DEV_FILE_NAME "vpp-dev.deb")
set(CPACK_DEBIAN_PLUGINS_PACKAGE_NAME "vpp-plugins")
set(CPACK_DEBIAN_PLUGINS_FILE_NAME "vpp-plugins.deb")
include(CPack)
