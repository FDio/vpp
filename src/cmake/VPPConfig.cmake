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

get_filename_component(CMAKE_CURRENT_LIST_DIR ${CMAKE_CURRENT_LIST_FILE} PATH)

find_path(VPP_INCLUDE_DIR PATH_SUFFIXES NAMES vppinfra/clib.h)
find_program(VPP_APIGEN vppapigen)
find_program(VPP_VAPI_C_GEN vapi_c_gen.py)
find_program(VPP_VAPI_CPP_GEN vapi_cpp_gen.py)

if(VPP_INCLUDE_DIR AND VPP_APIGEN)
  include_directories (${VPP_INCLUDE_DIR})
  include_directories (${VPP_INCLUDE_DIR}/vpp_plugins)
else()
  message(FATAL_ERROR "VPP headers, libraries and/or tools not found")
endif()

set(VPP_EXTERNAL_PROJECT 1)

include(CheckCCompilerFlag)

check_c_compiler_flag("-Wno-address-of-packed-member" compiler_flag_no_address_of_packed_member)
if (compiler_flag_no_address_of_packed_member)
  add_definitions(-Wno-address-of-packed-member)
endif()

set(VPP_RUNTIME_DIR "bin" CACHE STRING "Relative runtime directory path")
set(VPP_LIBRARY_DIR "lib" CACHE STRING "Relative library directory path")
set(VPP_BINARY_DIR ${CMAKE_BINARY_DIR}/CMakeFiles)

include(${CMAKE_CURRENT_LIST_DIR}/cpu.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/api.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/library.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/plugin.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/pack.cmake)
