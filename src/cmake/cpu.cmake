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

##############################################################################
# CPU optimizations and multiarch support
##############################################################################
if(CMAKE_SYSTEM_PROCESSOR MATCHES "amd64.*|x86_64.*|AMD64.*")
  set(CMAKE_C_FLAGS "-march=corei7 -mtune=corei7-avx ${CMAKE_C_FLAGS}")
  set(VPP_LIB_DIR_NAME lib64)
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
  set(VPP_LIB_DIR_NAME lib64)
else()
  set(VPP_LIB_DIR_NAME lib)
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

