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
# Cache line size detection
##############################################################################
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64.*|AARCH64.*)")
  file(READ "/proc/cpuinfo" cpuinfo)
  string(REPLACE "\n" ";" cpuinfo ${cpuinfo})
  foreach(l ${cpuinfo})
    string(REPLACE ":" ";" l ${l})
    list(GET l 0 name)
    list(GET l 1 value)
    string(STRIP ${name} name)
    string(STRIP ${value} value)
    if(${name} STREQUAL "CPU implementer")
      set(CPU_IMPLEMENTER ${value})
    endif()
    if(${name} STREQUAL "CPU part")
      set(CPU_PART ${value})
    endif()
  endforeach()
  # Implementer 0x43 - Cavium
  #  Part 0x0af - ThunderX2 is 64B, rest all are 128B
  if (${CPU_IMPLEMENTER} STREQUAL "0x43")
    if (${CPU_PART} STREQUAL "0x0af")
      set(VPP_LOG2_CACHE_LINE_SIZE 6)
    else()
      set(VPP_LOG2_CACHE_LINE_SIZE 7)
    endif()
  else()
      set(VPP_LOG2_CACHE_LINE_SIZE 6)
  endif()
  math(EXPR VPP_CACHE_LINE_SIZE "1 << ${VPP_LOG2_CACHE_LINE_SIZE}")
  message(STATUS "ARM AArch64 CPU implementer ${CPU_IMPLEMENTER} part ${CPU_PART} cacheline size ${VPP_CACHE_LINE_SIZE}")
else()
  set(VPP_LOG2_CACHE_LINE_SIZE 6)
endif()

set(VPP_LOG2_CACHE_LINE_SIZE ${VPP_LOG2_CACHE_LINE_SIZE}
    CACHE STRING "Target CPU cache line size (power of 2)")

##############################################################################
# CPU optimizations and multiarch support
##############################################################################
if(CMAKE_SYSTEM_PROCESSOR MATCHES "amd64.*|x86_64.*|AMD64.*")
  set(CMAKE_C_FLAGS "-march=core-avx2  -mtune=core-avx2 ${CMAKE_C_FLAGS}")
  check_c_compiler_flag("-march=core-avx2" compiler_flag_march_core_avx2)
  if(compiler_flag_march_core_avx2)
    list(APPEND MARCH_VARIANTS "avx2\;-march=core-avx2 -mtune=core-avx2")
  endif()
  check_c_compiler_flag("-march=skylake-avx512" compiler_flag_march_skylake_avx512)
  if(compiler_flag_march_skylake_avx512)
    list(APPEND MARCH_VARIANTS "avx512\;-march=skylake-avx512 -mtune=skylake-avx512")
  endif()
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64.*|AARCH64.*)")
  set(CMAKE_C_FLAGS "-march=armv8-a+crc ${CMAKE_C_FLAGS}")
  check_c_compiler_flag("-march=armv8-a+crc+crypto -mtune=qdf24xx" compiler_flag_march_core_qdf24xx)
  if(compiler_flag_march_core_qdf24xx)
    list(APPEND MARCH_VARIANTS "qdf24xx\;-march=armv8-a+crc+crypto -DCLIB_N_PREFETCHES=8")
  endif()
  check_c_compiler_flag("-march=armv8.1-a+crc+crypto -mtune=thunderx2t99" compiler_flag_march_thunderx2t99)
  if(compiler_flag_march_thunderx2t99)
    if (CMAKE_C_COMPILER_VERSION VERSION_GREATER 7.3)
      list(APPEND MARCH_VARIANTS "thunderx2t99\;-march=armv8.1-a+crc+crypto -mtune=thunderx2t99 -DCLIB_N_PREFETCHES=8")
    else()
      list(APPEND MARCH_VARIANTS "thunderx2t99\;-march=armv8.1-a+crc+crypto -DCLIB_N_PREFETCHES=8")
    endif()
  endif()
  check_c_compiler_flag("-march=armv8-a+crc+crypto -mtune=cortex-a72" compiler_flag_march_cortexa72)
  if(compiler_flag_march_cortexa72)
    list(APPEND MARCH_VARIANTS "cortexa72\;-march=armv8-a+crc+crypto -mtune=cortex-a72 -DCLIB_N_PREFETCHES=6")
  endif()
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

