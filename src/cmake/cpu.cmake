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

macro(set_log2_cacheline_size var n)
  if(${n} EQUAL 128)
    set(${var} 7)
  elseif(${n} EQUAL 64)
    set(${var} 6)
  else()
     message(FATAL_ERROR "Cacheline size ${n} not supported")
  endif()
endmacro()

##############################################################################
# Cache line size
##############################################################################
if(DEFINED VPP_CACHE_LINE_SIZE)
  # Cache line size assigned via cmake args
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64.*|AARCH64.*)")
  set(VPP_CACHE_LINE_SIZE 128)
else()
  set(VPP_CACHE_LINE_SIZE 64)
endif()

set(VPP_CACHE_LINE_SIZE ${VPP_CACHE_LINE_SIZE}
    CACHE STRING "Target CPU cache line size")

set_log2_cacheline_size(VPP_LOG2_CACHE_LINE_SIZE ${VPP_CACHE_LINE_SIZE})

##############################################################################
# Gnu Assembler AVX-512 bug detection
# - see: https://sourceware.org/bugzilla/show_bug.cgi?id=23465
##############################################################################
if(CMAKE_SYSTEM_PROCESSOR MATCHES "amd64.*|x86_64.*|AMD64.*")
  if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
    set(pfx ${CMAKE_CURRENT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/gas_avx512_bug_test)
    file(WRITE ${pfx}.s "vmovaps 0x40(,%rax), %zmm0\n")
    execute_process(COMMAND ${CMAKE_C_COMPILER} -c ${pfx}.s -o ${pfx}.o)
    execute_process(COMMAND objdump -s ${pfx}.o OUTPUT_VARIABLE _output)
    if (NOT _output MATCHES "62f17c48 28040540 000000")
      set(GNU_ASSEMBLER_AVX512_BUG 1)
    endif()
  endif()
endif()

##############################################################################
# CPU optimizations and multiarch support
##############################################################################
macro(add_vpp_march_variant v)
  cmake_parse_arguments(ARG
    "OFF"
    "N_PREFETCHES;CACHE_PREFETCH_BYTES"
    "FLAGS"
    ${ARGN}
  )

  if(ARG_FLAGS)
    set(flags_ok 1)
    set(fs "")
    foreach(f ${ARG_FLAGS})
      string(APPEND fs " ${f}")
      string(REGEX REPLACE "[-=+]" "_" sfx ${f})
      if(NOT DEFINED compiler_flag${sfx})
        check_c_compiler_flag(${f} compiler_flag${sfx})
      endif()
      if(NOT compiler_flag${sfx})
        unset(flags_ok)
      endif()
    endforeach()
    if(ARG_N_PREFETCHES)
      string(APPEND fs " -DCLIB_N_PREFETCHES=${ARG_N_PREFETCHES}")
    endif()
    if(ARG_CACHE_PREFETCH_BYTES)
      set_log2_cacheline_size(log2 ${ARG_CACHE_PREFETCH_BYTES})
      string(APPEND fs " -DCLIB_LOG2_CACHE_PREFETCH_BYTES=${log2}")
    endif()
    if(flags_ok)
      string(TOUPPER ${v} uv)
      if(ARG_OFF)
        option(VPP_MARCH_VARIANT_${uv} "Build ${v} multiarch variant." OFF)
      else()
        option(VPP_MARCH_VARIANT_${uv} "Build ${v} multiarch variant." ON)
      endif()
      if (VPP_MARCH_VARIANT_${uv})
        list(APPEND MARCH_VARIANTS "${v}\;${fs}")
      else()
        list(APPEND MARCH_VARIANTS_DISABLED "${v}\;${fs}")
      endif()
    endif()
  endif()
endmacro()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "amd64.*|x86_64.*|AMD64.*")
  set(VPP_DEFAULT_MARCH_FLAGS -march=corei7 -mtune=corei7-avx)

  add_vpp_march_variant(hsw
    FLAGS -march=haswell -mtune=haswell
  )

  add_vpp_march_variant(trm
    FLAGS -march=tremont -mtune=tremont
    OFF
  )

  if (GNU_ASSEMBLER_AVX512_BUG)
     message(WARNING "AVX-512 multiarch variant(s) disabled due to GNU Assembler bug")
  else()
    add_vpp_march_variant(skx
      FLAGS -march=skylake-avx512 -mtune=skylake-avx512 -mprefer-vector-width=256
    )

    add_vpp_march_variant(icl
      FLAGS -march=icelake-client -mtune=icelake-client -mprefer-vector-width=512
    )
  endif()
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64.*|AARCH64.*)")
  set(VPP_DEFAULT_MARCH_FLAGS -march=armv8-a+crc)

  add_vpp_march_variant(qdf24xx
    FLAGS -march=armv8-a+crc+crypto -mtune=qdf24xx
    N_PREFETCHES 8
    CACHE_PREFETCH_BYTES 64
    OFF
  )

  add_vpp_march_variant(octeontx2
    FLAGS -march=armv8.2-a+crc+crypto+lse
    N_PREFETCHES 8
  )

  add_vpp_march_variant(thunderx2t99
    FLAGS -march=armv8.1-a+crc+crypto -mtune=thunderx2t99
    N_PREFETCHES 8
    CACHE_PREFETCH_BYTES 64
  )

  add_vpp_march_variant(cortexa72
    FLAGS -march=armv8-a+crc+crypto -mtune=cortex-a72
    N_PREFETCHES 6
    CACHE_PREFETCH_BYTES 64
  )

  add_vpp_march_variant(neoversen1
    FLAGS -march=armv8.2-a+crc+crypto -mtune=neoverse-n1
    N_PREFETCHES 6
    CACHE_PREFETCH_BYTES 64
  )

  add_vpp_march_variant(neoversen2
    FLAGS -march=armv8.5-a+crc+crypto+sve -mtune=neoverse-n2
    N_PREFETCHES 12
    CACHE_PREFETCH_BYTES 64
  )
endif()

macro(vpp_library_set_multiarch_sources lib)
  cmake_parse_arguments(ARG
    ""
    ""
    "SOURCES;DEPENDS;FORCE_ON"
    ${ARGN}
  )

  set(VARIANTS "${MARCH_VARIANTS}")

  if(ARG_FORCE_ON)
    foreach(F ${ARG_FORCE_ON})
      foreach(V ${MARCH_VARIANTS_DISABLED})
        list(GET V 0 VARIANT)
	if (VARIANT STREQUAL F)
          list(GET V 1 VARIANT_FLAGS)
          list(APPEND VARIANTS "${VARIANT}\;${VARIANT_FLAGS}")
	endif()
      endforeach()
    endforeach()
  endif()

  foreach(V ${VARIANTS})
    list(GET V 0 VARIANT)
    list(GET V 1 VARIANT_FLAGS)
    set(l ${lib}_${VARIANT})
    add_library(${l} OBJECT ${ARG_SOURCES})
    if(ARG_DEPENDS)
      add_dependencies(${l} ${ARG_DEPENDS})
    endif()
    set_target_properties(${l} PROPERTIES POSITION_INDEPENDENT_CODE ON)
    target_compile_definitions(${l} PUBLIC CLIB_MARCH_VARIANT=${VARIANT})
    separate_arguments(VARIANT_FLAGS)
    target_compile_options(${l} PUBLIC ${VARIANT_FLAGS})
    target_sources(${lib} PRIVATE $<TARGET_OBJECTS:${l}>)
  endforeach()
endmacro()

