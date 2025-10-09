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

enable_language(ASM)

##############################################################################
# find libdl
##############################################################################
list(APPEND VPPINFRA_LIBS ${CMAKE_DL_LIBS})

##############################################################################
# find libunwind
##############################################################################
vpp_find_path(LIBUNWIND_INCLUDE_DIR unwind.h)
vpp_find_library(LIBUNWIND_LIB NAMES unwind libunwind)

if (LIBUNWIND_INCLUDE_DIR AND LIBUNWIND_LIB)
  message(STATUS "libunwind found at ${LIBUNWIND_LIB}")
  list(APPEND VPPINFRA_LIBS ${LIBUNWIND_LIB})
  add_definitions(-DHAVE_LIBUNWIND=1)
else()
  message(WARNING "libunwind not found - stack traces disabled")
  add_definitions(-DHAVE_LIBUNWIND=0)
endif()

##############################################################################
# Generate vppinfra/config.h
##############################################################################
set(LOG2_CACHE_LINE_BYTES ${VPP_LOG2_CACHE_LINE_SIZE})
set(N_PREFETCHES ${VPP_N_PREFETCHES})

option(VPP_VECTOR_GROW_BY_ONE "Vectors grow by one, instead of 3/2" OFF)
if(VPP_VECTOR_GROW_BY_ONE)
  set(VECTOR_GROW_BY_ONE 1)
else(VPP_VECTOR_GROW_BY_ONE)
  set(VECTOR_GROW_BY_ONE 0)
endif(VPP_VECTOR_GROW_BY_ONE)

configure_file(
  ${CMAKE_SOURCE_DIR}/vppinfra/config.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/config.h
)

install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/config.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/vppinfra
  COMPONENT vpp-dev
)

add_definitions(-fvisibility=hidden)

# Ensure symbols from cJSON are exported
set_source_files_properties( cJSON.c PROPERTIES
  COMPILE_DEFINITIONS " CJSON_API_VISIBILITY " )

##############################################################################
# vppinfra sources
##############################################################################
set(VPPINFRA_SRCS
  bitmap.c
  bihash_all_vector.c
  cpu.c
  devicetree.c
  dlmalloc.c
  elf.c
  elog.c
  error.c
  fifo.c
  format.c
  format_table.c
  hash.c
  heap.c
  interrupt.c
  longjmp.S
  macros.c
  maplog.c
  mem.c
  mem_bulk.c
  mem_dlmalloc.c
  mhash.c
  mpcap.c
  pcap.c
  pmalloc.c
  pool.c
  ptclosure.c
  random_buffer.c
  random.c
  random_isaac.c
  rbtree.c
  serialize.c
  socket.c
  stack.c
  std-formats.c
  string.c
  time.c
  time_range.c
  timing_wheel.c
  tw_timer_2t_2w_512sl.c
  tw_timer_16t_1w_2048sl.c
  tw_timer_16t_2w_512sl.c
  tw_timer_1t_3w_1024sl_ov.c
  tw_timer_2t_1w_2048sl.c
  tw_timer_4t_3w_256sl.c
  unformat.c
  unix-formats.c
  unix-misc.c
  valloc.c
  vec.c
  vector.c
  vector/toeplitz.c
  cJSON.c
)

set(VPPINFRA_HEADERS
  bihash_12_4.h
  bihash_16_8.h
  bihash_24_8.h
  bihash_32_8.h
  bihash_40_8.h
  bihash_48_8.h
  bihash_56_8.h
  bihash_8_8.h
  bihash_8_16.h
  bihash_24_16.h
  bihash_template.c
  bihash_template.h
  bihash_template_inlines.h
  bihash_vec8_8.h
  bitmap.h
  bitops.h
  byte_order.h
  cache.h
  callback.h
  callback_data.h
  cJSON.h
  clib_error.h
  clib.h
  cpu.h
  crc32.h
  crypto/sha2.h
  crypto/ghash.h
  crypto/aes.h
  crypto/aes_cbc.h
  crypto/aes_ctr.h
  crypto/aes_gcm.h
  crypto/poly1305.h
  devicetree.h
  dlist.h
  dlmalloc.h
  elf_clib.h
  elf.h
  elog.h
  error_bootstrap.h
  error.h
  fifo.h
  file.h
  format.h
  format_ansi.h
  format_table.h
  hash.h
  heap.h
  interrupt.h
  lb_hash_hash.h
  llist.h
  lock.h
  longjmp.h
  macros.h
  maplog.h
  math.h
  memcpy.h
  memcpy_x86_64.h
  mem.h
  mhash.h
  mpcap.h
  os.h
  pcap.h
  pcap_funcs.h
  pcg.h
  perfmon/perfmon.h
  pmalloc.h
  pool.h
  ptclosure.h
  random_buffer.h
  random.h
  random_isaac.h
  rbtree.h
  ring.h
  serialize.h
  socket.h
  sparse_vec.h
  stack.h
  string.h
  time.h
  time_range.h
  timing_wheel.h
  tw_timer_2t_2w_512sl.h
  tw_timer_16t_1w_2048sl.h
  tw_timer_16t_2w_512sl.h
  tw_timer_1t_3w_1024sl_ov.h
  tw_timer_2t_1w_2048sl.h
  tw_timer_4t_3w_256sl.h
  tw_timer_template.c
  tw_timer_template.h
  types.h
  atomics.h
  unix.h
  valloc.h
  vec_bootstrap.h
  vec.h
  vector_altivec.h
  vector_avx2.h
  vector_avx512.h
  vector/array_mask.h
  vector/compress.h
  vector/count_equal.h
  vector/index_to_ptr.h
  vector/ip_csum.h
  vector/mask_compare.h
  vector/toeplitz.h
  vector.h
  vector_neon.h
  vector_sse42.h
  warnings.h
  xxhash.h
  linux/sysfs.h
)

if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
  list(APPEND VPPINFRA_SRCS
    elf_clib.c
    linux/mem.c
    linux/sysfs.c
    linux/netns.c
# TODO: Temporarily don't build perfmon on non-Linux
    perfmon/bundle_default.c
    perfmon/bundle_core_power.c
    perfmon/perfmon.c
   )
elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "FreeBSD")
  list(APPEND VPPINFRA_SRCS
    elf_clib.c
    freebsd/mem.c
   )
endif()

add_vpp_library(vppinfra
  SOURCES ${VPPINFRA_SRCS}
  LINK_LIBRARIES m ${VPPINFRA_LIBS}
  INSTALL_HEADERS ${VPPINFRA_HEADERS}
  COMPONENT libvppinfra
  LTO
)

##############################################################################
# vppinfra headers
##############################################################################
option(VPP_BUILD_VPPINFRA_TESTS "Build vppinfra tests." OFF)
if(VPP_BUILD_VPPINFRA_TESTS)
  foreach(test
    bihash_vec88
    dlist
    elf
    elog
    fifo
    format
    fpool
    hash
    heap
    interrupt
    longjmp
    macros
    maplog
    mhash
    pmalloc
    pool_alloc
    pool_iterate
    ptclosure
    random
    random_isaac
    rwlock
    serialize
    socket
    spinlock
    time
    time_range
    tw_timer
    valloc
    vec
  )
    add_vpp_executable(test_${test}
      SOURCES test_${test}.c
      LINK_LIBRARIES vppinfra pthread
      )
  endforeach()

  foreach(test bihash_template)
    add_vpp_executable(test_${test}
      SOURCES test_${test}.c
      LINK_LIBRARIES vppinfra Threads::Threads
      )
  endforeach()
endif(VPP_BUILD_VPPINFRA_TESTS)

set(test_files
  test/aes_cbc.c
  test/aes_ctr.c
  test/aes_gcm.c
  test/poly1305.c
  test/array_mask.c
  test/compress.c
  test/count_equal.c
  test/crc32c.c
  test/index_to_ptr.c
  test/ip_csum.c
  test/mask_compare.c
  test/memcpy_x86_64.c
  test/sha2.c
  test/toeplitz.c
)

add_vpp_executable(test_infra
  SOURCES
  test/test.c
  ${test_files}
  LINK_LIBRARIES vppinfra
  NO_INSTALL
)

vpp_library_set_multiarch_sources(test_infra
  SOURCES
  ${test_files}
)

