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
# Generate vppinfra/config.h
##############################################################################
set(LOG2_CACHE_LINE_BYTES ${VPP_LOG2_CACHE_LINE_SIZE})
option(VPP_USE_DLMALLOC "Use dlmalloc memory allocator." ON)
if(VPP_USE_DLMALLOC)
  set(DLMALLOC 1)
else(VPP_USE_DLMALLOC)
  set(DLMALLOC 0)
endif(VPP_USE_DLMALLOC)

configure_file(
  ${CMAKE_SOURCE_DIR}/vppinfra/config.h.in
  ${CMAKE_BINARY_DIR}/vppinfra/config.h
)

install(
  FILES ${CMAKE_BINARY_DIR}/vppinfra/config.h
  DESTINATION include/vppinfra
  COMPONENT vpp-dev
)

##############################################################################
# vppinfra sources
##############################################################################
set(VPPINFRA_SRCS
  asm_x86.c
  backtrace.c
  cpu.c
  cuckoo_template.c
  elf.c
  elog.c
  error.c
  fheap.c
  fifo.c
  format.c
  graph.c
  hash.c
  heap.c
  longjmp.S
  macros.c
  maplog.c
  mhash.c
  pcap.c
  pmalloc.c
  pool.c
  ptclosure.c
  random.c
  random_buffer.c
  random_isaac.c
  serialize.c
  slist.c
  socket.c
  std-formats.c
  string.c
  time.c
  time_range.c
  timer.c
  timing_wheel.c
  tw_timer_2t_1w_2048sl.c
  tw_timer_16t_2w_512sl.c
  tw_timer_16t_1w_2048sl.c
  tw_timer_4t_3w_256sl.c
  tw_timer_1t_3w_1024sl_ov.c
  unformat.c
  unix-formats.c
  unix-misc.c
  valloc.c
  vec.c
  vector.c
  zvec.c
)

set(VPPINFRA_HEADERS
  asm_mips.h
  asm_x86.h
  bihash_16_8.h
  bihash_24_8.h
  bihash_40_8.h
  bihash_48_8.h
  bihash_8_8.h
  bihash_template.c
  bihash_template.h
  bihash_vec8_8.h
  bitmap.h
  bitops.h
  byte_order.h
  cache.h
  clib_error.h
  clib.h
  cpu.h
  crc32.h
  dlist.h
  dlmalloc.h
  elf_clib.h
  elf.h
  elog.h
  error_bootstrap.h
  error.h
  fheap.h
  fifo.h
  file.h
  flowhash_24_16.h
  flowhash_8_8.h
  flowhash_template.h
  format.h
  graph.h
  hash.h
  heap.h
  lb_hash_hash.h
  lock.h
  longjmp.h
  macros.h
  maplog.h
  math.h
  memcpy_avx2.h
  memcpy_avx512.h
  memcpy_sse3.h
  mem.h
  mhash.h
  mheap_bootstrap.h
  mheap.h
  os.h
  pcap.h
  pcap_funcs.h
  pipeline.h
  pmalloc.h
  pool.h
  pmc.h
  ptclosure.h
  random_buffer.h
  random.h
  random_isaac.h
  serialize.h
  slist.h
  smp.h
  socket.h
  sparse_vec.h
  string.h
  time.h
  time_range.h
  timer.h
  timing_wheel.h
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
  valgrind.h
  valloc.h
  vec_bootstrap.h
  vec.h
  vector_altivec.h
  vector_avx2.h
  vector_avx512.h
  vector_funcs.h
  vector.h
  vector_neon.h
  vector_sse42.h
  xxhash.h
  xy.h
  zvec.h
  linux/syscall.h
  linux/sysfs.h
)

if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
  list(APPEND VPPINFRA_SRCS
    elf_clib.c
    linux/mem.c
    linux/sysfs.c
   )
endif()


if(VPP_USE_DLMALLOC)
  list(APPEND VPPINFRA_SRCS
    dlmalloc.c
    mem_dlmalloc.c
  )
else(VPP_USE_DLMALLOC)
  list(APPEND VPPINFRA_SRCS
    mheap.c
    mem_mheap.c
  )
endif(VPP_USE_DLMALLOC)

add_vpp_library(vppinfra
  SOURCES ${VPPINFRA_SRCS}
  LINK_LIBRARIES m
  INSTALL_HEADERS ${VPPINFRA_HEADERS}
  COMPONENT libvppinfra
)

##############################################################################
# vppinfra headers
##############################################################################
option(VPP_BUILD_VPPINFRA_TESTS "Build vppinfra tests." OFF)
if(VPP_BUILD_VPPINFRA_TESTS)
  foreach(test
    bihash_vec88
    cuckoo_template
    dlist
    elf
    elog
    fifo
    flowhash_template
    format
    fpool
    hash
    heap
    longjmp
    macros
    maplog
    pmalloc
    pool_iterate
    ptclosure
    random
    random_isaac
    serialize
    slist
    socket
    time
    time_range
    timing_wheel
    tw_timer
    valloc
    vec
    zvec
  )
    add_vpp_executable(test_${test}
      SOURCES test_${test}.c
      LINK_LIBRARIES vppinfra
      )
  endforeach()

  foreach(test bihash_template cuckoo_bihash)
    add_vpp_executable(test_${test}
      SOURCES test_${test}.c
      LINK_LIBRARIES vppinfra Threads::Threads
      )
  endforeach()
endif(VPP_BUILD_VPPINFRA_TESTS)
