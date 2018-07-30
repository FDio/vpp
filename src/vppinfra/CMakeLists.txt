

set (LOG2_CACHE_LINE_BYTES 6)

configure_file (
    ${CMAKE_SOURCE_DIR}/vppinfra/config.h.in
    ${CMAKE_BINARY_DIR}/vppinfra/config.h
)


enable_language(ASM)

set(VPPINFRA_SRCS
  asm_x86.c
  backtrace.c
  cpu.c
  cuckoo_template.c
  dlmalloc.c
  elf.c
  elf_clib.c
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
  mem_dlmalloc.c
  mhash.c
  pool.c
  ptclosure.c
  qsort.c
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
  vhash.c
  zvec.c
  linux/mem.c
  linux/sysfs.c
)

add_library(vppinfra SHARED ${VPPINFRA_SRCS})
target_link_libraries(vppinfra m)
install(TARGETS vppinfra DESTINATION lib)

set (VPPINFRA_TESTS
  bihash_template
  bihash_vec88
  cuckoo_bihash
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
  vhash
  zvec
)

foreach (test ${VPPINFRA_TESTS})
  add_executable(test_${test} test_${test}.c)
  target_link_libraries(test_${test} vppinfra)
endforeach ()

target_link_libraries(test_bihash_template Threads::Threads)
target_link_libraries(test_cuckoo_bihash Threads::Threads)
