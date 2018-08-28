# Copyright (c) 2015 Cisco and/or its affiliates.
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


AM_CFLAGS = -Wall -I../src/vppinfra -g -O0 -m32 -msse4
AM_LDFLAGS = -m32 -msse2

# Copyright (c) 2015 Cisco and/or its affiliates.
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

lib_LTLIBRARIES = libvppinfra.la

TESTS = test_bihash_32

noinst_PROGRAMS = $(TESTS)
check_PROGRAMS	= $(TESTS)

test_bihash_32_SOURCES = test32/test32.c

# All unit tests use ASSERT for failure
# So we'll need -DDEBUG to enable ASSERTs
test_bihash_32_CPPFLAGS = $(AM_CPPFLAGS) -DCLIB_DEBUG $(AM_CFLAGS)

test_bihash_32_LDADD = libvppinfra.la 

test_bihash_32_LDFLAGS = -static

nobase_include_HEADERS = \
  vppinfra/asm_mips.h \
  vppinfra/asm_x86.h \
  vppinfra/bihash_8_8.h \
  vppinfra/bihash_vec8_8.h \
  vppinfra/bihash_16_8.h \
  vppinfra/bihash_24_8.h \
  vppinfra/bihash_40_8.h \
  vppinfra/bihash_48_8.h \
  vppinfra/bihash_template.h \
  vppinfra/bihash_template.c \
  vppinfra/bitmap.h \
  vppinfra/bitops.h \
  vppinfra/byte_order.h \
  vppinfra/cache.h \
  vppinfra/config.h \
  vppinfra/clib.h \
  vppinfra/clib_error.h \
  vppinfra/cpu.h \
  vppinfra/crc32.h \
  vppinfra/lb_hash_hash.h \
  vppinfra/dlist.h \
  vppinfra/elf.h \
  vppinfra/elf_clib.h \
  vppinfra/elog.h \
  vppinfra/fheap.h \
  vppinfra/error.h \
  vppinfra/error_bootstrap.h \
  vppinfra/fifo.h \
  vppinfra/file.h \
  vppinfra/flowhash_template.h \
  vppinfra/flowhash_8_8.h \
  vppinfra/flowhash_24_16.h \
  vppinfra/format.h \
  vppinfra/graph.h \
  vppinfra/hash.h \
  vppinfra/heap.h \
  vppinfra/linux/sysfs.h \
  vppinfra/linux/syscall.h \
  vppinfra/lock.h \
  vppinfra/longjmp.h \
  vppinfra/macros.h \
  vppinfra/maplog.h \
  vppinfra/math.h \
  vppinfra/mem.h \
  vppinfra/memcpy_sse3.h \
  vppinfra/memcpy_avx2.h \
  vppinfra/memcpy_avx512.h \
  vppinfra/mhash.h \
  vppinfra/mheap.h \
  vppinfra/mheap_bootstrap.h \
  vppinfra/os.h \
  vppinfra/pipeline.h \
  vppinfra/pool.h \
  vppinfra/ptclosure.h \
  vppinfra/random.h \
  vppinfra/random_buffer.h \
  vppinfra/random_isaac.h \
  vppinfra/serialize.h \
  vppinfra/slist.h \
  vppinfra/smp.h \
  vppinfra/socket.h \
  vppinfra/sparse_vec.h \
  vppinfra/string.h \
  vppinfra/time.h \
  vppinfra/time_range.h \
  vppinfra/timing_wheel.h \
  vppinfra/timer.h \
  vppinfra/tw_timer_2t_1w_2048sl.h \
  vppinfra/tw_timer_16t_2w_512sl.h \
  vppinfra/tw_timer_16t_1w_2048sl.h \
  vppinfra/tw_timer_4t_3w_256sl.h \
  vppinfra/tw_timer_1t_3w_1024sl_ov.h \
  vppinfra/tw_timer_template.h \
  vppinfra/tw_timer_template.c \
  vppinfra/types.h \
  vppinfra/unix.h \
  vppinfra/valloc.h \
  vppinfra/vec.h \
  vppinfra/vec_bootstrap.h \
  vppinfra/vector.h \
  vppinfra/vector_altivec.h \
  vppinfra/vector_avx2.h \
  vppinfra/vector_avx512.h \
  vppinfra/vector_funcs.h \
  vppinfra/vector_neon.h \
  vppinfra/vector_sse42.h \
  vppinfra/valgrind.h \
  vppinfra/xxhash.h \
  vppinfra/xy.h \
  vppinfra/zvec.h

if ENABLE_DLMALLOC
  nobase_include_HEADERS += \
  vppinfra/dlmalloc.h
else
  nobase_include_HEADERS +=  \
  vppinfra/mheap_bootstrap.h 
endif

CLIB_CORE = \
  vppinfra/asm_x86.c \
  vppinfra/backtrace.c \
  vppinfra/bihash_8_8.h \
  vppinfra/bihash_vec8_8.h \
  vppinfra/bihash_24_8.h \
  vppinfra/bihash_template.h \
  vppinfra/cpu.c \
  vppinfra/elf.c \
  vppinfra/elog.c \
  vppinfra/error.c \
  vppinfra/fifo.c \
  vppinfra/fheap.c \
  vppinfra/flowhash_8_8.h \
  vppinfra/flowhash_24_16.h \
  vppinfra/flowhash_template.h \
  vppinfra/format.c \
  vppinfra/pool.c \
  vppinfra/graph.c \
  vppinfra/hash.c \
  vppinfra/heap.c \
  vppinfra/macros.c \
  vppinfra/mhash.c \
  vppinfra/ptclosure.c \
  vppinfra/random.c \
  vppinfra/random_buffer.c \
  vppinfra/random_isaac.c \
  vppinfra/serialize.c \
  vppinfra/slist.c \
  vppinfra/std-formats.c \
  vppinfra/string.c \
  vppinfra/time.c \
  vppinfra/time_range.c \
  vppinfra/timing_wheel.c \
  vppinfra/tw_timer_template.h \
  vppinfra/tw_timer_2t_1w_2048sl.h \
  vppinfra/tw_timer_2t_1w_2048sl.c \
  vppinfra/tw_timer_16t_2w_512sl.h \
  vppinfra/tw_timer_16t_2w_512sl.c \
  vppinfra/tw_timer_16t_1w_2048sl.h \
  vppinfra/tw_timer_16t_1w_2048sl.c \
  vppinfra/tw_timer_4t_3w_256sl.h \
  vppinfra/tw_timer_4t_3w_256sl.c \
  vppinfra/tw_timer_1t_3w_1024sl_ov.h \
  vppinfra/tw_timer_1t_3w_1024sl_ov.c \
  vppinfra/unformat.c \
  vppinfra/valloc.c \
  vppinfra/vec.c \
  vppinfra/vector.c \
  vppinfra/zvec.c

if ENABLE_DLMALLOC
  CLIB_CORE += \
  vppinfra/mem_dlmalloc.c \
  vppinfra/dlmalloc.c \
  vppinfra/dlmalloc.h
else
  CLIB_CORE += \
  vppinfra/mheap.c \
  vppinfra/mem_mheap.c 
endif

# Core plus Unix additions
libvppinfra_la_SOURCES =			\
  $(CLIB_CORE)					\
  vppinfra/elf_clib.c				\
  vppinfra/linux/mem.c				\
  vppinfra/linux/sysfs.c			\
  vppinfra/maplog.c 				\
  vppinfra/socket.c				\
  vppinfra/timer.c				\
  vppinfra/unix-formats.c			\
  vppinfra/unix-misc.c

# vi:syntax=automake
