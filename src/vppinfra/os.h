/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2001-2005 Eliot Dresselhaus
 */

#ifndef included_os_h
#define included_os_h

#include <vppinfra/clib.h>
#include <vppinfra/types.h>

/* External panic function. */
void os_panic (void);

/* External exit function analogous to unix exit. */
void os_exit (int code);

/* External function to print a line. */
void os_puts (u8 * string, uword length, uword is_error);

/* External function to handle out of memory. */
void os_out_of_memory (void);

/* Estimate, measure or divine CPU timestamp clock frequency. */
f64 os_cpu_clock_frequency (void);

extern __thread clib_thread_index_t __os_thread_index;
extern __thread clib_numa_node_index_t __os_numa_index;

static_always_inline clib_thread_index_t
os_get_thread_index (void)
{
  return __os_thread_index;
}

static_always_inline void
os_set_thread_index (clib_thread_index_t thread_index)
{
  __os_thread_index = thread_index;
}

static_always_inline clib_numa_node_index_t
os_get_numa_index (void)
{
  return __os_numa_index;
}

static_always_inline void
os_set_numa_index (clib_numa_node_index_t numa_index)
{
  __os_numa_index = numa_index;
}

static_always_inline uword
os_get_cpu_number (void) __attribute__ ((deprecated));

static_always_inline uword
os_get_cpu_number (void)
{
  return __os_thread_index;
}

uword os_get_nthreads (void);

#include <vppinfra/cache.h>

#endif /* included_os_h */
