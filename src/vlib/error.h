/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* error.h: drop/punt error packets */

#ifndef included_vlib_error_h
#define included_vlib_error_h

#include <vppinfra/format.h>

typedef u16 vlib_error_t;

enum vl_counter_severity_e
{
  VL_COUNTER_SEVERITY_ERROR,
  VL_COUNTER_SEVERITY_WARN,
  VL_COUNTER_SEVERITY_INFO,
};

typedef struct
{
  char *name;
  char *desc;
  enum vl_counter_severity_e severity;
  u32 stats_entry_index;
} vlib_error_desc_t;

typedef struct
{
  /* Error counters. */
  u64 *counters;

  /* Counter values as of last counter clear. */
  u64 *counters_last_clear;

  /* Counter structures in heap. Heap index
     indexes counter vector. */
  vlib_error_desc_t *counters_heap;

  /* stats segment entry index */
  u32 stats_err_entry_index;
} vlib_error_main_t;

/* Per node error registration. */
void vlib_register_errors (struct vlib_main_t *vm, u32 node_index,
			   u32 n_errors, char *error_strings[],
			   vlib_error_desc_t counters[]);
void vlib_unregister_errors (struct vlib_main_t *vm, u32 node_index);

unformat_function_t unformat_vlib_error;

#endif /* included_vlib_error_h */
