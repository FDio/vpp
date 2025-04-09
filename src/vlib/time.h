/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifndef included_vlib_time_h
#define included_vlib_time_h

#include <vlib/vlib.h>

static inline void
vlib_time_adjust (vlib_main_t *vm, f64 offset)
{
  vm->time_offset += offset;
}

#endif /* included_vlib_time_h */
