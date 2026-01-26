/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef _TRACEPATH_H_
#define _TRACEPATH_H_

#include <vlib/vlib.h>
#include <vlib/trace.h>
#include <vppinfra/bitmap.h>

typedef struct
{
  clib_bitmap_t *thread_bitmap;
  u32 *path_indices;
  u64 path_id;
  u32 n_pkts;
} trace_path_t;

#endif /* _TRACEPATH_H_ */
