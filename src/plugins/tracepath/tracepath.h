/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#ifndef _TRACEPATH_H_
#define _TRACEPATH_H_

#include <vnet/vnet.h>
#include <vlib/vlib.h>
#include <vlib/trace.h>

#define TRACE_PATH_MAX_LENGTH 32

typedef struct
{
  u32 path_length;
  u32 path_indices[TRACE_PATH_MAX_LENGTH];
  u64 path_id;
  u32 n_pkts;
  u64 thread_bitmap; /* TODO: u64 limits thread tracking to 64 threads */
} trace_path_t;

#endif /* _TRACEPATH_H_ */
