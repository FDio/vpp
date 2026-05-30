/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#pragma once

#include <vlib/main.h>

#define VLIB_HANDOFF_QUEUE_SLOT_SIZE (2 * CLIB_CACHE_LINE_BYTES / sizeof (u32))

typedef struct
{
  union
  {
    u32 buffer_indices[VLIB_HANDOFF_QUEUE_SLOT_SIZE];
    u32x4 as_u32x4[VLIB_HANDOFF_QUEUE_SLOT_SIZE / 4];
    u32x8 as_u32x8[VLIB_HANDOFF_QUEUE_SLOT_SIZE / 8];
    u32x16 as_u32x16[VLIB_HANDOFF_QUEUE_SLOT_SIZE / 16];
  };
} __clib_aligned (VLIB_HANDOFF_QUEUE_SLOT_SIZE * sizeof (u32))
vlib_handoff_queue_slot_t;

STATIC_ASSERT_SIZEOF (vlib_handoff_queue_slot_t, VLIB_HANDOFF_QUEUE_SLOT_SIZE * sizeof (u32));

typedef struct
{
  u32 dequeue_vector_limit;
  u32 size;

  /* modified by enqueue side  */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  u64 tail;
  u64 trace_stop;

  /* modified by dequeue side  */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline2);
  u64 head;

  vlib_handoff_queue_slot_t data[0];
} vlib_handoff_queue_t;

static_always_inline vlib_handoff_queue_slot_t *
vlib_handoff_queue_buffer_index_slots (vlib_handoff_queue_t *hq)
{
  return hq->data;
}

static_always_inline vlib_handoff_queue_slot_t *
vlib_handoff_queue_aux_slots (vlib_handoff_queue_t *hq)
{
  return hq->data + hq->size;
}

struct vlib_handoff_queue_main_t_;
typedef u32 (vlib_handoff_queues_dequeue_fn_t) (vlib_main_t *vm);
typedef struct vlib_handoff_queue_main_t_
{
  u32 node_index;
  u32 size;
  u8 with_aux;

  vlib_handoff_queue_t **vlib_handoff_queues;
} vlib_handoff_queue_main_t;

typedef struct
{
  u32 node_index;
  u32 queue_size;
} vlib_handoff_alloc_queues_args_t;

u32 vlib_handoff_alloc_queues (vlib_handoff_alloc_queues_args_t *a);
extern clib_march_fn_registration *vlib_handoff_queues_dequeue_fn_march_fn_registrations;
