/*
 *------------------------------------------------------------------
 * Copyright (c) 2021 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <snort/snort.h>

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
} snort_enq_trace_t;

static u8 *
format_snort_enq_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  snort_enq_trace_t *t = va_arg (*args, snort_enq_trace_t *);

  s = format (s, "snort-enq: sw_if_index %d, next index %d\n", t->sw_if_index,
	      t->next_index);

  return s;
}

#define foreach_snort_enq_error _ (SWAPPED, "Mac swap packets processed")

typedef enum
{
#define _(sym, str) SAMPLE_ERROR_##sym,
  foreach_snort_enq_error
#undef _
    SAMPLE_N_ERROR,
} snort_enq_error_t;

static char *snort_enq_error_strings[] = {
#define _(sym, string) string,
  foreach_snort_enq_error
#undef _
};

VLIB_NODE_FN (snort_enq_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  snort_main_t *sm = &snort_main;
  snort_instance_t *si;
  snort_qpair_t *qp;
  u32 n_left = frame->n_vectors;
  u32 *from = vlib_frame_vector_args (frame);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u32 *data;
  u32 next;

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left)
    {
      daq_vpp_desc_t *d;
      u32 desc_index;
      data = vnet_feature_next_with_data (&next, b[0], sizeof (*data));
      si = vec_elt_at_index (sm->instances, *data);
      qp = vec_elt_at_index (si->qpairs, vm->thread_index);
      desc_index = qp->freelist[--_vec_len(qp->freelist)];

      /* fill descriptor */
      d = qp->descriptors + desc_index;
      d->buffer_pool = b[0]->buffer_pool_index;
      d->length = b[0]->current_length;
      d->offset = (u8 *) b[0]->data + b[0]->current_data -
        sm->buffer_pool_base_addrs[d->buffer_pool];;

      /* enqueue */
      u32 head = *qp->enq_head;
      qp->enq_ring[head] = desc_index;
      head = (head + 1) & pow2_mask (qp->log2_queue_size);
      __atomic_store_n (qp->enq_head, head, __ATOMIC_RELEASE);

      fformat (stderr, "desc_index %u, head %u enq_headp %p enq_ringp %p\n",
	       desc_index, *qp->enq_head, qp->enq_head, qp->enq_ring);
      n_left--;
      b++;
    }

  return 0;
}

VLIB_REGISTER_NODE (snort_enq_node) = {
  .name = "snort-enq",
  .vector_size = sizeof (u32),
  .format_trace = format_snort_enq_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (snort_enq_error_strings),
  .error_strings = snort_enq_error_strings,

  .n_next_nodes = 0,
};
