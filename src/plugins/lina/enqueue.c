/*
 *------------------------------------------------------------------
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vppinfra/socket.h>
#include <vlib/vlib.h>

#include <lina/shared.h>
#include <lina/lina.h>

#define foreach_lina_enqueue_error \
  _(NO_FREE_SLOTS, "no free slots")

typedef enum
{
#define _(f,s) LINA_TX_ERROR_##f,
  foreach_lina_enqueue_error
#undef _
    LINA_ENQUEUE_N_ERROR,
} lina_enqueue_error_t;

static char *lina_enqueue_error_strings[] = {
#define _(n,s) s,
  foreach_lina_enqueue_error
#undef _
};


static u8 *
format_lina_enqueue_trace (u8 * s, va_list * args)
{
  s = format (s, "Unimplemented...");
  return s;
}


VLIB_NODE_FN (lina_enqueue_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  lina_main_t *lm = &lina_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u32 n_left, *from;
  lina_instance_t *lin;
  lina_ring_t *ring;
  u16 head, mask;

  clib_warning ("%u packets received", frame->n_vectors);

  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left);

  lin = pool_elt_at_index (lm->instances, 0);
  ring = vec_elt_at_index (lin->rings, vm->thread_index);

  mask = (1 << lin->shm_hdr->log2_ring_sz) - 1;
  head = ring->hdr->head;

  while (n_left)
    {
      vlib_buffer_pool_t *bp;
      lina_shm_desc_t *d = ring->descs + head;
      u32 buffer_pool_index = b[0]->buffer_pool_index;
      bp = vec_elt_at_index (buffer_main.buffer_pools, buffer_pool_index);
      d[0].length = b[0]->current_length;
      d[0].region = buffer_pool_index + 1;
      d[0].offset = vlib_buffer_get_current_va (b[0]) - bp->start;

      /* next */
      head = (head + 1) & mask;
      from++;
      b++;
      n_left--;
    }

  CLIB_MEMORY_STORE_BARRIER ();
  ring->hdr->head = head;

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (lina_enqueue_node) = {
  .name = "lina-enqueue",
  .vector_size = sizeof (u32),
  .format_trace = format_lina_enqueue_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = LINA_ENQUEUE_N_ERROR,
  .error_strings = lina_enqueue_error_strings,
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
