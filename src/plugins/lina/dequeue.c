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

typedef enum
{
  LINE_DEQUEUE_NEXT_ETHERNET_INPUT,
  LINE_DEQUEUE_NEXT_ERROR_DROP,
  LINE_DEQUEUE_N_NEXTS,
} lina_dequeue_next_t;

static u8 *
format_lina_dequeue_trace (u8 * s, va_list * args)
{
  s = format (s, "Unimplemented...");
  return s;
}

static_always_inline uword
lina_dequeue_node_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			  lina_instance_t * lin)
{
  lina_ring_t *ring;
  u32 mask, slot, tail, n_rx_packets = 0;
  u32 frame[VLIB_FRAME_SIZE], *bi;
  u16 nexts[VLIB_FRAME_SIZE], *next;

  if ((lin->flags & LINA_INSTANCE_F_CONNECTED) == 0)
    return 0;

  ring = vec_elt_at_index (lin->rings, vm->thread_index);
  tail = ring->hdr->tail;
  slot = ring->last_tail;

  if (slot == tail)
    return 0;

  mask = (1 << lin->shm_hdr->log2_ring_sz) - 1;

  next = nexts;
  bi = frame;
  while (slot != tail && n_rx_packets < VLIB_FRAME_SIZE)
    {
      lina_shm_desc_t *d = ring->descs + slot;

      bi[0] = ring->buffer_indices[slot];
      if (d->action == LINA_SHM_DESC_ACTION_DROP)
	next[0] = LINE_DEQUEUE_NEXT_ERROR_DROP;
      else
	next[0] = LINE_DEQUEUE_NEXT_ETHERNET_INPUT;

      /* next */
      bi++;
      next++;
      slot = (slot + 1) & mask;
    }

  clib_warning ("new last_tail %u", ring->last_tail);
  vlib_buffer_enqueue_to_next (vm, node, frame, nexts, n_rx_packets);
  return n_rx_packets;
}


VLIB_NODE_FN (lina_dequeue_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  lina_main_t *lm = &lina_main;
  lina_instance_t *lin;
  uword n_rx_packets = 0;

  pool_foreach (lin, lm->instances, {

    n_rx_packets += lina_dequeue_node_inline (vm, node, lin);
  });

  return n_rx_packets;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (lina_dequeue_node) = {
  .name = "lina-dequeue",
  .vector_size = sizeof (u32),
  .format_trace = format_lina_dequeue_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .n_next_nodes = LINE_DEQUEUE_N_NEXTS,
  .next_nodes = {
      [LINE_DEQUEUE_NEXT_ETHERNET_INPUT] = "ethernet-input",
      [LINE_DEQUEUE_NEXT_ERROR_DROP] = "error-drop",
  }
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
