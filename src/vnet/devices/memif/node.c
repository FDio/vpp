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

#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>

#include <vnet/devices/memif/memif.h>

#define foreach_memif_input_error

typedef enum
{
#define _(f,s) MEMIF_INPUT_ERROR_##f,
  foreach_memif_input_error
#undef _
    MEMIF_INPUT_N_ERROR,
} memif_input_error_t;

static char *memif_input_error_strings[] = {
#define _(n,s) s,
  foreach_memif_input_error
#undef _
};

enum
{
  MEMIF_INPUT_NEXT_DROP,
  MEMIF_INPUT_NEXT_ETHERNET_INPUT,
  MEMIF_INPUT_N_NEXT,
};

typedef struct
{
  u32 next_index;
  u32 hw_if_index;
} memif_input_trace_t;

static u8 *
format_memif_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  memif_input_trace_t *t = va_arg (*args, memif_input_trace_t *);
  uword indent = format_get_indent (s);

  s = format (s, "memif: hw_if_index %d next-index %d",
	      t->hw_if_index, t->next_index);
  s = format (s, "\n%Uslot: TODO", format_white_space, indent + 2);
  return s;
}

always_inline uword
memif_device_input_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		       vlib_frame_t * frame, memif_if_t * nif)
{
  u8 rid = 0;			/* Ring id */
  memif_ring_t *ring = memif_get_s2m_ring (nif, rid);
  memif_ring_data_t *rd = vec_elt_at_index (nif->s2m_ring_data, rid);
  u16 head;

  if (nif->flags & MEMIF_IF_FLAG_IS_SLAVE)
    return 0;

  head = ring->head;
  if (head == rd->last_head)
    return 0;

  clib_warning ("head: old %u new head %u", rd->last_head, head);
  ring->tail = rd->last_head = head;

  return 0;

#if 0
  u32 next_index = MEMIF_INPUT_NEXT_ETHERNET_INPUT;
  uword n_trace = vlib_get_trace_count (vm, node);
  memif_main_t *nm = &memif_main;
  u32 n_rx_packets = 0;
  u32 n_rx_bytes = 0;
  u32 *to_next = 0;
  u32 n_free_bufs;
  struct memif_ring *ring;
  int cur_ring;
  u32 cpu_index = os_get_cpu_number ();
  u32 n_buffer_bytes = vlib_buffer_free_list_buffer_size (vm,
							  VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);

  if (nif->per_interface_next_index != ~0)
    next_index = nif->per_interface_next_index;

  n_free_bufs = vec_len (nm->rx_buffers[cpu_index]);
  if (PREDICT_FALSE (n_free_bufs < VLIB_FRAME_SIZE))
    {
      vec_validate (nm->rx_buffers[cpu_index],
		    VLIB_FRAME_SIZE + n_free_bufs - 1);
      n_free_bufs +=
	vlib_buffer_alloc (vm, &nm->rx_buffers[cpu_index][n_free_bufs],
			   VLIB_FRAME_SIZE);
      _vec_len (nm->rx_buffers[cpu_index]) = n_free_bufs;
    }

  cur_ring = nif->first_rx_ring;
  while (cur_ring <= nif->last_rx_ring && n_free_bufs)
    {
      int r = 0;
      u32 cur_slot_index;
      ring = MEMIF_RXRING (nif->nifp, cur_ring);
      r = nm_ring_space (ring);

      if (!r)
	{
	  cur_ring++;
	  continue;
	}

      if (r > n_free_bufs)
	r = n_free_bufs;

      cur_slot_index = ring->cur;
      while (r)
	{
	  u32 n_left_to_next;
	  u32 next0 = next_index;
	  vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

	  while (r && n_left_to_next)
	    {
	      vlib_buffer_t *b0, *first_b0 = 0;
	      u32 offset = 0;
	      u32 bi0 = 0, first_bi0 = 0, prev_bi0;
	      u32 next_slot_index = (cur_slot_index + 1) % ring->num_slots;
	      u32 next2_slot_index = (cur_slot_index + 2) % ring->num_slots;
	      struct memif_slot *slot = &ring->slot[cur_slot_index];
	      u32 data_len = slot->len;

	      /* prefetch 2 slots in advance */
	      CLIB_PREFETCH (&ring->slot[next2_slot_index],
			     CLIB_CACHE_LINE_BYTES, LOAD);
	      /* prefetch start of next packet */
	      CLIB_PREFETCH (MEMIF_BUF
			     (ring, ring->slot[next_slot_index].buf_idx),
			     CLIB_CACHE_LINE_BYTES, LOAD);

	      while (data_len && n_free_bufs)
		{
		  /* grab free buffer */
		  u32 last_empty_buffer =
		    vec_len (nm->rx_buffers[cpu_index]) - 1;
		  prev_bi0 = bi0;
		  bi0 = nm->rx_buffers[cpu_index][last_empty_buffer];
		  b0 = vlib_get_buffer (vm, bi0);
		  _vec_len (nm->rx_buffers[cpu_index]) = last_empty_buffer;
		  n_free_bufs--;

		  /* copy data */
		  u32 bytes_to_copy =
		    data_len > n_buffer_bytes ? n_buffer_bytes : data_len;
		  b0->current_data = 0;
		  clib_memcpy (vlib_buffer_get_current (b0),
			       (u8 *) MEMIF_BUF (ring,
						 slot->buf_idx) + offset,
			       bytes_to_copy);

		  /* fill buffer header */
		  b0->current_length = bytes_to_copy;

		  if (offset == 0)
		    {
#if DPDK > 0
		      struct rte_mbuf *mb = rte_mbuf_from_vlib_buffer (b0);
		      rte_pktmbuf_data_len (mb) = b0->current_length;
		      rte_pktmbuf_pkt_len (mb) = b0->current_length;
#endif
		      b0->total_length_not_including_first_buffer = 0;
		      b0->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
		      vnet_buffer (b0)->sw_if_index[VLIB_RX] =
			nif->sw_if_index;
		      vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
		      first_bi0 = bi0;
		      first_b0 = vlib_get_buffer (vm, first_bi0);
		    }
		  else
		    buffer_add_to_chain (vm, bi0, first_bi0, prev_bi0);

		  offset += bytes_to_copy;
		  data_len -= bytes_to_copy;
		}

	      /* trace */
	      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (first_b0);
	      if (PREDICT_FALSE (n_trace > 0))
		{
		  if (PREDICT_TRUE (first_b0 != 0))
		    {
		      memif_input_trace_t *tr;
		      vlib_trace_buffer (vm, node, next0, first_b0,
					 /* follow_chain */ 0);
		      vlib_set_trace_count (vm, node, --n_trace);
		      tr = vlib_add_trace (vm, node, first_b0, sizeof (*tr));
		      tr->next_index = next0;
		      tr->hw_if_index = nif->hw_if_index;
		      memcpy (&tr->slot, slot, sizeof (struct memif_slot));
		    }
		}
	      /* enque and take next packet */
	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					       n_left_to_next, first_bi0,
					       next0);

	      /* next packet */
	      n_rx_packets++;
	      n_rx_bytes += slot->len;
	      to_next[0] = first_bi0;
	      to_next += 1;
	      n_left_to_next--;
	      cur_slot_index = next_slot_index;

	      r--;
	    }
	  vlib_put_next_frame (vm, node, next_index, n_left_to_next);
	}
      ring->head = ring->cur = cur_slot_index;
      cur_ring++;
    }

  if (n_rx_packets)
    ioctl (nif->fd, NIOCRXSYNC, NULL);

  vlib_increment_combined_counter
    (vnet_get_main ()->interface_main.combined_sw_if_counters
     + VNET_INTERFACE_COUNTER_RX,
     os_get_cpu_number (), nif->hw_if_index, n_rx_packets, n_rx_bytes);

  return n_rx_packets;
#endif
  return 0;
}

static uword
memif_input_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{
  int i;
  u32 n_rx_packets = 0;
  u32 cpu_index = os_get_cpu_number ();
  memif_main_t *nm = &memif_main;
  memif_if_t *nmi;

  for (i = 0; i < vec_len (nm->interfaces); i++)
    {
      nmi = vec_elt_at_index (nm->interfaces, i);
      if (nmi->flags & MEMIF_IF_FLAG_ADMIN_UP &&
	  nmi->flags & MEMIF_IF_FLAG_CONNECTED &&
	  (i % nm->input_cpu_count) ==
	  (cpu_index - nm->input_cpu_first_index))
	n_rx_packets += memif_device_input_fn (vm, node, frame, nmi);
    }

  return n_rx_packets;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (memif_input_node) = {
  .function = memif_input_fn,
  .name = "memif-input",
  .format_trace = format_memif_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_POLLING,
  .n_errors = MEMIF_INPUT_N_ERROR,
  .error_strings = memif_input_error_strings,

  .n_next_nodes = MEMIF_INPUT_N_NEXT,
  .next_nodes = {
    [MEMIF_INPUT_NEXT_DROP] = "error-drop",
    [MEMIF_INPUT_NEXT_ETHERNET_INPUT] = "ethernet-input",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (memif_input_node, memif_input_fn)
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
