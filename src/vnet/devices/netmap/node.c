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
#include <vnet/devices/devices.h>
#include <vnet/feature/feature.h>

#include <vnet/devices/netmap/net_netmap.h>
#include <vnet/devices/netmap/netmap.h>

#define foreach_netmap_input_error

typedef enum
{
#define _(f,s) NETMAP_INPUT_ERROR_##f,
  foreach_netmap_input_error
#undef _
    NETMAP_INPUT_N_ERROR,
} netmap_input_error_t;

static char *netmap_input_error_strings[] = {
#define _(n,s) s,
  foreach_netmap_input_error
#undef _
};

typedef struct
{
  u32 next_index;
  u32 hw_if_index;
  struct netmap_slot slot;
} netmap_input_trace_t;

static u8 *
format_netmap_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  netmap_input_trace_t *t = va_arg (*args, netmap_input_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "netmap: hw_if_index %d next-index %d",
	      t->hw_if_index, t->next_index);
  s = format (s, "\n%Uslot: flags 0x%x len %u buf_idx %u",
	      format_white_space, indent + 2,
	      t->slot.flags, t->slot.len, t->slot.buf_idx);
  return s;
}

always_inline void
buffer_add_to_chain (vlib_main_t * vm, u32 bi, u32 first_bi, u32 prev_bi)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  vlib_buffer_t *first_b = vlib_get_buffer (vm, first_bi);
  vlib_buffer_t *prev_b = vlib_get_buffer (vm, prev_bi);

  /* update first buffer */
  first_b->total_length_not_including_first_buffer += b->current_length;

  /* update previous buffer */
  prev_b->next_buffer = bi;
  prev_b->flags |= VLIB_BUFFER_NEXT_PRESENT;

  /* update current buffer */
  b->next_buffer = 0;
}

always_inline uword
netmap_device_input_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
			vlib_frame_t * frame, netmap_if_t * nif)
{
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  uword n_trace = vlib_get_trace_count (vm, node);
  netmap_main_t *nm = &netmap_main;
  u32 n_rx_packets = 0;
  u32 n_rx_bytes = 0;
  u32 *to_next = 0;
  u32 n_free_bufs;
  struct netmap_ring *ring;
  int cur_ring;
  u32 thread_index = vm->thread_index;
  u32 n_buffer_bytes = VLIB_BUFFER_DEFAULT_FREE_LIST_BYTES;

  if (nif->per_interface_next_index != ~0)
    next_index = nif->per_interface_next_index;

  n_free_bufs = vec_len (nm->rx_buffers[thread_index]);
  if (PREDICT_FALSE (n_free_bufs < VLIB_FRAME_SIZE))
    {
      vec_validate (nm->rx_buffers[thread_index],
		    VLIB_FRAME_SIZE + n_free_bufs - 1);
      n_free_bufs +=
	vlib_buffer_alloc (vm, &nm->rx_buffers[thread_index][n_free_bufs],
			   VLIB_FRAME_SIZE);
      _vec_len (nm->rx_buffers[thread_index]) = n_free_bufs;
    }

  cur_ring = nif->first_rx_ring;
  while (cur_ring <= nif->last_rx_ring && n_free_bufs)
    {
      int r = 0;
      u32 cur_slot_index;
      ring = NETMAP_RXRING (nif->nifp, cur_ring);
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
	      vlib_buffer_t *first_b0 = 0;
	      u32 offset = 0;
	      u32 bi0 = 0, first_bi0 = 0, prev_bi0;
	      u32 next_slot_index = (cur_slot_index + 1) % ring->num_slots;
	      u32 next2_slot_index = (cur_slot_index + 2) % ring->num_slots;
	      struct netmap_slot *slot = &ring->slot[cur_slot_index];
	      u32 data_len = slot->len;

	      /* prefetch 2 slots in advance */
	      CLIB_PREFETCH (&ring->slot[next2_slot_index],
			     CLIB_CACHE_LINE_BYTES, LOAD);
	      /* prefetch start of next packet */
	      CLIB_PREFETCH (NETMAP_BUF
			     (ring, ring->slot[next_slot_index].buf_idx),
			     CLIB_CACHE_LINE_BYTES, LOAD);

	      while (data_len && n_free_bufs)
		{
		  vlib_buffer_t *b0;
		  /* grab free buffer */
		  u32 last_empty_buffer =
		    vec_len (nm->rx_buffers[thread_index]) - 1;
		  prev_bi0 = bi0;
		  bi0 = nm->rx_buffers[thread_index][last_empty_buffer];
		  b0 = vlib_get_buffer (vm, bi0);
		  _vec_len (nm->rx_buffers[thread_index]) = last_empty_buffer;
		  n_free_bufs--;

		  /* copy data */
		  u32 bytes_to_copy =
		    data_len > n_buffer_bytes ? n_buffer_bytes : data_len;
		  b0->current_data = 0;
		  clib_memcpy_fast (vlib_buffer_get_current (b0),
				    (u8 *) NETMAP_BUF (ring, slot->buf_idx) +
				    offset, bytes_to_copy);

		  /* fill buffer header */
		  b0->current_length = bytes_to_copy;

		  if (offset == 0)
		    {
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
		      netmap_input_trace_t *tr;
		      vlib_trace_buffer (vm, node, next0, first_b0,
					 /* follow_chain */ 0);
		      vlib_set_trace_count (vm, node, --n_trace);
		      tr = vlib_add_trace (vm, node, first_b0, sizeof (*tr));
		      tr->next_index = next0;
		      tr->hw_if_index = nif->hw_if_index;
		      memcpy (&tr->slot, slot, sizeof (struct netmap_slot));
		    }
		}

	      /* redirect if feature path enabled */
	      vnet_feature_start_device_input_x1 (nif->sw_if_index, &next0,
						  first_b0);

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
     vlib_get_thread_index (), nif->hw_if_index, n_rx_packets, n_rx_bytes);

  vnet_device_increment_rx_packets (thread_index, n_rx_packets);

  return n_rx_packets;
}

static uword
netmap_input_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		 vlib_frame_t * frame)
{
  int i;
  u32 n_rx_packets = 0;
  u32 thread_index = vm->thread_index;
  netmap_main_t *nm = &netmap_main;
  netmap_if_t *nmi;

  for (i = 0; i < vec_len (nm->interfaces); i++)
    {
      nmi = vec_elt_at_index (nm->interfaces, i);
      if (nmi->is_admin_up &&
	  (i % nm->input_cpu_count) ==
	  (thread_index - nm->input_cpu_first_index))
	n_rx_packets += netmap_device_input_fn (vm, node, frame, nmi);
    }

  return n_rx_packets;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (netmap_input_node) = {
  .function = netmap_input_fn,
  .name = "netmap-input",
  .sibling_of = "device-input",
  .format_trace = format_netmap_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  /* default state is INTERRUPT mode, switch to POLLING if worker threads are enabled */
  .state = VLIB_NODE_STATE_INTERRUPT,
  .n_errors = NETMAP_INPUT_N_ERROR,
  .error_strings = netmap_input_error_strings,
};

VLIB_NODE_FUNCTION_MULTIARCH (netmap_input_node, netmap_input_fn)
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
