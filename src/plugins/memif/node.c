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

#define _GNU_SOURCE
#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>
#include <vnet/feature/feature.h>

#include <memif/memif.h>

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

typedef struct
{
  u32 next_index;
  u32 hw_if_index;
  u16 ring;
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
  s = format (s, "\n%Uslot: ring %u", format_white_space, indent + 2,
	      t->ring);
  return s;
}

static_always_inline void
memif_prefetch (vlib_main_t * vm, u32 bi)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  vlib_prefetch_buffer_header (b, STORE);
  CLIB_PREFETCH (b->data, CLIB_CACHE_LINE_BYTES, STORE);
}

static_always_inline uword
memif_device_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			   vlib_frame_t * frame, memif_if_t * mif,
			   memif_ring_type_t type)
{
  vnet_main_t *vnm = vnet_get_main ();
  u8 rid = 0;			/* Ring id */
  memif_ring_t *ring = memif_get_ring (mif, type, rid);
  memif_ring_data_t *rd =
    vec_elt_at_index (mif->ring_data, rid + type * mif->num_s2m_rings);
  u16 head;

  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  uword n_trace = vlib_get_trace_count (vm, node);
  memif_main_t *nm = &memif_main;
  u32 n_rx_packets = 0;
  u32 n_rx_bytes = 0;
  u32 *to_next = 0;
  u32 n_free_bufs;
  u32 thread_index = vlib_get_thread_index ();
  u32 bi0, bi1;
  vlib_buffer_t *b0, *b1;
  u16 ring_size = 1 << mif->log2_ring_size;
  u16 mask = ring_size - 1;
  u16 num_slots;
  void *mb0, *mb1;

  if (mif->per_interface_next_index != ~0)
    next_index = mif->per_interface_next_index;

  n_free_bufs = vec_len (nm->rx_buffers[thread_index]);
  if (PREDICT_FALSE (n_free_bufs < ring_size))
    {
      vec_validate (nm->rx_buffers[thread_index],
		    ring_size + n_free_bufs - 1);
      n_free_bufs +=
	vlib_buffer_alloc (vm, &nm->rx_buffers[thread_index][n_free_bufs],
			   ring_size);
      _vec_len (nm->rx_buffers[thread_index]) = n_free_bufs;
    }

  head = ring->head;
  if (head == rd->last_head)
    return 0;

  if (head > rd->last_head)
    num_slots = head - rd->last_head;
  else
    num_slots = ring_size - rd->last_head + head;

  while (num_slots)
    {
      u32 n_left_to_next;
      u32 next0 = next_index;
      u32 next1 = next_index;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (num_slots > 5 && n_left_to_next > 2)
	{
	  if (PREDICT_TRUE (rd->last_head + 5 < ring_size))
	    {
	      CLIB_PREFETCH (memif_get_buffer (mif, ring, rd->last_head + 2),
			     CLIB_CACHE_LINE_BYTES, LOAD);
	      CLIB_PREFETCH (memif_get_buffer (mif, ring, rd->last_head + 3),
			     CLIB_CACHE_LINE_BYTES, LOAD);
	      CLIB_PREFETCH (&ring->desc[rd->last_head + 4],
			     CLIB_CACHE_LINE_BYTES, LOAD);
	      CLIB_PREFETCH (&ring->desc[rd->last_head + 5],
			     CLIB_CACHE_LINE_BYTES, LOAD);
	    }
	  else
	    {
	      CLIB_PREFETCH (memif_get_buffer
			     (mif, ring, (rd->last_head + 2) % mask),
			     CLIB_CACHE_LINE_BYTES, LOAD);
	      CLIB_PREFETCH (memif_get_buffer
			     (mif, ring, (rd->last_head + 3) % mask),
			     CLIB_CACHE_LINE_BYTES, LOAD);
	      CLIB_PREFETCH (&ring->desc[(rd->last_head + 4) % mask],
			     CLIB_CACHE_LINE_BYTES, LOAD);
	      CLIB_PREFETCH (&ring->desc[(rd->last_head + 5) % mask],
			     CLIB_CACHE_LINE_BYTES, LOAD);
	    }
	  /* get empty buffer */
	  u32 last_buf = vec_len (nm->rx_buffers[thread_index]) - 1;
	  bi0 = nm->rx_buffers[thread_index][last_buf];
	  bi1 = nm->rx_buffers[thread_index][last_buf - 1];
	  _vec_len (nm->rx_buffers[thread_index]) -= 2;

	  if (last_buf > 4)
	    {
	      memif_prefetch (vm, nm->rx_buffers[thread_index][last_buf - 2]);
	      memif_prefetch (vm, nm->rx_buffers[thread_index][last_buf - 3]);
	    }

	  /* enqueue buffer */
	  to_next[0] = bi0;
	  to_next[1] = bi1;
	  to_next += 2;
	  n_left_to_next -= 2;

	  /* fill buffer metadata */
	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = mif->sw_if_index;
	  vnet_buffer (b1)->sw_if_index[VLIB_RX] = mif->sw_if_index;

	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	  vnet_buffer (b1)->sw_if_index[VLIB_TX] = (u32) ~ 0;

	  /* copy buffer */
	  mb0 = memif_get_buffer (mif, ring, rd->last_head);
	  clib_memcpy (vlib_buffer_get_current (b0), mb0,
		       CLIB_CACHE_LINE_BYTES);
	  b0->current_length = ring->desc[rd->last_head].length;
	  rd->last_head = (rd->last_head + 1) & mask;

	  mb1 = memif_get_buffer (mif, ring, rd->last_head);
	  clib_memcpy (vlib_buffer_get_current (b1), mb1,
		       CLIB_CACHE_LINE_BYTES);
	  b1->current_length = ring->desc[rd->last_head].length;
	  rd->last_head = (rd->last_head + 1) & mask;

	  if (b0->current_length > CLIB_CACHE_LINE_BYTES)
	    clib_memcpy (vlib_buffer_get_current (b0) + CLIB_CACHE_LINE_BYTES,
			 mb0 + CLIB_CACHE_LINE_BYTES,
			 b0->current_length - CLIB_CACHE_LINE_BYTES);

	  if (b1->current_length > CLIB_CACHE_LINE_BYTES)
	    clib_memcpy (vlib_buffer_get_current (b1) + CLIB_CACHE_LINE_BYTES,
			 mb1 + CLIB_CACHE_LINE_BYTES,
			 b1->current_length - CLIB_CACHE_LINE_BYTES);

	  /* trace */
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b1);

	  if (PREDICT_FALSE (n_trace > 0))
	    {
	      /* b0 */
	      memif_input_trace_t *tr;
	      vlib_trace_buffer (vm, node, next0, b0,
				 /* follow_chain */ 0);
	      vlib_set_trace_count (vm, node, --n_trace);
	      tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->next_index = next0;
	      tr->hw_if_index = mif->hw_if_index;
	      tr->ring = rid;

	      if (n_trace)
		{
		  /* b1 */
		  memif_input_trace_t *tr;
		  vlib_trace_buffer (vm, node, next1, b1,
				     /* follow_chain */ 0);
		  vlib_set_trace_count (vm, node, --n_trace);
		  tr = vlib_add_trace (vm, node, b1, sizeof (*tr));
		  tr->next_index = next1;
		  tr->hw_if_index = mif->hw_if_index;
		  tr->ring = rid;
		}
	    }

	  /* redirect if feature path enabled */
	  vnet_feature_start_device_input_x2 (mif->sw_if_index,
					      &next0, &next1, b0, b1);

	  /* enqueue */
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next,
					   bi0, bi1, next0, next1);

	  /* next packet */
	  num_slots -= 2;
	  n_rx_packets += 2;
	  n_rx_bytes += b0->current_length;
	  n_rx_bytes += b1->current_length;
	}
      while (num_slots && n_left_to_next)
	{
	  /* get empty buffer */
	  u32 last_buf = vec_len (nm->rx_buffers[thread_index]) - 1;
	  bi0 = nm->rx_buffers[thread_index][last_buf];
	  _vec_len (nm->rx_buffers[thread_index]) = last_buf;

	  /* enqueue buffer */
	  to_next[0] = bi0;
	  to_next += 1;
	  n_left_to_next--;

	  /* fill buffer metadata */
	  b0 = vlib_get_buffer (vm, bi0);
	  b0->current_length = ring->desc[rd->last_head].length;
	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = mif->sw_if_index;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;

	  /* copy buffer */
	  mb0 = memif_get_buffer (mif, ring, rd->last_head);
	  clib_memcpy (vlib_buffer_get_current (b0), mb0,
		       CLIB_CACHE_LINE_BYTES);
	  if (b0->current_length > CLIB_CACHE_LINE_BYTES)
	    clib_memcpy (vlib_buffer_get_current (b0) + CLIB_CACHE_LINE_BYTES,
			 mb0 + CLIB_CACHE_LINE_BYTES,
			 b0->current_length - CLIB_CACHE_LINE_BYTES);

	  /* trace */
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);

	  if (PREDICT_FALSE (n_trace > 0))
	    {
	      memif_input_trace_t *tr;
	      vlib_trace_buffer (vm, node, next0, b0,
				 /* follow_chain */ 0);
	      vlib_set_trace_count (vm, node, --n_trace);
	      tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->next_index = next0;
	      tr->hw_if_index = mif->hw_if_index;
	      tr->ring = rid;
	    }


	  /* redirect if feature path enabled */
	  vnet_feature_start_device_input_x1 (mif->sw_if_index, &next0, b0);

	  /* enqueue */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);

	  /* next packet */
	  rd->last_head = (rd->last_head + 1) & mask;
	  num_slots--;
	  n_rx_packets++;
	  n_rx_bytes += b0->current_length;
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  CLIB_MEMORY_STORE_BARRIER ();
  ring->tail = head;

  vlib_increment_combined_counter (vnm->interface_main.combined_sw_if_counters
				   + VNET_INTERFACE_COUNTER_RX, thread_index,
				   mif->hw_if_index, n_rx_packets,
				   n_rx_bytes);

  return n_rx_packets;
}

static uword
memif_input_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{
  u32 n_rx_packets = 0;
  u32 thread_index = vlib_get_thread_index ();
  memif_main_t *nm = &memif_main;
  memif_if_t *mif;

  /* *INDENT-OFF* */
  pool_foreach (mif, nm->interfaces,
    ({
      if (mif->flags & MEMIF_IF_FLAG_ADMIN_UP &&
	  mif->flags & MEMIF_IF_FLAG_CONNECTED &&
	  (mif->if_index % nm->input_cpu_count) ==
	  (thread_index - nm->input_cpu_first_index))
	{
	  if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
	    n_rx_packets +=
	      memif_device_input_inline (vm, node, frame, mif,
					 MEMIF_RING_M2S);
	  else
	    n_rx_packets +=
	      memif_device_input_inline (vm, node, frame, mif,
					 MEMIF_RING_S2M);
	}
    }));
  /* *INDENT-ON* */

  return n_rx_packets;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (memif_input_node) = {
  .function = memif_input_fn,
  .name = "memif-input",
  .sibling_of = "device-input",
  .format_trace = format_memif_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .n_errors = MEMIF_INPUT_N_ERROR,
  .error_strings = memif_input_error_strings,
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
