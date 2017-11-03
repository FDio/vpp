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
#include <memif/private.h>

#define foreach_memif_input_error \
  _(NOT_IP, "not ip packet")

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
  u32 indent = format_get_indent (s);

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

static_always_inline void
memif_buffer_add_to_chain (vlib_main_t * vm, u32 bi, u32 first_bi,
			   u32 prev_bi)
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

/**
 * @brief Copy buffer from rx ring
 *
 * @param * vm (in)
 * @param * mif (in) pointer to memif interface
 * @param * ring (in) pointer to memif ring
 * @param * rd (in) pointer to ring data
 * @param ring_size (in) ring size
 * @param * n_free_bufs (in/out) the number of free vlib buffers available
 * @param ** first_b (out) the first vlib buffer pointer
 * @param * first_bi (out) the first vlib buffer index
 * @param * bi (in/out) the current buffer index
 * #param * num_slots (in/out) the number of descriptors available to read
 *
 * @return total bytes read from rx ring also written to vlib buffers
 */
static_always_inline uword
memif_copy_buffer_from_rx_ring (vlib_main_t * vm, memif_if_t * mif,
				memif_ring_t * ring, memif_queue_t * mq,
				u16 ring_size, u32 n_buffer_bytes,
				u32 * n_free_bufs, vlib_buffer_t ** first_b,
				u32 * first_bi, u32 * bi, u16 * num_slots)
{
  memif_main_t *nm = &memif_main;
  u32 thread_index = vlib_get_thread_index ();
  u32 total_bytes = 0, offset = 0;
  u32 data_len;
  u32 bytes_to_copy;
  void *mb;
  vlib_buffer_t *b;
  u16 mask = ring_size - 1;
  u32 prev_bi;
  u16 last_head;

  while (*num_slots)
    {
      data_len = ring->desc[mq->last_head & mask].length;
      while (data_len && (*n_free_bufs))
	{
	  /* get empty buffer */
	  u32 last_buf = vec_len (nm->rx_buffers[thread_index]) - 1;
	  prev_bi = *bi;
	  *bi = nm->rx_buffers[thread_index][last_buf];
	  b = vlib_get_buffer (vm, *bi);
	  _vec_len (nm->rx_buffers[thread_index]) = last_buf;
	  (*n_free_bufs)--;
	  if (PREDICT_FALSE (*n_free_bufs == 0))
	    {
	      *n_free_bufs +=
		vlib_buffer_alloc (vm,
				   &nm->rx_buffers[thread_index]
				   [*n_free_bufs], ring_size);
	      _vec_len (nm->rx_buffers[thread_index]) = *n_free_bufs;
	    }

	  if (last_buf > 4)
	    {
	      memif_prefetch (vm, nm->rx_buffers[thread_index][last_buf - 2]);
	      memif_prefetch (vm, nm->rx_buffers[thread_index][last_buf - 3]);
	    }

	  /* copy buffer */
	  bytes_to_copy =
	    data_len > n_buffer_bytes ? n_buffer_bytes : data_len;
	  b->current_data = 0;
	  mb = memif_get_buffer (mif, ring, mq->last_head & mask);
	  clib_memcpy (vlib_buffer_get_current (b), mb + offset,
		       CLIB_CACHE_LINE_BYTES);
	  if (bytes_to_copy > CLIB_CACHE_LINE_BYTES)
	    clib_memcpy (vlib_buffer_get_current (b) + CLIB_CACHE_LINE_BYTES,
			 mb + CLIB_CACHE_LINE_BYTES + offset,
			 bytes_to_copy - CLIB_CACHE_LINE_BYTES);

	  /* fill buffer header */
	  b->current_length = bytes_to_copy;

	  if (total_bytes == 0)
	    {
	      /* fill buffer metadata */
	      b->total_length_not_including_first_buffer = 0;
	      b->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
	      vnet_buffer (b)->sw_if_index[VLIB_RX] = mif->sw_if_index;
	      vnet_buffer (b)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	      *first_bi = *bi;
	      *first_b = vlib_get_buffer (vm, *first_bi);
	    }
	  else
	    memif_buffer_add_to_chain (vm, *bi, *first_bi, prev_bi);

	  offset += bytes_to_copy;
	  total_bytes += bytes_to_copy;
	  data_len -= bytes_to_copy;
	}
      last_head = mq->last_head;
      /* Advance to next descriptor */
      mq->last_head++;
      offset = 0;
      (*num_slots)--;
      if ((ring->desc[last_head & mask].flags & MEMIF_DESC_FLAG_NEXT) == 0)
	break;
    }

  return (total_bytes);
}


static_always_inline u32
memif_next_from_ip_hdr (vlib_node_runtime_t * node, vlib_buffer_t * b)
{
  u8 *ptr = vlib_buffer_get_current (b);
  u8 v = *ptr & 0xf0;

  if (PREDICT_TRUE (v == 0x40))
    return VNET_DEVICE_INPUT_NEXT_IP4_NCS_INPUT;
  else if (PREDICT_TRUE (v == 0x60))
    return VNET_DEVICE_INPUT_NEXT_IP6_INPUT;

  b->error = node->errors[MEMIF_INPUT_ERROR_NOT_IP];
  return VNET_DEVICE_INPUT_NEXT_DROP;
}

static_always_inline uword
memif_device_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			   vlib_frame_t * frame, memif_if_t * mif,
			   memif_ring_type_t type, u16 qid,
			   memif_interface_mode_t mode)
{
  vnet_main_t *vnm = vnet_get_main ();
  memif_ring_t *ring;
  memif_queue_t *mq;
  u16 head;
  u32 next_index;
  uword n_trace = vlib_get_trace_count (vm, node);
  memif_main_t *nm = &memif_main;
  u32 n_rx_packets = 0;
  u32 n_rx_bytes = 0;
  u32 *to_next = 0;
  u32 n_free_bufs;
  u32 b0_total, b1_total;
  u32 thread_index = vlib_get_thread_index ();
  u16 ring_size, mask, num_slots;
  u32 n_buffer_bytes = vlib_buffer_free_list_buffer_size (vm,
							  VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);

  mq = vec_elt_at_index (mif->rx_queues, qid);
  ring = mq->ring;
  ring_size = 1 << mq->log2_ring_size;
  mask = ring_size - 1;

  if (mode == MEMIF_INTERFACE_MODE_IP)
    {
      next_index = VNET_DEVICE_INPUT_NEXT_IP6_INPUT;
    }
  else
    {
      next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
    }

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
  if (head == mq->last_head)
    return 0;

  num_slots = head - mq->last_head;

  while (num_slots)
    {
      u32 n_left_to_next;
      u32 next0 = next_index;
      u32 next1 = next_index;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (num_slots > 11 && n_left_to_next > 2)
	{
	  CLIB_PREFETCH (memif_get_buffer
			 (mif, ring, (mq->last_head + 2) & mask),
			 CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (memif_get_buffer
			 (mif, ring, (mq->last_head + 3) & mask),
			 CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (&ring->desc[(mq->last_head + 4) & mask],
			 CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (&ring->desc[(mq->last_head + 5) & mask],
			 CLIB_CACHE_LINE_BYTES, LOAD);

	  vlib_buffer_t *first_b0 = 0;
	  u32 bi0 = 0, first_bi0 = 0;
	  b0_total = memif_copy_buffer_from_rx_ring (vm, mif, ring, mq,
						     ring_size,
						     n_buffer_bytes,
						     &n_free_bufs, &first_b0,
						     &first_bi0, &bi0,
						     &num_slots);

	  vlib_buffer_t *first_b1 = 0;
	  u32 bi1 = 0, first_bi1 = 0;
	  b1_total = memif_copy_buffer_from_rx_ring (vm, mif, ring, mq,
						     ring_size,
						     n_buffer_bytes,
						     &n_free_bufs, &first_b1,
						     &first_bi1, &bi1,
						     &num_slots);

	  /* enqueue buffer */
	  to_next[0] = first_bi0;
	  to_next[1] = first_bi1;
	  to_next += 2;
	  n_left_to_next -= 2;


	  if (mode == MEMIF_INTERFACE_MODE_IP)
	    {
	      next0 = memif_next_from_ip_hdr (node, first_b0);
	      next1 = memif_next_from_ip_hdr (node, first_b1);
	    }
	  else if (mode == MEMIF_INTERFACE_MODE_ETHERNET)
	    {
	      if (PREDICT_FALSE (mif->per_interface_next_index != ~0))
		next0 = next1 = mif->per_interface_next_index;
	      else
		/* redirect if feature path
		 * enabled */
		vnet_feature_start_device_input_x2 (mif->sw_if_index,
						    &next0, &next1,
						    first_b0, first_b1);
	    }

	  /* trace */
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (first_b0);
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (first_b1);

	  if (PREDICT_FALSE (n_trace > 0))
	    {
	      /* b0 */
	      if (PREDICT_TRUE (first_b0 != 0))
		{
		  memif_input_trace_t *tr;
		  vlib_trace_buffer (vm, node, next0, first_b0,
				     /* follow_chain */ 0);
		  vlib_set_trace_count (vm, node, --n_trace);
		  tr = vlib_add_trace (vm, node, first_b0, sizeof (*tr));
		  tr->next_index = next0;
		  tr->hw_if_index = mif->hw_if_index;
		  tr->ring = qid;
		}
	      if (n_trace)
		{
		  /* b1 */
		  if (PREDICT_TRUE (first_b1 != 0))
		    {
		      memif_input_trace_t *tr;
		      vlib_trace_buffer (vm, node, next1, first_b1,
					 /* follow_chain */ 0);
		      vlib_set_trace_count (vm, node, --n_trace);
		      tr = vlib_add_trace (vm, node, first_b1, sizeof (*tr));
		      tr->next_index = next1;
		      tr->hw_if_index = mif->hw_if_index;
		      tr->ring = qid;
		    }
		}
	    }

	  /* enqueue */
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next, first_bi0,
					   first_bi1, next0, next1);

	  /* next packet */
	  n_rx_packets += 2;
	  n_rx_bytes += b0_total + b1_total;
	}
      while (num_slots && n_left_to_next)
	{
	  vlib_buffer_t *first_b0 = 0;
	  u32 bi0 = 0, first_bi0 = 0;
	  b0_total = memif_copy_buffer_from_rx_ring (vm, mif, ring, mq,
						     ring_size,
						     n_buffer_bytes,
						     &n_free_bufs, &first_b0,
						     &first_bi0, &bi0,
						     &num_slots);

	  if (mode == MEMIF_INTERFACE_MODE_IP)
	    {
	      next0 = memif_next_from_ip_hdr (node, first_b0);
	    }
	  else if (mode == MEMIF_INTERFACE_MODE_ETHERNET)
	    {
	      if (PREDICT_FALSE (mif->per_interface_next_index != ~0))
		next0 = mif->per_interface_next_index;
	      else
		/* redirect if feature path
		 * enabled */
		vnet_feature_start_device_input_x1 (mif->sw_if_index,
						    &next0, first_b0);
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
		  tr->hw_if_index = mif->hw_if_index;
		  tr->ring = qid;
		}
	    }

	  /* enqueue buffer */
	  to_next[0] = first_bi0;
	  to_next += 1;
	  n_left_to_next--;

	  /* enqueue */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, first_bi0, next0);

	  /* next packet */
	  n_rx_packets++;
	  n_rx_bytes += b0_total;
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
  u32 n_rx = 0;
  memif_main_t *nm = &memif_main;
  vnet_device_input_runtime_t *rt = (void *) node->runtime_data;
  vnet_device_and_queue_t *dq;

  foreach_device_and_queue (dq, rt->devices_and_queues)
  {
    memif_if_t *mif;
    mif = vec_elt_at_index (nm->interfaces, dq->dev_instance);
    if ((mif->flags & MEMIF_IF_FLAG_ADMIN_UP) &&
	(mif->flags & MEMIF_IF_FLAG_CONNECTED))
      {
	if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
	  {
	    if (mif->mode == MEMIF_INTERFACE_MODE_IP)
	      n_rx += memif_device_input_inline (vm, node, frame, mif,
						 MEMIF_RING_M2S, dq->queue_id,
						 MEMIF_INTERFACE_MODE_IP);
	    else
	      n_rx += memif_device_input_inline (vm, node, frame, mif,
						 MEMIF_RING_M2S, dq->queue_id,
						 MEMIF_INTERFACE_MODE_ETHERNET);
	  }
	else
	  {
	    if (mif->mode == MEMIF_INTERFACE_MODE_IP)
	      n_rx += memif_device_input_inline (vm, node, frame, mif,
						 MEMIF_RING_S2M, dq->queue_id,
						 MEMIF_INTERFACE_MODE_IP);
	    else
	      n_rx += memif_device_input_inline (vm, node, frame, mif,
						 MEMIF_RING_S2M, dq->queue_id,
						 MEMIF_INTERFACE_MODE_ETHERNET);
	  }
      }
  }

  return n_rx;
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
