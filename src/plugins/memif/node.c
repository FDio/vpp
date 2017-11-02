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
  _(BUFFER_ALLOC_FAIL, "buffer allocation failed")		\
  _(NOT_IP, "not ip packet")

typedef enum
{
#define _(f,s) MEMIF_INPUT_ERROR_##f,
  foreach_memif_input_error
#undef _
    MEMIF_INPUT_N_ERROR,
} memif_input_error_t;

static __clib_unused char *memif_input_error_strings[] = {
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

static __clib_unused u8 *
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

static_always_inline u32
memif_prealloc_bufs (vlib_main_t * vm, memif_per_thread_data_t * ptd,
		     u16 ring_size)
{
  u32 n_free_bufs = vec_len (ptd->rx_buffers);
  if (PREDICT_FALSE (n_free_bufs < ring_size))
    {
      vec_validate (ptd->rx_buffers, ring_size + n_free_bufs - 1);
      n_free_bufs += vlib_buffer_alloc (vm, &ptd->rx_buffers[n_free_bufs],
					ring_size);
      _vec_len (ptd->rx_buffers) = n_free_bufs;
    }
  return n_free_bufs;
}

static_always_inline void
memif_trace_buffer (vlib_main_t * vm, vlib_node_runtime_t * node,
		    memif_if_t * mif, vlib_buffer_t * b, u32 next, u16 qid,
		    uword * n_tracep)
{
  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b);

  if (PREDICT_TRUE (b != 0))
    {
      memif_input_trace_t *tr;
      vlib_trace_buffer (vm, node, next, b, /* follow_chain */ 0);
      vlib_set_trace_count (vm, node, --(*n_tracep));
      tr = vlib_add_trace (vm, node, b, sizeof (*tr));
      tr->next_index = next;
      tr->hw_if_index = mif->hw_if_index;
      tr->ring = qid;
    }
}

static_always_inline void
memif_add_copy_op (memif_per_thread_data_t * ptd, void *data, u32 len,
		   u16 buffer_offset, u16 buffer_vec_index)
{
  memif_copy_op_t *co;
  vec_add2_aligned (ptd->copy_ops, co, 1, CLIB_CACHE_LINE_BYTES);
  co->data = data;
  co->data_len = len;
  co->buffer_offset = buffer_offset;
  co->buffer_vec_index = buffer_vec_index;
}

static_always_inline void
memif_add_to_chain (vlib_main_t * vm, vlib_buffer_t * b, u32 * buffers,
		    u32 buffer_size)
{
  vlib_buffer_t *seg = b;
  i32 bytes_left = b->current_length - buffer_size + b->current_data;

  if (PREDICT_TRUE (bytes_left <= 0))
    return;

  b->current_length -= bytes_left;
  b->total_length_not_including_first_buffer = bytes_left;

  while (bytes_left)
    {
      seg->flags |= VLIB_BUFFER_NEXT_PRESENT;
      seg->next_buffer = buffers[0];
      seg = vlib_get_buffer (vm, buffers[0]);
      buffers++;
      seg->current_data = 0;
      seg->current_length = clib_min (buffer_size, bytes_left);
      bytes_left -= seg->current_length;
    }
  //fformat (stderr, "%U\n", format_vnet_buffer, b);
}

static_always_inline uword
memif_device_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			   vlib_frame_t * frame, memif_if_t * mif,
			   u16 qid, memif_interface_mode_t mode,
			   memif_ring_type_t type)
{
  vnet_main_t *vnm = vnet_get_main ();
  memif_ring_t *ring;
  memif_queue_t *mq;
  u16 buffer_size = 2048;
  u32 next_index;
  uword n_trace = vlib_get_trace_count (vm, node);
  u32 n_rx_packets = 0, n_rx_bytes = 0;
  u32 *to_next = 0;
  u32 thread_index = vlib_get_thread_index ();
  memif_per_thread_data_t *ptd = vec_elt_at_index (memif_main.per_thread_data,
						   thread_index);
  u16 cur_slot, last_slot, ring_size, n_slots, mask;
  i16 start_offset;
  u16 n_buffers = 0, n_alloc;
  int i;

  mq = vec_elt_at_index (mif->rx_queues, qid);
  ring = mq->ring;
  ring_size = 1 << mq->log2_ring_size;
  mask = ring_size - 1;

  next_index = (mode == MEMIF_INTERFACE_MODE_IP) ?
    VNET_DEVICE_INPUT_NEXT_IP6_INPUT : VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;

  /* asume that somebody will want to add ethernet header on the packet
     so start with IP header at offset 14 */
  start_offset = (mode == MEMIF_INTERFACE_MODE_IP) ? 14 : 0;


  /* for S2M rings, we are consumers of packet buffers, and for M2S rings we
     are producers of empty buffers */
  cur_slot = (type == MEMIF_RING_S2M) ? mq->last_head : mq->last_tail;
  last_slot = (type == MEMIF_RING_S2M) ? ring->head : ring->tail;
  if (cur_slot == last_slot)
    goto refill;
  n_slots = last_slot - cur_slot;

  /* construct copy and packet vector out of ring slots */
  while (n_slots)
    {
      u32 dst_off, src_off, n_bytes_left;
      u16 s0;
      memif_desc_t *d0;
      void *mb0;
      memif_packet_op_t *po;
      vec_add2_aligned (ptd->packet_ops, po, 1, CLIB_CACHE_LINE_BYTES);
      po->first_buffer_vec_index = n_buffers++;
      po->packet_len = 0;
      src_off = 0;
      dst_off = start_offset;

    next_slot:
      s0 = cur_slot & mask;
      d0 = &ring->desc[s0];
      n_bytes_left = d0->length;
      po->packet_len += n_bytes_left;
      mb0 = memif_get_buffer (mif, ring, s0);

      do
	{
	  u32 dst_free = buffer_size - dst_off;
	  if (dst_free == 0)
	    {
	      dst_off = 0;
	      dst_free = buffer_size;
	      n_buffers++;
	    }
	  u32 bytes_to_copy = clib_min (dst_free, n_bytes_left);
	  memif_add_copy_op (ptd, mb0 + src_off, bytes_to_copy, dst_off,
			     n_buffers - 1);
	  n_bytes_left -= bytes_to_copy;
	  src_off += bytes_to_copy;
	  dst_off += bytes_to_copy;
	}
      while (PREDICT_FALSE (n_bytes_left));

      cur_slot++;
      n_slots--;
      if ((d0->flags & MEMIF_DESC_FLAG_NEXT) && n_slots)
	{
	  src_off = 0;
	  goto next_slot;
	}
    }

  /* allocate free buffers */
  vec_validate_aligned (ptd->buffers, n_buffers - 1, CLIB_CACHE_LINE_BYTES);
  n_alloc = vlib_buffer_alloc (vm, ptd->buffers, n_buffers);
  if (PREDICT_FALSE (n_alloc != n_buffers))
    {
      if (n_alloc)
	vlib_buffer_free (vm, ptd->buffers, n_alloc);
      vlib_error_count (vm, node->node_index,
			MEMIF_INPUT_ERROR_BUFFER_ALLOC_FAIL, 1);
      goto refill;
    }

  /* copy data */
  vec_foreach_index (i, ptd->copy_ops)
  {
    memif_copy_op_t *co = vec_elt_at_index (ptd->copy_ops, i);
    u32 bi = ptd->buffers[co->buffer_vec_index];
    vlib_buffer_t *b = vlib_get_buffer (vm, bi);
    clib_memcpy (b->data + co->buffer_offset, co->data, co->data_len);
#if 0
    fformat (stderr, "index %u data %p len %u bvi %u offset %u\n", i,
	     co->data, co->data_len, co->buffer_vec_index, co->buffer_offset);
#endif

  }

#if 0
  vec_foreach_index (i, ptd->packet_ops)
  {
    memif_packet_op_t *po = vec_elt_at_index (ptd->packet_ops, i);
    fformat (stderr, "index %u n_buffers %u first_bvi %u, len %u\n", i,
	     po->n_add_buffers, po->first_buffer_vec_index, po->packet_len);
  }
#endif

  /* release slots from the ring */
  if (type == MEMIF_RING_S2M)
    {
      CLIB_MEMORY_STORE_BARRIER ();
      ring->tail = mq->last_head = cur_slot;
    }
  else
    {
      mq->last_tail = cur_slot;
    }

  u32 n_from = n_rx_packets = vec_len (ptd->packet_ops);
  memif_packet_op_t *po = ptd->packet_ops;

  while (n_from)
    {
      u32 n_left_to_next;
      u32 next0 = next_index;
      u32 bi0;
      vlib_buffer_t *b0;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_from && n_left_to_next)
	{
	  /* enqueue buffer */
	  u32 fbvi = po->first_buffer_vec_index;
	  bi0 = ptd->buffers[fbvi];
	  b0 = vlib_get_buffer (vm, bi0);
	  to_next[0] = bi0;
	  to_next += 1;
	  n_left_to_next--;

	  b0->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
	  b0->total_length_not_including_first_buffer = 0;
	  b0->current_data = start_offset;
	  b0->current_length = po->packet_len;
	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = mif->sw_if_index;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;

	  memif_add_to_chain (vm, b0, ptd->buffers + fbvi + 1, buffer_size);

	  if (mode == MEMIF_INTERFACE_MODE_IP)
	    {
	      next0 = memif_next_from_ip_hdr (node, b0);
	    }
	  else if (mode == MEMIF_INTERFACE_MODE_ETHERNET)
	    {
	      if (PREDICT_FALSE (mif->per_interface_next_index != ~0))
		next0 = mif->per_interface_next_index;
	      else
		/* redirect if feature path enabled */
		vnet_feature_start_device_input_x1 (mif->sw_if_index,
						    &next0, b0);
	    }

	  /* trace */
	  if (PREDICT_FALSE (n_trace > 0))
	    memif_trace_buffer (vm, node, mif, b0, next0, qid, &n_trace);

	  /* enqueue */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);

	  /* next */
	  n_from--;
	  po++;
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_increment_combined_counter (vnm->interface_main.combined_sw_if_counters
				   + VNET_INTERFACE_COUNTER_RX, thread_index,
				   mif->hw_if_index, n_rx_packets,
				   n_rx_bytes);

  /* refill ring with empty buffers */
refill:
  vec_reset_length (ptd->enq_buffers);
  vec_reset_length (ptd->buffers);
  vec_reset_length (ptd->packet_ops);
  vec_reset_length (ptd->copy_ops);

  if (type == MEMIF_RING_M2S)
    {
      u16 head = ring->head;
      n_slots = ring_size - head + mq->last_tail;
      head += n_slots;
      CLIB_MEMORY_STORE_BARRIER ();
      ring->head = head;
    }

  return n_rx_packets;
}

uword
CLIB_MULTIARCH_FN (memif_input_fn) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
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
						 dq->queue_id,
						 MEMIF_INTERFACE_MODE_IP,
						 MEMIF_RING_M2S);
	    else
	      n_rx += memif_device_input_inline (vm, node, frame, mif,
						 dq->queue_id,
						 MEMIF_INTERFACE_MODE_ETHERNET,
						 MEMIF_RING_M2S);
	  }
	else
	  {
	    if (mif->mode == MEMIF_INTERFACE_MODE_IP)
	      n_rx += memif_device_input_inline (vm, node, frame, mif,
						 dq->queue_id,
						 MEMIF_INTERFACE_MODE_IP,
						 MEMIF_RING_S2M);
	    else
	      n_rx += memif_device_input_inline (vm, node, frame, mif,
						 dq->queue_id,
						 MEMIF_INTERFACE_MODE_ETHERNET,
						 MEMIF_RING_S2M);
	  }
      }
  }

  return n_rx;
}

#ifndef CLIB_MULTIARCH_VARIANT
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

vlib_node_function_t __clib_weak memif_input_fn_avx512;
vlib_node_function_t __clib_weak memif_input_fn_avx2;

#if __x86_64__
static void __clib_constructor
memif_input_multiarch_select (void)
{
  if (memif_input_fn_avx512 && clib_cpu_supports_avx512f ())
    memif_input_node.function = memif_input_fn_avx512;
  else if (memif_input_fn_avx2 && clib_cpu_supports_avx2 ())
    memif_input_node.function = memif_input_fn_avx2;
}
#endif
#endif

/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
