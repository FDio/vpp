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
#include <vnet/interface/rx_queue_funcs.h>
#include <vnet/feature/feature.h>

#include <memif/memif.h>
#include <memif/private.h>

#define MEMIF_IP_OFFSET 14

#define foreach_memif_input_error                                             \
  _ (BUFFER_ALLOC_FAIL, buffer_alloc, ERROR, "buffer allocation failed")      \
  _ (BAD_DESC, bad_desc, ERROR, "bad descriptor")                             \
  _ (NOT_IP, not_ip, INFO, "not ip packet")

typedef enum
{
#define _(f, n, s, d) MEMIF_INPUT_ERROR_##f,
  foreach_memif_input_error
#undef _
    MEMIF_INPUT_N_ERROR,
} memif_input_error_t;

static vlib_error_desc_t memif_input_error_counters[] = {
#define _(f, n, s, d) { #n, d, VL_COUNTER_SEVERITY_##s },
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

static_always_inline void
memif_trace_buffer (vlib_main_t * vm, vlib_node_runtime_t * node,
		    memif_if_t * mif, vlib_buffer_t * b, u32 next, u16 qid,
		    uword * n_tracep)
{
  if (PREDICT_TRUE
      (b != 0 && vlib_trace_buffer (vm, node, next, b, /* follow_chain */ 0)))
    {
      memif_input_trace_t *tr;
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
}

static_always_inline u16
memif_parse_desc (memif_per_thread_data_t *ptd, memif_if_t *mif,
		  memif_queue_t *mq, u16 next, u16 n_avail)
{
  memif_ring_t *ring = mq->ring;
  memif_desc_t *descs = ring->desc;
  void **desc_data = ptd->desc_data;
  u16 *desc_len = ptd->desc_len;
  memif_desc_status_t *desc_status = ptd->desc_status;
  u16 n_desc = 0, n_pkts = 0;
  u32 i = 0;
  u16 mask = pow2_mask (mq->log2_ring_size);
  memif_desc_t *d = 0;
  u32 slot = next;

  while (i < n_avail)
    {
      u8 flags;
      d = descs + (slot++ & mask);
      desc_data[i] = (void *) ((u64) d->region << 32 | d->offset);
      desc_len[i] = d->length;
      desc_status[i].as_u8 = flags = d->flags;
      i++;
      if (PREDICT_FALSE ((flags & MEMIF_DESC_FLAG_NEXT)) == 0)
	{
	  n_desc = i;
	  if (++n_pkts == MEMIF_RX_VECTOR_SZ)
	    goto frame_full;
	}
    }
frame_full:

  /* done */
  ptd->n_packets = n_pkts;
  return n_desc;
}

static_always_inline void
memif_desc_status_set_err (memif_desc_status_t *p,
			   memif_desc_status_err_code_t e)
{
  memif_desc_status_t s = { .err = 1, .err_code = e };
  p->as_u8 |= s.as_u8;
}

static_always_inline void
memif_validate_desc_data (memif_per_thread_data_t *ptd, memif_if_t *mif,
			  u16 n_desc, int is_ethernet)
{
  void **desc_data = ptd->desc_data;
  u16 *desc_len = ptd->desc_len;
  memif_desc_status_t *desc_status = ptd->desc_status;
  u16 n_regions = vec_len (mif->regions);
  u32 n_rx_bytes = 0;
  u16 max_len = 0;
  u8 xor_status = 0;

  for (u32 i = 0; i < n_desc; i++)
    {
      u16 region = ((u64) desc_data[i]) >> 32;
      u32 offset = (u64) desc_data[i];
      u16 len = desc_len[i];
      memif_region_t *r = mif->regions + region;

      if (region >= n_regions)
	memif_desc_status_set_err (desc_status + i,
				   MEMIF_DESC_STATUS_ERR_BAD_REGION);
      else if (offset + len > r->region_size)
	memif_desc_status_set_err (desc_status + i,
				   MEMIF_DESC_STATUS_ERR_REGION_OVERRUN);
      else if (is_ethernet && len > ETHERNET_MAX_PACKET_BYTES)
	memif_desc_status_set_err (desc_status + i,
				   MEMIF_DESC_STATUS_ERR_DATA_TOO_BIG);
      else if (len == 0)
	memif_desc_status_set_err (desc_status + i,
				   MEMIF_DESC_STATUS_ERR_ZERO_LENGTH);
      else
	{
	  desc_data[i] = r->shm + offset;
	  if (len > max_len)
	    max_len = len;
	  n_rx_bytes += len;
	}
      xor_status |= desc_status[i].as_u8;
    }

  ptd->max_desc_len = max_len;
  ptd->xor_status = xor_status;
  ptd->n_rx_bytes = n_rx_bytes;
}

static_always_inline u32
memif_process_desc (vlib_main_t *vm, vlib_node_runtime_t *node,
		    memif_per_thread_data_t *ptd, memif_if_t *mif)
{
  u16 buffer_size = vlib_buffer_get_default_data_size (vm);
  int is_ip = mif->mode == MEMIF_INTERFACE_MODE_IP;
  i16 start_offset = (is_ip) ? MEMIF_IP_OFFSET : 0;
  memif_packet_op_t *po = ptd->packet_ops;
  void **desc_data = ptd->desc_data;
  u16 *desc_len = ptd->desc_len;
  memif_desc_status_t *desc_status = ptd->desc_status;
  u32 n_buffers = 0;
  u32 n_left = ptd->n_packets;
  u32 packet_len;
  int i = -1;
  int bad_packets = 0;

  /* construct copy and packet vector out of ring slots */
  while (n_left)
    {
      u32 dst_off, src_off, n_bytes_left;
      void *mb0;
      po->first_buffer_vec_index = n_buffers++;

      packet_len = 0;
      src_off = 0;
      dst_off = start_offset;

    next_slot:
      i++; /* next descriptor */
      n_bytes_left = desc_len[i];

      packet_len += n_bytes_left;
      mb0 = desc_data[i];

      if (PREDICT_FALSE (desc_status[i].err))
	{
	  vlib_error_count (vm, node->node_index, MEMIF_INPUT_ERROR_BAD_DESC,
			    1);
	  bad_packets++;
	  ASSERT (n_buffers > 0);
	  n_buffers--;
	  goto next_packet;
	}
      else
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

      if (desc_status[i].next)
	{
	  src_off = 0;
	  goto next_slot;
	}

      /* update packet op */
      po->packet_len = packet_len;
      po++;

    next_packet:
      /* next packet */
      n_left--;
    }
  ASSERT (ptd->n_packets >= bad_packets);
  ptd->n_packets -= bad_packets;
  return n_buffers;
}
static_always_inline void
memif_fill_buffer_mdata_simple (vlib_node_runtime_t *node,
				memif_per_thread_data_t *ptd,
				vlib_buffer_t **b, u16 *next, int is_ip)
{
  vlib_buffer_t bt;
  u16 *dl = ptd->desc_len;
  /* process buffer metadata */

  u32 n_left = ptd->n_packets;

  /* copy template into local variable - will save per packet load */
  vlib_buffer_copy_template (&bt, &ptd->buffer_template);

  while (n_left >= 8)
    {
      vlib_prefetch_buffer_header (b[4], STORE);
      vlib_prefetch_buffer_header (b[5], STORE);
      vlib_prefetch_buffer_header (b[6], STORE);
      vlib_prefetch_buffer_header (b[7], STORE);

      vlib_buffer_copy_template (b[0], &bt);
      vlib_buffer_copy_template (b[1], &bt);
      vlib_buffer_copy_template (b[2], &bt);
      vlib_buffer_copy_template (b[3], &bt);

      b[0]->current_length = dl[0];
      b[1]->current_length = dl[1];
      b[2]->current_length = dl[2];
      b[3]->current_length = dl[3];

      if (is_ip)
	{
	  next[0] = memif_next_from_ip_hdr (node, b[0]);
	  next[1] = memif_next_from_ip_hdr (node, b[1]);
	  next[2] = memif_next_from_ip_hdr (node, b[2]);
	  next[3] = memif_next_from_ip_hdr (node, b[3]);
	}

      /* next */
      n_left -= 4;
      b += 4;
      dl += 4;
      next += 4;
    }

  while (n_left)
    {
      /* enqueue buffer */
      vlib_buffer_copy_template (b[0], &bt);
      b[0]->current_length = dl[0];
      if (is_ip)
	next[0] = memif_next_from_ip_hdr (node, b[0]);

      /* next */
      n_left -= 1;
      b += 1;
      dl += 1;
      next += 1;
    }
}

static_always_inline void
memif_fill_buffer_mdata (vlib_main_t *vm, vlib_node_runtime_t *node,
			 memif_per_thread_data_t *ptd, memif_if_t *mif,
			 u32 *bi, u16 *next, int is_ip)
{
  u16 buffer_size = vlib_buffer_get_default_data_size (vm);
  vlib_buffer_t *b0, *b1, *b2, *b3, bt;
  memif_packet_op_t *po;
  /* process buffer metadata */

  u32 n_from = ptd->n_packets;
  po = ptd->packet_ops;

  /* copy template into local variable - will save per packet load */
  vlib_buffer_copy_template (&bt, &ptd->buffer_template);

  while (n_from >= 8)
    {
      b0 = vlib_get_buffer (vm, ptd->buffers[po[4].first_buffer_vec_index]);
      b1 = vlib_get_buffer (vm, ptd->buffers[po[5].first_buffer_vec_index]);
      b2 = vlib_get_buffer (vm, ptd->buffers[po[6].first_buffer_vec_index]);
      b3 = vlib_get_buffer (vm, ptd->buffers[po[7].first_buffer_vec_index]);

      vlib_prefetch_buffer_header (b0, STORE);
      vlib_prefetch_buffer_header (b1, STORE);
      vlib_prefetch_buffer_header (b2, STORE);
      vlib_prefetch_buffer_header (b3, STORE);

      /* enqueue buffer */
      u32 fbvi[4];
      fbvi[0] = po[0].first_buffer_vec_index;
      fbvi[1] = po[1].first_buffer_vec_index;
      fbvi[2] = po[2].first_buffer_vec_index;
      fbvi[3] = po[3].first_buffer_vec_index;

      bi[0] = ptd->buffers[fbvi[0]];
      bi[1] = ptd->buffers[fbvi[1]];
      bi[2] = ptd->buffers[fbvi[2]];
      bi[3] = ptd->buffers[fbvi[3]];

      b0 = vlib_get_buffer (vm, bi[0]);
      b1 = vlib_get_buffer (vm, bi[1]);
      b2 = vlib_get_buffer (vm, bi[2]);
      b3 = vlib_get_buffer (vm, bi[3]);

      vlib_buffer_copy_template (b0, &bt);
      vlib_buffer_copy_template (b1, &bt);
      vlib_buffer_copy_template (b2, &bt);
      vlib_buffer_copy_template (b3, &bt);

      b0->current_length = po[0].packet_len;
      b1->current_length = po[1].packet_len;
      b2->current_length = po[2].packet_len;
      b3->current_length = po[3].packet_len;

      memif_add_to_chain (vm, b0, ptd->buffers + fbvi[0] + 1, buffer_size);
      memif_add_to_chain (vm, b1, ptd->buffers + fbvi[1] + 1, buffer_size);
      memif_add_to_chain (vm, b2, ptd->buffers + fbvi[2] + 1, buffer_size);
      memif_add_to_chain (vm, b3, ptd->buffers + fbvi[3] + 1, buffer_size);

      if (is_ip)
	{
	  next[0] = memif_next_from_ip_hdr (node, b0);
	  next[1] = memif_next_from_ip_hdr (node, b1);
	  next[2] = memif_next_from_ip_hdr (node, b2);
	  next[3] = memif_next_from_ip_hdr (node, b3);
	}

      /* next */
      n_from -= 4;
      po += 4;
      bi += 4;
      next += 4;
    }
  while (n_from)
    {
      u32 fbvi[1];
      /* enqueue buffer */
      fbvi[0] = po[0].first_buffer_vec_index;
      bi[0] = ptd->buffers[fbvi[0]];
      b0 = vlib_get_buffer (vm, bi[0]);
      vlib_buffer_copy_template (b0, &bt);
      b0->current_length = po->packet_len;

      memif_add_to_chain (vm, b0, ptd->buffers + fbvi[0] + 1, buffer_size);

      if (is_ip)
	next[0] = memif_next_from_ip_hdr (node, b0);

      /* next */
      n_from -= 1;
      po += 1;
      bi += 1;
      next += 1;
    }
}

static_always_inline void
memif_advance_ring (memif_ring_type_t type, memif_queue_t *mq,
		    memif_ring_t *ring, u16 cur_slot)
{
  if (type == MEMIF_RING_S2M)
    {
      __atomic_store_n (&ring->tail, cur_slot, __ATOMIC_RELEASE);
      mq->last_head = cur_slot;
    }
  else
    {
      mq->last_tail = cur_slot;
    }
}

static_always_inline uword
memif_device_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			   memif_if_t *mif, memif_ring_type_t type, u16 qid,
			   memif_interface_mode_t mode)
{
  vnet_main_t *vnm = vnet_get_main ();
  memif_main_t *mm = &memif_main;
  memif_ring_t *ring;
  memif_queue_t *mq;
  u16 buffer_size = vlib_buffer_get_default_data_size (vm);
  uword n_trace;
  u16 nexts[MEMIF_RX_VECTOR_SZ], *next = nexts;
  u32 _to_next_bufs[MEMIF_RX_VECTOR_SZ], *to_next_bufs = _to_next_bufs, *bi;
  u32 n_left_to_next;
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  vlib_buffer_t *buffer_ptrs[MEMIF_RX_VECTOR_SZ];
  u32 thread_index = vm->thread_index;
  memif_per_thread_data_t *ptd =
    vec_elt_at_index (mm->per_thread_data, thread_index);
  u16 cur_slot, ring_size, n_slots, mask;
  u16 n_buffers, n_alloc, n_desc;
  i16 start_offset;
  memif_copy_op_t *co;
  int is_slave = (mif->flags & MEMIF_IF_FLAG_IS_SLAVE) != 0;
  int is_simple = 1;
  int i;

  mq = vec_elt_at_index (mif->rx_queues, qid);
  ring = mq->ring;
  ring_size = 1 << mq->log2_ring_size;
  mask = ring_size - 1;

  start_offset = (mode == MEMIF_INTERFACE_MODE_IP) ? MEMIF_IP_OFFSET : 0;

  if (is_slave)
    {
      cur_slot = mq->last_tail;
      n_slots = __atomic_load_n (&ring->tail, __ATOMIC_ACQUIRE) - cur_slot;
    }
  else
    {
      cur_slot = mq->last_head;
      n_slots = __atomic_load_n (&ring->head, __ATOMIC_ACQUIRE) - cur_slot;
    }

  if (n_slots == 0)
    goto refill;

  n_desc = memif_parse_desc (ptd, mif, mq, cur_slot, n_slots);

  if (n_desc != ptd->n_packets)
    is_simple = 0;

  cur_slot += n_desc;

  if (mif->mode == MEMIF_INTERFACE_MODE_ETHERNET)
    memif_validate_desc_data (ptd, mif, n_desc, /* is_ethernet */ 1);
  else
    memif_validate_desc_data (ptd, mif, n_desc, /* is_ethernet */ 0);

  if (ptd->max_desc_len > buffer_size - start_offset)
    is_simple = 0;

  if (ptd->xor_status != 0)
    is_simple = 0;

  if (is_simple)
    n_buffers = ptd->n_packets;
  else
    n_buffers = memif_process_desc (vm, node, ptd, mif);

  if (PREDICT_FALSE (n_buffers == 0))
    {
      /* All descriptors are bad. Release slots in the ring and bail */
      memif_advance_ring (type, mq, ring, cur_slot);
      goto refill;
    }

  /* allocate free buffers */
  vec_validate_aligned (ptd->buffers, n_buffers - 1, CLIB_CACHE_LINE_BYTES);
  n_alloc = vlib_buffer_alloc_from_pool (vm, ptd->buffers, n_buffers,
					 mq->buffer_pool_index);
  if (PREDICT_FALSE (n_alloc != n_buffers))
    {
      if (n_alloc)
	vlib_buffer_free (vm, ptd->buffers, n_alloc);
      vlib_error_count (vm, node->node_index,
			MEMIF_INPUT_ERROR_BUFFER_ALLOC_FAIL, 1);
      goto refill;
    }

  /* copy data */
  if (is_simple)
    {
      int n_pkts = ptd->n_packets;
      void **desc_data = ptd->desc_data;
      u16 *desc_len = ptd->desc_len;

      vlib_get_buffers (vm, ptd->buffers, buffer_ptrs, n_buffers);

      for (i = 0; i + 8 < n_pkts; i++)
	{
	  clib_prefetch_load (desc_data[i + 8]);
	  clib_prefetch_store (buffer_ptrs[i + 8]->data);
	  clib_memcpy_fast (buffer_ptrs[i]->data + start_offset, desc_data[i],
			    desc_len[i]);
	}
      for (; i < n_pkts; i++)
	clib_memcpy_fast (buffer_ptrs[i]->data + start_offset, desc_data[i],
			  desc_len[i]);
    }
  else
    {
      vlib_buffer_t *b;
      u32 n_pkts = vec_len (ptd->copy_ops);
      co = ptd->copy_ops;

      for (i = 0; i + 8 < n_pkts; i++)
	{
	  clib_prefetch_load (co[i + 8].data);
	  b = vlib_get_buffer (vm, ptd->buffers[co[i].buffer_vec_index]);
	  clib_memcpy_fast (b->data + co[i].buffer_offset, co[i].data,
			    co[i].data_len);
	}
      for (; i < n_pkts; i++)
	{
	  b = vlib_get_buffer (vm, ptd->buffers[co[i].buffer_vec_index]);
	  clib_memcpy_fast (b->data + co[i].buffer_offset, co[i].data,
			    co[i].data_len);
	}
    }

  /* release slots from the ring */
  memif_advance_ring (type, mq, ring, cur_slot);

  /* prepare buffer template and next indices */
  vnet_buffer (&ptd->buffer_template)->sw_if_index[VLIB_RX] = mif->sw_if_index;
  vnet_buffer (&ptd->buffer_template)->feature_arc_index = 0;
  ptd->buffer_template.current_data = start_offset;
  ptd->buffer_template.current_config_index = 0;
  ptd->buffer_template.buffer_pool_index = mq->buffer_pool_index;
  ptd->buffer_template.ref_count = 1;

  if (mode == MEMIF_INTERFACE_MODE_ETHERNET)
    {
      next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
      if (mif->per_interface_next_index != ~0)
	next_index = mif->per_interface_next_index;
      else
	vnet_feature_start_device_input_x1 (mif->sw_if_index, &next_index,
					    &ptd->buffer_template);

      vlib_get_new_next_frame (vm, node, next_index, to_next_bufs,
			       n_left_to_next);
      if (PREDICT_TRUE (next_index == VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT))
	{
	  vlib_next_frame_t *nf;
	  vlib_frame_t *f;
	  ethernet_input_frame_t *ef;
	  nf = vlib_node_runtime_get_next_frame (vm, node, next_index);
	  f = vlib_get_frame (vm, nf->frame);
	  f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;

	  ef = vlib_frame_scalar_args (f);
	  ef->sw_if_index = mif->sw_if_index;
	  ef->hw_if_index = mif->hw_if_index;
	  vlib_frame_no_append (f);
	}
    }

  if (is_simple)
    {
      vlib_buffer_copy_indices (to_next_bufs, ptd->buffers, ptd->n_packets);
      if (mode == MEMIF_INTERFACE_MODE_IP)
	memif_fill_buffer_mdata_simple (node, ptd, buffer_ptrs, nexts, 1);
      else
	memif_fill_buffer_mdata_simple (node, ptd, buffer_ptrs, nexts, 0);
    }
  else
    {
      if (mode == MEMIF_INTERFACE_MODE_IP)
	memif_fill_buffer_mdata (vm, node, ptd, mif, to_next_bufs, nexts, 1);
      else
	memif_fill_buffer_mdata (vm, node, ptd, mif, to_next_bufs, nexts, 0);
    }

  /* packet trace if enabled */
  if (PREDICT_FALSE ((n_trace = vlib_get_trace_count (vm, node))))
    {
      u32 n_left = ptd->n_packets;
      bi = to_next_bufs;
      next = nexts;
      u32 ni = next_index;
      while (n_trace && n_left)
	{
	  vlib_buffer_t *b;
	  memif_input_trace_t *tr;
	  if (mode != MEMIF_INTERFACE_MODE_ETHERNET)
	    ni = next[0];
	  b = vlib_get_buffer (vm, bi[0]);
	  if (PREDICT_TRUE
	      (vlib_trace_buffer (vm, node, ni, b, /* follow_chain */ 0)))
	    {
	      tr = vlib_add_trace (vm, node, b, sizeof (*tr));
	      tr->next_index = ni;
	      tr->hw_if_index = mif->hw_if_index;
	      tr->ring = qid;
	      n_trace--;
	    }

	  /* next */
	  n_left--;
	  bi++;
	  next++;
	}
      vlib_set_trace_count (vm, node, n_trace);
    }

  if (mode == MEMIF_INTERFACE_MODE_ETHERNET)
    {
      n_left_to_next -= ptd->n_packets;
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  else
    vlib_buffer_enqueue_to_next (vm, node, to_next_bufs, nexts,
				 ptd->n_packets);

  vlib_increment_combined_counter (
    vnm->interface_main.combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
    thread_index, mif->sw_if_index, ptd->n_packets, ptd->n_rx_bytes);

  /* refill ring with empty buffers */
refill:
  vec_reset_length (ptd->buffers);
  vec_reset_length (ptd->copy_ops);

  if (type == MEMIF_RING_M2S)
    {
      u16 head = ring->head;
      n_slots = ring_size - head + mq->last_tail;

      while (n_slots--)
	{
	  u16 s = head++ & mask;
	  memif_desc_t *d = &ring->desc[s];
	  d->length = mif->run.buffer_size;
	}
      __atomic_store_n (&ring->head, head, __ATOMIC_RELEASE);
    }

  return ptd->n_packets;
}

static_always_inline uword
memif_device_input_zc_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			      memif_if_t *mif, u16 qid,
			      memif_interface_mode_t mode)
{
  vnet_main_t *vnm = vnet_get_main ();
  memif_main_t *mm = &memif_main;
  memif_ring_t *ring;
  memif_queue_t *mq;
  u32 next_index;
  uword n_trace = vlib_get_trace_count (vm, node);
  u32 n_rx_packets = 0, n_rx_bytes = 0;
  u32 *to_next = 0, *buffers;
  u32 bi0, bi1, bi2, bi3;
  u16 slot, s0;
  memif_desc_t *d0;
  vlib_buffer_t *b0, *b1, *b2, *b3;
  u32 thread_index = vm->thread_index;
  memif_per_thread_data_t *ptd = vec_elt_at_index (mm->per_thread_data,
						   thread_index);
  u16 cur_slot, last_slot, ring_size, n_slots, mask, head;
  i16 start_offset;
  u64 offset;
  u32 buffer_length;
  u16 n_alloc, n_from;

  mq = vec_elt_at_index (mif->rx_queues, qid);
  ring = mq->ring;
  ring_size = 1 << mq->log2_ring_size;
  mask = ring_size - 1;

  next_index = (mode == MEMIF_INTERFACE_MODE_IP) ?
    VNET_DEVICE_INPUT_NEXT_IP6_INPUT : VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;

  /* asume that somebody will want to add ethernet header on the packet
     so start with IP header at offset 14 */
  start_offset = (mode == MEMIF_INTERFACE_MODE_IP) ? 14 : 0;
  buffer_length = vlib_buffer_get_default_data_size (vm) - start_offset;

  cur_slot = mq->last_tail;
  last_slot = __atomic_load_n (&ring->tail, __ATOMIC_ACQUIRE);
  if (cur_slot == last_slot)
    goto refill;
  n_slots = last_slot - cur_slot;

  /* process ring slots */
  vec_validate_aligned (ptd->buffers, MEMIF_RX_VECTOR_SZ,
			CLIB_CACHE_LINE_BYTES);
  while (n_slots && n_rx_packets < MEMIF_RX_VECTOR_SZ)
    {
      vlib_buffer_t *hb;

      s0 = cur_slot & mask;
      bi0 = mq->buffers[s0];
      ptd->buffers[n_rx_packets++] = bi0;

      clib_prefetch_load (&ring->desc[(cur_slot + 8) & mask]);
      d0 = &ring->desc[s0];
      hb = b0 = vlib_get_buffer (vm, bi0);
      b0->current_data = start_offset;
      b0->current_length = d0->length;
      n_rx_bytes += d0->length;

      cur_slot++;
      n_slots--;
      if (PREDICT_FALSE ((d0->flags & MEMIF_DESC_FLAG_NEXT) && n_slots))
	{
	  hb->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
	  hb->total_length_not_including_first_buffer = 0;
	next_slot:
	  s0 = cur_slot & mask;
	  d0 = &ring->desc[s0];
	  bi0 = mq->buffers[s0];

	  /* previous buffer */
	  b0->next_buffer = bi0;
	  b0->flags |= VLIB_BUFFER_NEXT_PRESENT;

	  /* current buffer */
	  b0 = vlib_get_buffer (vm, bi0);
	  b0->current_data = start_offset;
	  b0->current_length = d0->length;
	  hb->total_length_not_including_first_buffer += d0->length;
	  n_rx_bytes += d0->length;

	  cur_slot++;
	  n_slots--;
	  if ((d0->flags & MEMIF_DESC_FLAG_NEXT) && n_slots)
	    goto next_slot;
	}
    }

  /* release slots from the ring */
  mq->last_tail = cur_slot;

  n_from = n_rx_packets;
  buffers = ptd->buffers;

  while (n_from)
    {
      u32 n_left_to_next;
      u32 next0, next1, next2, next3;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_from >= 8 && n_left_to_next >= 4)
	{
	  b0 = vlib_get_buffer (vm, buffers[4]);
	  b1 = vlib_get_buffer (vm, buffers[5]);
	  b2 = vlib_get_buffer (vm, buffers[6]);
	  b3 = vlib_get_buffer (vm, buffers[7]);
	  vlib_prefetch_buffer_header (b0, STORE);
	  vlib_prefetch_buffer_header (b1, STORE);
	  vlib_prefetch_buffer_header (b2, STORE);
	  vlib_prefetch_buffer_header (b3, STORE);

	  /* enqueue buffer */
	  to_next[0] = bi0 = buffers[0];
	  to_next[1] = bi1 = buffers[1];
	  to_next[2] = bi2 = buffers[2];
	  to_next[3] = bi3 = buffers[3];
	  to_next += 4;
	  n_left_to_next -= 4;
	  buffers += 4;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  b2 = vlib_get_buffer (vm, bi2);
	  b3 = vlib_get_buffer (vm, bi3);

	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = mif->sw_if_index;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = ~0;
	  vnet_buffer (b1)->sw_if_index[VLIB_RX] = mif->sw_if_index;
	  vnet_buffer (b1)->sw_if_index[VLIB_TX] = ~0;
	  vnet_buffer (b2)->sw_if_index[VLIB_RX] = mif->sw_if_index;
	  vnet_buffer (b2)->sw_if_index[VLIB_TX] = ~0;
	  vnet_buffer (b3)->sw_if_index[VLIB_RX] = mif->sw_if_index;
	  vnet_buffer (b3)->sw_if_index[VLIB_TX] = ~0;

	  if (mode == MEMIF_INTERFACE_MODE_IP)
	    {
	      next0 = memif_next_from_ip_hdr (node, b0);
	      next1 = memif_next_from_ip_hdr (node, b1);
	      next2 = memif_next_from_ip_hdr (node, b2);
	      next3 = memif_next_from_ip_hdr (node, b3);
	    }
	  else if (mode == MEMIF_INTERFACE_MODE_ETHERNET)
	    {
	      if (PREDICT_FALSE (mif->per_interface_next_index != ~0))
		{
		  next0 = mif->per_interface_next_index;
		  next1 = mif->per_interface_next_index;
		  next2 = mif->per_interface_next_index;
		  next3 = mif->per_interface_next_index;
		}
	      else
		{
		  next0 = next1 = next2 = next3 = next_index;
		  /* redirect if feature path enabled */
		  vnet_feature_start_device_input_x1 (mif->sw_if_index,
						      &next0, b0);
		  vnet_feature_start_device_input_x1 (mif->sw_if_index,
						      &next1, b1);
		  vnet_feature_start_device_input_x1 (mif->sw_if_index,
						      &next2, b2);
		  vnet_feature_start_device_input_x1 (mif->sw_if_index,
						      &next3, b3);
		}
	    }

	  /* trace */
	  if (PREDICT_FALSE (n_trace > 0))
	    {
	      memif_trace_buffer (vm, node, mif, b0, next0, qid, &n_trace);
	      if (PREDICT_FALSE (n_trace > 0))
		memif_trace_buffer (vm, node, mif, b1, next1, qid, &n_trace);
	      if (PREDICT_FALSE (n_trace > 0))
		memif_trace_buffer (vm, node, mif, b2, next2, qid, &n_trace);
	      if (PREDICT_FALSE (n_trace > 0))
		memif_trace_buffer (vm, node, mif, b3, next3, qid, &n_trace);
	    }

	  /* enqueue */
	  vlib_validate_buffer_enqueue_x4 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, bi2, bi3,
					   next0, next1, next2, next3);

	  /* next */
	  n_from -= 4;
	}
      while (n_from && n_left_to_next)
	{
	  /* enqueue buffer */
	  to_next[0] = bi0 = buffers[0];
	  to_next += 1;
	  n_left_to_next--;
	  buffers += 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = mif->sw_if_index;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = ~0;

	  if (mode == MEMIF_INTERFACE_MODE_IP)
	    {
	      next0 = memif_next_from_ip_hdr (node, b0);
	    }
	  else if (mode == MEMIF_INTERFACE_MODE_ETHERNET)
	    {
	      if (PREDICT_FALSE (mif->per_interface_next_index != ~0))
		next0 = mif->per_interface_next_index;
	      else
		{
		  next0 = next_index;
		  /* redirect if feature path enabled */
		  vnet_feature_start_device_input_x1 (mif->sw_if_index,
						      &next0, b0);
		}
	    }

	  /* trace */
	  if (PREDICT_FALSE (n_trace > 0))
	    memif_trace_buffer (vm, node, mif, b0, next0, qid, &n_trace);

	  /* enqueue */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);

	  /* next */
	  n_from--;
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_increment_combined_counter (vnm->interface_main.combined_sw_if_counters
				   + VNET_INTERFACE_COUNTER_RX, thread_index,
				   mif->sw_if_index, n_rx_packets,
				   n_rx_bytes);

  /* refill ring with empty buffers */
refill:
  vec_reset_length (ptd->buffers);

  head = ring->head;
  n_slots = ring_size - head + mq->last_tail;
  slot = head & mask;

  n_slots &= ~7;

  if (n_slots < 32)
    goto done;

  memif_desc_t desc_template, *dt = &desc_template;
  clib_memset (dt, 0, sizeof (memif_desc_t));
  dt->length = buffer_length;

  n_alloc = vlib_buffer_alloc_to_ring_from_pool (
    vm, mq->buffers, slot, ring_size, n_slots, mq->buffer_pool_index);
  dt->region = mq->buffer_pool_index + 1;
  offset = (u64) mif->regions[dt->region].shm - start_offset;

  if (PREDICT_FALSE (n_alloc != n_slots))
    vlib_error_count (vm, node->node_index,
		      MEMIF_INPUT_ERROR_BUFFER_ALLOC_FAIL, 1);

  head += n_alloc;

  while (n_alloc)
    {
      memif_desc_t *d = ring->desc + slot;
      u32 *bi = mq->buffers + slot;

      if (PREDICT_FALSE (((slot + 7 > mask) || (n_alloc < 8))))
	goto one_by_one;

      clib_memcpy_fast (d + 0, dt, sizeof (memif_desc_t));
      clib_memcpy_fast (d + 1, dt, sizeof (memif_desc_t));
      clib_memcpy_fast (d + 2, dt, sizeof (memif_desc_t));
      clib_memcpy_fast (d + 3, dt, sizeof (memif_desc_t));
      clib_memcpy_fast (d + 4, dt, sizeof (memif_desc_t));
      clib_memcpy_fast (d + 5, dt, sizeof (memif_desc_t));
      clib_memcpy_fast (d + 6, dt, sizeof (memif_desc_t));
      clib_memcpy_fast (d + 7, dt, sizeof (memif_desc_t));

      d[0].offset = (u64) vlib_get_buffer (vm, bi[0])->data - offset;
      d[1].offset = (u64) vlib_get_buffer (vm, bi[1])->data - offset;
      d[2].offset = (u64) vlib_get_buffer (vm, bi[2])->data - offset;
      d[3].offset = (u64) vlib_get_buffer (vm, bi[3])->data - offset;
      d[4].offset = (u64) vlib_get_buffer (vm, bi[4])->data - offset;
      d[5].offset = (u64) vlib_get_buffer (vm, bi[5])->data - offset;
      d[6].offset = (u64) vlib_get_buffer (vm, bi[6])->data - offset;
      d[7].offset = (u64) vlib_get_buffer (vm, bi[7])->data - offset;

      slot = (slot + 8) & mask;
      n_alloc -= 8;
      continue;

    one_by_one:
      clib_memcpy_fast (d, dt, sizeof (memif_desc_t));
      d[0].offset = (u64) vlib_get_buffer (vm, bi[0])->data - offset;

      slot = (slot + 1) & mask;
      n_alloc -= 1;
    }

  __atomic_store_n (&ring->head, head, __ATOMIC_RELEASE);

done:
  return n_rx_packets;
}

CLIB_MARCH_FN (memif_dma_completion_cb, void, vlib_main_t *vm,
	       vlib_dma_batch_t *b)
{
  memif_main_t *mm = &memif_main;
  memif_if_t *mif = vec_elt_at_index (mm->interfaces, b->cookie >> 16);
  u32 thread_index = vm->thread_index;
  u32 n_left_to_next = 0;
  u16 nexts[MEMIF_RX_VECTOR_SZ], *next;
  u32 _to_next_bufs[MEMIF_RX_VECTOR_SZ], *to_next_bufs = _to_next_bufs, *bi;
  uword n_trace;
  memif_dma_data_t *dma_data;
  u16 qid = b->cookie & 0xffff;
  memif_queue_t *mq = vec_elt_at_index (mif->rx_queues, qid);
  dma_data = mq->dma_data + mq->dma_data_head;
  memif_per_thread_data_t *ptd = &dma_data->data;
  vnet_main_t *vnm = vnet_get_main ();

  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;

  __atomic_store_n (&mq->ring->tail, dma_data->dma_tail, __ATOMIC_RELEASE);

  /* prepare buffer template and next indices */
  i16 start_offset =
    (dma_data->mode == MEMIF_INTERFACE_MODE_IP) ? MEMIF_IP_OFFSET : 0;
  vnet_buffer (&ptd->buffer_template)->sw_if_index[VLIB_RX] = mif->sw_if_index;
  vnet_buffer (&ptd->buffer_template)->feature_arc_index = 0;
  ptd->buffer_template.current_data = start_offset;
  ptd->buffer_template.current_config_index = 0;
  ptd->buffer_template.buffer_pool_index = mq->buffer_pool_index;
  ptd->buffer_template.ref_count = 1;

  if (dma_data->mode == MEMIF_INTERFACE_MODE_ETHERNET)
    {
      next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
      if (mif->per_interface_next_index != ~0)
	next_index = mif->per_interface_next_index;
      else
	vnet_feature_start_device_input_x1 (mif->sw_if_index, &next_index,
					    &ptd->buffer_template);

      vlib_get_new_next_frame (vm, dma_data->node, next_index, to_next_bufs,
			       n_left_to_next);
      if (PREDICT_TRUE (next_index == VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT))
	{
	  vlib_next_frame_t *nf;
	  vlib_frame_t *f;
	  ethernet_input_frame_t *ef;
	  nf =
	    vlib_node_runtime_get_next_frame (vm, dma_data->node, next_index);
	  f = vlib_get_frame (vm, nf->frame);
	  f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;

	  ef = vlib_frame_scalar_args (f);
	  ef->sw_if_index = mif->sw_if_index;
	  ef->hw_if_index = mif->hw_if_index;
	  vlib_frame_no_append (f);
	}
    }

  vec_reset_length (ptd->buffers);

  if (dma_data->mode == MEMIF_INTERFACE_MODE_IP)
    memif_fill_buffer_mdata (vm, dma_data->node, ptd, mif, to_next_bufs, nexts,
			     1);
  else
    memif_fill_buffer_mdata (vm, dma_data->node, ptd, mif, to_next_bufs, nexts,
			     0);

  if (PREDICT_FALSE ((n_trace = vlib_get_trace_count (vm, dma_data->node))))
    {
      u32 n_left = ptd->n_packets;
      bi = to_next_bufs;
      next = nexts;
      u32 ni = next_index;
      while (n_trace && n_left)
	{
	  vlib_buffer_t *b;
	  memif_input_trace_t *tr;
	  if (dma_data->mode != MEMIF_INTERFACE_MODE_ETHERNET)
	    ni = next[0];
	  b = vlib_get_buffer (vm, bi[0]);
	  if (PREDICT_TRUE (vlib_trace_buffer (vm, dma_data->node, ni, b,
					       /* follow_chain */ 0)))
	    {
	      tr = vlib_add_trace (vm, dma_data->node, b, sizeof (*tr));
	      tr->next_index = ni;
	      tr->hw_if_index = mif->hw_if_index;
	      tr->ring = qid;
	      n_trace--;
	    }

	  /* next */
	  n_left--;
	  bi++;
	  next++;
	}
      vlib_set_trace_count (vm, dma_data->node, n_trace);
    }

  if (dma_data->mode == MEMIF_INTERFACE_MODE_ETHERNET)
    {
      n_left_to_next -= ptd->n_packets;
      vlib_put_next_frame (vm, dma_data->node, next_index, n_left_to_next);
    }
  else
    vlib_buffer_enqueue_to_next (vm, dma_data->node, to_next_bufs, nexts,
				 ptd->n_packets);

  vlib_increment_combined_counter (
    vnm->interface_main.combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
    thread_index, mif->sw_if_index, ptd->n_packets, ptd->n_rx_bytes);

  mq->dma_data_head++;
  if (mq->dma_data_head == mq->dma_data_size)
    mq->dma_data_head = 0;

  return;
}

#ifndef CLIB_MARCH_VARIANT
void
memif_dma_completion_cb (vlib_main_t *vm, vlib_dma_batch_t *b)
{
  return CLIB_MARCH_FN_SELECT (memif_dma_completion_cb) (vm, b);
}
#endif

static_always_inline uword
memif_device_input_inline_dma (vlib_main_t *vm, vlib_node_runtime_t *node,
			       memif_if_t *mif, memif_ring_type_t type,
			       u16 qid, memif_interface_mode_t mode)
{
  memif_main_t *mm = &memif_main;
  memif_ring_t *ring;
  memif_queue_t *mq;
  memif_per_thread_data_t *ptd;
  u16 cur_slot, n_slots;
  u16 n_buffers, n_alloc, n_desc;
  memif_copy_op_t *co;
  memif_dma_data_t *dma_data;
  int i;

  u16 mif_id = mif - mm->interfaces;
  mq = vec_elt_at_index (mif->rx_queues, qid);
  ring = mq->ring;

  if ((mq->dma_data_tail + 1 == mq->dma_data_head) ||
      ((mq->dma_data_head == mq->dma_data_size - 1) &&
       (mq->dma_data_tail == 0)))
    return 0;

  dma_data = mq->dma_data + mq->dma_data_tail;
  dma_data->node = node;
  dma_data->mode = mode;
  ptd = &dma_data->data;

  cur_slot = mq->last_head;
  n_slots = __atomic_load_n (&ring->head, __ATOMIC_ACQUIRE) - cur_slot;

  if (n_slots == 0)
    goto done;

  n_desc = memif_parse_desc (&dma_data->data, mif, mq, cur_slot, n_slots);

  cur_slot += n_desc;

  if (mif->mode == MEMIF_INTERFACE_MODE_ETHERNET)
    memif_validate_desc_data (&dma_data->data, mif, n_desc,
			      /* is_ethernet */ 1);
  else
    memif_validate_desc_data (&dma_data->data, mif, n_desc,
			      /* is_ethernet */ 0);

  n_buffers = memif_process_desc (vm, node, ptd, mif);

  if (PREDICT_FALSE (n_buffers == 0))
    {
      /* All descriptors are bad. Release slots in the ring and bail */
      memif_advance_ring (type, mq, ring, cur_slot);
      goto done;
    }

  /* allocate free buffers */
  vec_validate_aligned (dma_data->data.buffers, n_buffers - 1,
			CLIB_CACHE_LINE_BYTES);
  n_alloc = vlib_buffer_alloc_from_pool (vm, dma_data->data.buffers, n_buffers,
					 mq->buffer_pool_index);
  if (PREDICT_FALSE (n_alloc != n_buffers))
    {
      if (n_alloc)
	vlib_buffer_free (vm, dma_data->data.buffers, n_alloc);
      vlib_error_count (vm, node->node_index,
			MEMIF_INPUT_ERROR_BUFFER_ALLOC_FAIL, 1);
      goto done;
    }

  dma_data->data.n_rx_bytes = ptd->n_rx_bytes;
  dma_data->data.n_packets = ptd->n_packets;

  vlib_buffer_t *b;
  u32 n_pkts = clib_min (MEMIF_RX_VECTOR_SZ, vec_len (ptd->copy_ops));
  co = ptd->copy_ops;

  vlib_dma_batch_t *db;
  db = vlib_dma_batch_new (vm, mif->dma_input_config);
  for (i = 0; i < n_pkts; i++)
    {
      b = vlib_get_buffer (vm, ptd->buffers[co[i].buffer_vec_index]);
      vlib_dma_batch_add (vm, db, b->data + co[i].buffer_offset, co[i].data,
			  co[i].data_len);
    }

  for (i = n_pkts; i < vec_len (ptd->copy_ops); i++)
    {
      b = vlib_get_buffer (vm, ptd->buffers[co[i].buffer_vec_index]);
      vlib_dma_batch_add (vm, db, b->data + co[i].buffer_offset, co[i].data,
			  co[i].data_len);
    }
  vlib_dma_batch_set_cookie (vm, db, (mif_id << 16) | qid);
  vlib_dma_batch_submit (vm, db);

  dma_data->dma_tail = cur_slot;
  mq->last_head = dma_data->dma_tail;
  mq->dma_data_tail++;
  if (mq->dma_data_tail == mq->dma_data_size)
    mq->dma_data_tail = 0;

done:
  vec_reset_length (ptd->copy_ops);

  return ptd->n_packets;
}

VLIB_NODE_FN (memif_input_node) (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * frame)
{
  u32 n_rx = 0;
  memif_main_t *mm = &memif_main;
  memif_interface_mode_t mode_ip = MEMIF_INTERFACE_MODE_IP;
  memif_interface_mode_t mode_eth = MEMIF_INTERFACE_MODE_ETHERNET;

  vnet_hw_if_rxq_poll_vector_t *pv;
  pv = vnet_hw_if_get_rxq_poll_vector (vm, node);
  for (int i = 0; i < vec_len (pv); i++)
    {
      memif_if_t *mif;
      u32 qid;
      mif = vec_elt_at_index (mm->interfaces, pv[i].dev_instance);
      qid = pv[i].queue_id;
      if ((mif->flags & MEMIF_IF_FLAG_ADMIN_UP) &&
	  (mif->flags & MEMIF_IF_FLAG_CONNECTED))
	{
	  if (mif->flags & MEMIF_IF_FLAG_ZERO_COPY)
	    {
	      if (mif->mode == MEMIF_INTERFACE_MODE_IP)
		n_rx +=
		  memif_device_input_zc_inline (vm, node, mif, qid, mode_ip);
	      else
		n_rx +=
		  memif_device_input_zc_inline (vm, node, mif, qid, mode_eth);
	    }
	  else if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
	    {
	      if (mif->mode == MEMIF_INTERFACE_MODE_IP)
		n_rx += memif_device_input_inline (
		  vm, node, mif, MEMIF_RING_M2S, qid, mode_ip);
	      else
		n_rx += memif_device_input_inline (
		  vm, node, mif, MEMIF_RING_M2S, qid, mode_eth);
	    }
	  else
	    {
	      if ((mif->flags & MEMIF_IF_FLAG_USE_DMA) &&
		  (mif->dma_input_config >= 0))
		{
		  if (mif->mode == MEMIF_INTERFACE_MODE_IP)
		    n_rx += memif_device_input_inline_dma (
		      vm, node, mif, MEMIF_RING_S2M, qid, mode_ip);
		  else
		    n_rx += memif_device_input_inline_dma (
		      vm, node, mif, MEMIF_RING_S2M, qid, mode_eth);
		}
	      else
		{
		  if (mif->mode == MEMIF_INTERFACE_MODE_IP)
		    n_rx += memif_device_input_inline (
		      vm, node, mif, MEMIF_RING_S2M, qid, mode_ip);
		  else
		    n_rx += memif_device_input_inline (
		      vm, node, mif, MEMIF_RING_S2M, qid, mode_eth);
		}
	    }
	}
    }

  return n_rx;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (memif_input_node) = {
  .name = "memif-input",
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .sibling_of = "device-input",
  .format_trace = format_memif_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .n_errors = MEMIF_INPUT_N_ERROR,
  .error_counters = memif_input_error_counters,
};

/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
