/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

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
memif_init_buffer_template (vlib_main_t *vm, memif_if_t *mif,
			    memif_queue_t *mq, vlib_buffer_t *bt,
			    u32 *next_index, i16 start_off)
{
  vlib_buffer_pool_t *bp = vlib_get_buffer_pool (vm, mq->buffer_pool_index);

  vlib_buffer_copy_template (bt, &bp->buffer_template);
  vnet_buffer (bt)->sw_if_index[VLIB_RX] = mif->sw_if_index;
  vnet_buffer (bt)->sw_if_index[VLIB_TX] = ~0;
  vnet_buffer (bt)->feature_arc_index = 0;
  bt->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
  bt->current_data = start_off;
  bt->current_config_index = 0;
  if (mif->mode == MEMIF_INTERFACE_MODE_ETHERNET)
    {
      *next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
      if (mif->per_interface_next_index != ~0)
	*next_index = mif->per_interface_next_index;
      else
	vnet_feature_start_device_input_x1 (mif->sw_if_index, next_index, bt);
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

static_always_inline u32
memif_process_desc (vlib_main_t *vm, vlib_node_runtime_t *node,
		    memif_per_thread_data_t *ptd, memif_if_t *mif,
		    memif_queue_t *mq, u16 *cur_slot_p, u16 n_slots,
		    u32 *n_buffers_p, i16 start_offset, int is_slave)
{
  u16 buffer_size = vlib_buffer_get_default_data_size (vm);
  u32 n_buffers = 0, n_rx_packets = 0;
  memif_packet_op_t *po;
  memif_region_index_t last_region = ~0;
  void *last_region_shm = 0;
  void *last_region_max = 0;
  memif_ring_t *ring = mq->ring;
  u16 mask = pow2_mask (mq->log2_ring_size);
  u16 cur_slot = *cur_slot_p;

  /* construct copy and packet vector out of ring slots */
  while (n_slots && n_rx_packets < MEMIF_RX_VECTOR_SZ)
    {
      u32 dst_off, src_off, n_bytes_left;
      u16 s0;
      memif_desc_t *d0;
      void *mb0;
      po = ptd->packet_ops + n_rx_packets;
      n_rx_packets++;
      po->first_buffer_vec_index = n_buffers++;
      po->packet_len = 0;
      src_off = 0;
      dst_off = start_offset;

    next_slot:
      clib_prefetch_load (ring->desc + ((cur_slot + 8) & mask));
      s0 = cur_slot & mask;
      d0 = &ring->desc[s0];
      n_bytes_left = d0->length;

      /* slave resets buffer length,
       * so it can produce full size buffer for master
       */
      if (is_slave)
	d0->length = mif->run.buffer_size;

      po->packet_len += n_bytes_left;
      if (PREDICT_FALSE (last_region != d0->region))
	{
	  last_region_shm = mif->regions[d0->region].shm;
	  last_region = d0->region;
	  last_region_max =
	    last_region_shm + mif->regions[last_region].region_size;
	}
      mb0 = last_region_shm + d0->offset;

      if (PREDICT_FALSE (mb0 + n_bytes_left > last_region_max))
	vlib_error_count (vm, node->node_index, MEMIF_INPUT_ERROR_BAD_DESC, 1);
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

      cur_slot++;
      n_slots--;
      if ((d0->flags & MEMIF_DESC_FLAG_NEXT) && n_slots)
	{
	  src_off = 0;
	  goto next_slot;
	}
    }
  *n_buffers_p = n_buffers;
  *cur_slot_p = cur_slot;
  return n_rx_packets;
}

static_always_inline u32
memif_process_buffer_metdata (vlib_main_t *vm, vlib_node_runtime_t *node,
			      memif_per_thread_data_t *ptd, memif_if_t *mif,
			      memif_queue_t *mq, u32 *bi, u16 *next,
			      vlib_buffer_t *bt, u32 n_from, int is_ip)
{
  u16 buffer_size = vlib_buffer_get_default_data_size (vm);
  vlib_buffer_t *b0, *b1, *b2, *b3;
  memif_packet_op_t *po = ptd->packet_ops;
  u32 n_rx_bytes = 0;

  while (n_from >= 8)
    {
      b0 = vlib_get_buffer (vm, ptd->buffers[po[0].first_buffer_vec_index]);
      b1 = vlib_get_buffer (vm, ptd->buffers[po[1].first_buffer_vec_index]);
      b2 = vlib_get_buffer (vm, ptd->buffers[po[2].first_buffer_vec_index]);
      b3 = vlib_get_buffer (vm, ptd->buffers[po[3].first_buffer_vec_index]);

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

      vlib_buffer_copy_template (b0, bt);
      vlib_buffer_copy_template (b1, bt);
      vlib_buffer_copy_template (b2, bt);
      vlib_buffer_copy_template (b3, bt);

      b0->current_length = po[0].packet_len;
      n_rx_bytes += b0->current_length;
      b1->current_length = po[1].packet_len;
      n_rx_bytes += b1->current_length;
      b2->current_length = po[2].packet_len;
      n_rx_bytes += b2->current_length;
      b3->current_length = po[3].packet_len;
      n_rx_bytes += b3->current_length;

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
      u32 fbvi[4];
      /* enqueue buffer */
      fbvi[0] = po[0].first_buffer_vec_index;
      bi[0] = ptd->buffers[fbvi[0]];
      b0 = vlib_get_buffer (vm, bi[0]);
      vlib_buffer_copy_template (b0, bt);
      b0->current_length = po->packet_len;
      n_rx_bytes += b0->current_length;

      memif_add_to_chain (vm, b0, ptd->buffers + fbvi[0] + 1, buffer_size);

      if (is_ip)
	next[0] = memif_next_from_ip_hdr (node, b0);

      /* next */
      n_from -= 1;
      po += 1;
      bi += 1;
      next += 1;
    }
  return n_rx_bytes;
}

static_always_inline void
memif_trace (vlib_main_t *vm, vlib_node_runtime_t *node, memif_if_t *mif,
	     u16 qid, u32 *bi, u16 *next, u32 ni, u32 n_left)
{
  u32 n_trace = vlib_get_trace_count (vm, node);

  if (PREDICT_TRUE (n_trace == 0))
    return;

  while (n_trace && n_left)
    {
      vlib_buffer_t *b;
      memif_input_trace_t *tr;
      if (mif->mode != MEMIF_INTERFACE_MODE_ETHERNET)
	ni = next[0];
      b = vlib_get_buffer (vm, bi[0]);
      if (PREDICT_TRUE (
	    vlib_trace_buffer (vm, node, ni, b, /* follow_chain */ 0)))
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

static_always_inline void
memif_copy_data (vlib_main_t *vm, memif_per_thread_data_t *ptd)
{
  u32 n_left = vec_len (ptd->copy_ops);
  memif_copy_op_t *co = ptd->copy_ops;
  vlib_buffer_t *b0, *b1, *b2, *b3;

  while (n_left >= 8)
    {
      clib_prefetch_load (co[4].data);
      clib_prefetch_load (co[5].data);
      clib_prefetch_load (co[6].data);
      clib_prefetch_load (co[7].data);

      b0 = vlib_get_buffer (vm, ptd->buffers[co[0].buffer_vec_index]);
      b1 = vlib_get_buffer (vm, ptd->buffers[co[1].buffer_vec_index]);
      b2 = vlib_get_buffer (vm, ptd->buffers[co[2].buffer_vec_index]);
      b3 = vlib_get_buffer (vm, ptd->buffers[co[3].buffer_vec_index]);

      clib_memcpy_fast (b0->data + co[0].buffer_offset, co[0].data,
			co[0].data_len);
      clib_memcpy_fast (b1->data + co[1].buffer_offset, co[1].data,
			co[1].data_len);
      clib_memcpy_fast (b2->data + co[2].buffer_offset, co[2].data,
			co[2].data_len);
      clib_memcpy_fast (b3->data + co[3].buffer_offset, co[3].data,
			co[3].data_len);

      co += 4;
      n_left -= 4;
    }
  while (n_left)
    {
      b0 = vlib_get_buffer (vm, ptd->buffers[co[0].buffer_vec_index]);
      clib_memcpy_fast (b0->data + co[0].buffer_offset, co[0].data,
			co[0].data_len);
      co += 1;
      n_left -= 1;
    }
}

static_always_inline u32 *
memif_get_new_next_frame (vlib_main_t *vm, vlib_node_runtime_t *node,
			  memif_if_t *mif, u32 next_index)
{
  u32 *to_next_bufs;
  u32 n_left_to_next;

  vlib_get_new_next_frame (vm, node, next_index, to_next_bufs, n_left_to_next);
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
  return to_next_bufs;
}

static_always_inline void
memif_refill_m2s (memif_if_t *mif, memif_queue_t *mq)
{
  memif_ring_t *ring = mq->ring;
  u16 head = ring->head;
  u16 ring_size = 1 << mq->log2_ring_size;
  u16 mask = ring_size - 1;
  u16 n_slots = ring_size - head + mq->last_tail;

  while (n_slots--)
    {
      u16 s = head++ & mask;
      memif_desc_t *d = &ring->desc[s];
      d->length = mif->run.buffer_size;
    }

  __atomic_store_n (&ring->head, head, __ATOMIC_RELEASE);
}

static_always_inline uword
memif_device_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			   memif_if_t *mif, memif_queue_t *mq)
{
  vnet_main_t *vnm = vnet_get_main ();
  memif_main_t *mm = &memif_main;
  memif_ring_t *ring;
  u16 nexts[MEMIF_RX_VECTOR_SZ];
  u32 _to_next_bufs[MEMIF_RX_VECTOR_SZ], *to_next_bufs = _to_next_bufs;
  u32 n_rx_packets = 0, n_rx_bytes = 0;
  u32 n_buffers, n_left_to_next;
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  vlib_buffer_t _bt, *bt = &_bt;
  memif_per_thread_data_t *ptd =
    vec_elt_at_index (mm->per_thread_data, vm->thread_index);
  u16 slot, n_slots, mask;
  i16 start_off;
  u16 n_alloc;
  int is_slave = (mif->flags & MEMIF_IF_FLAG_IS_SLAVE) != 0;

  ring = mq->ring;
  mask = pow2_mask (mq->log2_ring_size);
  start_off = (mif->mode == MEMIF_INTERFACE_MODE_IP) ? MEMIF_IP_OFFSET : 0;

  /* for S2M rings, we are consumers of packet buffers, and for M2S rings we
     are producers of empty buffers */

  if (is_slave)
    {
      slot = mq->last_tail;
      n_slots = __atomic_load_n (&ring->tail, __ATOMIC_ACQUIRE) - slot;
    }
  else
    {
      slot = mq->last_head;
      n_slots = __atomic_load_n (&ring->head, __ATOMIC_ACQUIRE) - slot;
    }

  if (n_slots == 0)
    goto refill;

  if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
    n_rx_packets =
      memif_process_desc (vm, node, ptd, mif, mq, &slot, n_slots, &n_buffers,
			  start_off, /* is_slave */ 1);
  else
    n_rx_packets =
      memif_process_desc (vm, node, ptd, mif, mq, &slot, n_slots, &n_buffers,
			  start_off, /* is_slave */ 1);

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
  memif_copy_data (vm, ptd);

  /* release slots from the ring */
  if (is_slave)
    {
      mq->last_tail = slot;
    }
  else
    {
      __atomic_store_n (&ring->tail, slot, __ATOMIC_RELEASE);
      mq->last_head = slot;
    }

  /* prepare buffer template and next indices */
  memif_init_buffer_template (vm, mif, mq, bt, &next_index, start_off);

  if (mif->mode == MEMIF_INTERFACE_MODE_ETHERNET)
    {
      to_next_bufs = memif_get_new_next_frame (vm, node, mif, next_index);
      n_left_to_next = VLIB_FRAME_SIZE;
      n_rx_bytes =
	memif_process_buffer_metdata (vm, node, ptd, mif, mq, to_next_bufs,
				      nexts, bt, n_rx_packets, /* is _ip */ 0);
    }
  else
    n_rx_bytes =
      memif_process_buffer_metdata (vm, node, ptd, mif, mq, to_next_bufs,
				    nexts, bt, n_rx_packets, /* is_ip */ 1);

  memif_trace (vm, node, mif, mq->queue_index, to_next_bufs, nexts, next_index,
	       n_rx_packets);

  if (mif->mode == MEMIF_INTERFACE_MODE_ETHERNET)
    {
      n_left_to_next -= n_rx_packets;
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  else
    vlib_buffer_enqueue_to_next (vm, node, to_next_bufs, nexts, n_rx_packets);

  vlib_increment_combined_counter (
    vnm->interface_main.combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
    vm->thread_index, mif->sw_if_index, n_rx_packets, n_rx_bytes);

  /* refill ring with empty buffers */
refill:
  vec_reset_length (ptd->buffers);
  vec_reset_length (ptd->copy_ops);

  if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
    memif_refill_m2s (mif, mq);

  return n_rx_packets;
}

static_always_inline void
memif_process_buffer_metdata_zc (vlib_main_t *vm, vlib_node_runtime_t *node,
				 u32 *bi, u16 *next, u32 n_left)
{
  vlib_error_t error = node->errors[MEMIF_INPUT_ERROR_NOT_IP];
  u8 v;

  const u16 lut[16] = {
    VNET_DEVICE_INPUT_NEXT_DROP,	  VNET_DEVICE_INPUT_NEXT_DROP,
    VNET_DEVICE_INPUT_NEXT_DROP,	  VNET_DEVICE_INPUT_NEXT_DROP,
    VNET_DEVICE_INPUT_NEXT_IP4_NCS_INPUT, VNET_DEVICE_INPUT_NEXT_DROP,
    VNET_DEVICE_INPUT_NEXT_IP6_INPUT,	  VNET_DEVICE_INPUT_NEXT_DROP,
    VNET_DEVICE_INPUT_NEXT_DROP,	  VNET_DEVICE_INPUT_NEXT_DROP,
    VNET_DEVICE_INPUT_NEXT_DROP,	  VNET_DEVICE_INPUT_NEXT_DROP,
    VNET_DEVICE_INPUT_NEXT_DROP,	  VNET_DEVICE_INPUT_NEXT_DROP,
    VNET_DEVICE_INPUT_NEXT_DROP,	  VNET_DEVICE_INPUT_NEXT_DROP
  };

  while (n_left >= 8)
    {
      clib_prefetch_load (vlib_get_buffer (vm, bi[4])->data);
      clib_prefetch_load (vlib_get_buffer (vm, bi[5])->data);
      clib_prefetch_load (vlib_get_buffer (vm, bi[6])->data);
      clib_prefetch_load (vlib_get_buffer (vm, bi[7])->data);

      v = vlib_get_buffer (vm, bi[0])->data[MEMIF_IP_OFFSET] >> 4;
      if (PREDICT_FALSE ((next[0] = lut[v]) == VNET_DEVICE_INPUT_NEXT_DROP))
	vlib_get_buffer (vm, bi[0])->error = error;

      v = vlib_get_buffer (vm, bi[1])->data[MEMIF_IP_OFFSET] >> 4;
      if (PREDICT_FALSE ((next[1] = lut[v]) == VNET_DEVICE_INPUT_NEXT_DROP))
	vlib_get_buffer (vm, bi[1])->error = error;

      v = vlib_get_buffer (vm, bi[2])->data[MEMIF_IP_OFFSET] >> 4;
      if (PREDICT_FALSE ((next[2] = lut[v]) == VNET_DEVICE_INPUT_NEXT_DROP))
	vlib_get_buffer (vm, bi[2])->error = error;

      v = vlib_get_buffer (vm, bi[3])->data[MEMIF_IP_OFFSET] >> 4;
      if (PREDICT_FALSE ((next[3] = lut[v]) == VNET_DEVICE_INPUT_NEXT_DROP))
	vlib_get_buffer (vm, bi[3])->error = error;

      /* next */
      n_left -= 4;
      next += 4;
      bi += 4;
    }
  while (n_left)
    {
      v = vlib_get_buffer (vm, bi[0])->data[MEMIF_IP_OFFSET] >> 4;
      if (PREDICT_FALSE ((next[0] = lut[v]) == VNET_DEVICE_INPUT_NEXT_DROP))
	vlib_get_buffer (vm, bi[0])->error = error;

      /* next */
      n_left -= 1;
      next += 1;
      bi += 1;
    }
}

static_always_inline void
memif_refill_zc (vlib_main_t *vm, vlib_node_runtime_t *node, memif_if_t *mif,
		 memif_queue_t *mq, i16 start_offset)
{
  u16 buffer_length = vlib_buffer_get_default_data_size (vm) - start_offset;
  memif_desc_t desc_template = {}, *dt = &desc_template;
  memif_ring_t *ring = mq->ring;
  u64 offset;
  u16 n_alloc, head = ring->head;
  u16 ring_size = ring_size = 1 << mq->log2_ring_size;
  u16 mask = ring_size - 1;
  u16 n_slots = ring_size - head + mq->last_tail;
  u16 slot = head & mask;

  n_slots &= ~7;

  if (n_slots < 32)
    return;

  dt->length = buffer_length;
  dt->region = mq->buffer_pool_index + 1;

  n_alloc = vlib_buffer_alloc_to_ring_from_pool (
    vm, mq->buffers, slot, ring_size, n_slots, mq->buffer_pool_index);
  offset = (u64) mif->regions[dt->region].shm + start_offset;

  if (PREDICT_FALSE (n_alloc != n_slots))
    vlib_error_count (vm, node->node_index,
		      MEMIF_INPUT_ERROR_BUFFER_ALLOC_FAIL, n_slots - n_alloc);

  head += n_alloc;

  while (n_alloc)
    {
      memif_desc_t *d = ring->desc + slot;
      u32 *bi = mq->buffers + slot;

      if (PREDICT_FALSE (((slot + 8 > mask) || (n_alloc < 8))))
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

      slot += 8;
      n_alloc -= 8;
      continue;

    one_by_one:
      clib_memcpy_fast (d, dt, sizeof (memif_desc_t));
      d[0].offset = (u64) vlib_get_buffer (vm, bi[0])->data - offset;

      slot = (slot + 1) & mask;
      n_alloc -= 1;
    }

  __atomic_store_n (&ring->head, head, __ATOMIC_RELEASE);
}

static_always_inline uword
memif_device_input_zc_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			      memif_if_t *mif, memif_queue_t *mq)
{
  vnet_main_t *vnm = vnet_get_main ();
  memif_main_t *mm = &memif_main;
  memif_ring_t *ring;
  vlib_buffer_t _bt, *bt = &_bt;
  u32 next_index, n_rx_packets = 0, n_rx_bytes = 0;
  memif_per_thread_data_t *ptd =
    vec_elt_at_index (mm->per_thread_data, vm->thread_index);
  u16 tail, n_slots, mask;
  i16 start_off;
  u32 *buffers, buffer_length;

  ring = mq->ring;
  mask = pow2_mask (mq->log2_ring_size);
  start_off = (mif->mode == MEMIF_INTERFACE_MODE_IP) ? MEMIF_IP_OFFSET : 0;

  tail = mq->last_tail;
  n_slots = __atomic_load_n (&ring->tail, __ATOMIC_ACQUIRE) - tail;

  if (n_slots == 0)
    goto done;

  buffer_length = vlib_buffer_get_default_data_size (vm) - start_off;
  next_index = VNET_DEVICE_INPUT_NEXT_IP6_INPUT;
  memif_init_buffer_template (vm, mif, mq, bt, &next_index, start_off);

  if (mif->mode == MEMIF_INTERFACE_MODE_ETHERNET)
    {
      buffers = memif_get_new_next_frame (vm, node, mif, next_index);
    }
  else
    {
      vec_validate_aligned (ptd->buffers, MEMIF_RX_VECTOR_SZ,
			    CLIB_CACHE_LINE_BYTES);
      buffers = ptd->buffers;
    }

  /* process ring slots */
  while (n_slots && n_rx_packets < MEMIF_RX_VECTOR_SZ)
    {
      vlib_buffer_t *hb, *b;
      u32 bi0;
      u16 slot;
      memif_desc_t *d;

      slot = tail & mask;
      bi0 = mq->buffers[slot];
      buffers[n_rx_packets++] = bi0;

      clib_prefetch_load (ring->desc + ((tail + 8) & mask));
      d = ring->desc + slot;
      hb = b = vlib_get_buffer (vm, bi0);
      vlib_buffer_copy_template (b, bt);
      b->current_length = d->length;
      n_rx_bytes += d->length;

      tail++;
      n_slots--;
      if (PREDICT_FALSE ((d->flags & MEMIF_DESC_FLAG_NEXT) && n_slots))
	{
	  hb->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
	next_slot:
	  slot = tail & mask;
	  d = &ring->desc[slot];
	  bi0 = mq->buffers[slot];

	  /* previous buffer */
	  b->next_buffer = bi0;
	  b->flags |= VLIB_BUFFER_NEXT_PRESENT;

	  /* current buffer */
	  b = vlib_get_buffer (vm, bi0);
	  b->current_data = start_off;
	  b->current_length = d->length;
	  hb->total_length_not_including_first_buffer += d->length;
	  n_rx_bytes += d->length;

	  tail++;
	  n_slots--;
	  if ((d->flags & MEMIF_DESC_FLAG_NEXT) && n_slots)
	    goto next_slot;
	}
    }

  /* release slots from the ring */
  mq->last_tail = tail;

  if (mif->mode == MEMIF_INTERFACE_MODE_IP)
    memif_process_buffer_metdata_zc (vm, node, buffers, ptd->nexts,
				     n_rx_packets);

  memif_trace (vm, node, mif, mq->queue_index, ptd->buffers, ptd->nexts,
	       next_index, n_rx_packets);

  if (mif->mode == MEMIF_INTERFACE_MODE_ETHERNET)
    vlib_put_next_frame (vm, node, next_index, VLIB_FRAME_SIZE - n_rx_packets);
  else
    vlib_buffer_enqueue_to_next (vm, node, buffers, ptd->nexts, n_rx_packets);

  vlib_increment_combined_counter (
    vnm->interface_main.combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
    vm->thread_index, mif->sw_if_index, n_rx_packets, n_rx_bytes);

done:
  vec_reset_length (ptd->buffers);

  memif_refill_zc (vm, node, mif, mq, start_off);

  return n_rx_packets;
}

VLIB_NODE_FN (memif_input_node) (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * frame)
{
  u32 n_rx = 0;
  memif_main_t *mm = &memif_main;

  vnet_hw_if_rxq_poll_vector_t *pv;
  pv = vnet_hw_if_get_rxq_poll_vector (vm, node);
  for (int i = 0; i < vec_len (pv); i++)
    {
      memif_if_t *mif;
      memif_queue_t *mq;

      u32 qid;
      mif = vec_elt_at_index (mm->interfaces, pv[i].dev_instance);
      qid = pv[i].queue_id;

      if ((mif->flags & MEMIF_IF_FLAG_ADMIN_UP) == 0 ||
	  (mif->flags & MEMIF_IF_FLAG_CONNECTED) == 0)
	continue;

      mq = vec_elt_at_index (mif->rx_queues, qid);

      if (mif->flags & MEMIF_IF_FLAG_ZERO_COPY)
	n_rx += memif_device_input_zc_inline (vm, node, mif, mq);
      else
	n_rx += memif_device_input_inline (vm, node, mif, mq);
    }

  return n_rx;
}

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
