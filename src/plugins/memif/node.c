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

static_always_inline void
memif_init_buffer_template (vlib_main_t *vm, memif_if_t *mif,
			    memif_queue_t *mq, vlib_buffer_t *bt,
			    u32 *next_index, i16 start_off)
{
  vlib_buffer_pool_t *bp = vlib_get_buffer_pool (vm, mq->buffer_pool_index);

  vlib_buffer_copy_template (bt, &bp->buffer_template);
  vnet_buffer (bt)->sw_if_index[VLIB_RX] = mif->sw_if_index;
  vnet_buffer (bt)->sw_if_index[VLIB_TX] = ~0;
  bt->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
  bt->current_data = start_off;
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
memif_parse_desc (memif_per_thread_data_t *ptd, memif_if_t *mif,
		  memif_queue_t *mq, u16 *next_p, u16 n_slots, int is_slave)
{
  u32 max_bytes = (mif->mode == MEMIF_INTERFACE_MODE_ETHERNET) ? 9216 : 65535;
  memif_ring_t *ring = mq->ring;
  memif_off_region_flags_t *orf = ptd->desc_off_region_flags;
  u64 *next_flag_bmp = ptd->desc_next_flag_bmp;
  u32 *len = ptd->desc_len;
  memif_desc_t *descs = ring->desc;
  memif_region_t *regions = mif->regions;
  u16 n_regions = vec_len (regions);
  u16 mask = pow2_mask (mq->log2_ring_size);
  u16 next = *next_p;
  u16 n_desc = 0, n_next_flags, n_left;
  memif_desc_t *d = 0;

  n_left = clib_min (n_slots, VLIB_FRAME_SIZE);

  while (n_left)
    {
      d = descs + (next++ & mask);
      len[n_desc] = d[0].length;
      orf[n_desc].offset = d[0].offset;
      orf[n_desc].region = d[0].region;
      orf[n_desc].flags = d[0].flags;
      n_desc++;
      n_left--;
    }

  if (PREDICT_FALSE (orf[n_desc - 1].flags & MEMIF_DESC_FLAG_NEXT))
    {
      /* last available descriptor should not have NEXT flag set */
      if (n_desc == n_slots)
	goto error;

      /* revert back to last complete packet */
      while (n_desc > 0 && orf[n_desc - 1].flags & MEMIF_DESC_FLAG_NEXT)
	n_desc--;

      /* we don't support more than VLIB_FRAME_SIZE(256) chained descriptors */
      if (n_desc == 0)
	goto error;
    }

  /* security checks */
  for (u32 i = 0; i < n_desc; i++)
    {
      u16 r = orf[i].region;
      if (PREDICT_FALSE (r >= n_regions))
	goto error;

      if (PREDICT_FALSE (len[i] >= max_bytes || len[i] == 0))
	goto error;

      if (PREDICT_FALSE (orf[i].offset + len[i] >= regions[r].region_size))
	goto error;

      if (PREDICT_FALSE (orf[i].flags & ~MEMIF_DESC_FLAG_NEXT))
	goto error;
    }

  if (is_slave)
    {
      u32 sz = mif->run.buffer_size;
      for (u16 i = *next_p; i < *next_p + n_desc; i++)
	descs[i & mask].length = sz;
    }

  n_left = n_desc;
  orf = ptd->desc_off_region_flags;
  n_next_flags = 0;

  while (n_left >= 64)
    {
      u64 w = 0;
      for (u32 i = 0; i < 64; i++)
	{
	  if (orf[i].flags & MEMIF_DESC_FLAG_NEXT)
	    w |= 1ULL << i;
	  orf[i].ptr = regions[orf[i].region].shm + orf[i].offset;
	}

      n_left -= 64;
      orf += 64;
      n_next_flags += count_set_bits (w);
      next_flag_bmp++[0] = w;
    }

  if (n_left)
    {
      u64 w = 0;
      for (u32 i = 0; i < n_left; i++)
	{
	  if (orf[i].flags & MEMIF_DESC_FLAG_NEXT)
	    w |= 1ULL << i;
	  orf[i].ptr = regions[orf[i].region].shm + orf[i].offset;
	}
      n_next_flags += count_set_bits (w);
      next_flag_bmp[0] = w;
    }

  /* done */
  *next_p += n_desc;
  ptd->n_packets = n_desc - n_next_flags;
  ptd->n_descs = n_desc;
  return;

error:
  mif->flags |= MEMIF_IF_FLAG_ERROR;
  ptd->n_descs = 0;
}

static_always_inline void
memif_process_desc (vlib_main_t *vm, vlib_node_runtime_t *node,
		    memif_per_thread_data_t *ptd, u32 *buffers,
		    vlib_buffer_t *bt, i16 start_offset, int maybe_next)
{
  u16 buffer_size = vlib_buffer_get_default_data_size (vm);
  u32 *bufs = buffers;
  memif_off_region_flags_t *orf = ptd->desc_off_region_flags;
  u32 *len = ptd->desc_len;
  u64 *next_flag_bmp = ptd->desc_next_flag_bmp, desc_bit = 1;
  u32 n_left = ptd->n_packets;
  vlib_buffer_t *hb, *b;
  u8 *from, *to;
  u32 n_from, n_to, n_copy;
  u32 n_bytes = 0;

  while (n_left)
    {
      hb = b = vlib_get_buffer (vm, bufs[0]);
      vlib_buffer_copy_template (b, bt);
      to = b->data + start_offset;
      n_to = buffer_size - start_offset;

      from = orf[0].ptr;
      n_from = len[0];

      n_copy = clib_min (n_from, n_to);
      clib_memcpy_fast (to, from, n_copy);
      n_bytes += n_copy;
      b->current_length = n_copy;
      n_from -= n_copy;

      if (PREDICT_TRUE (n_from == 0 && (maybe_next == 0 ||
					(next_flag_bmp[0] & desc_bit) == 0)))
	goto next;

      clib_panic ("todo");

      n_to -= n_copy;
      from += n_copy;
      to += n_copy;

      while (n_from)
	{
	  n_copy = clib_min (n_from, n_to);
	  clib_memcpy_fast (to, from, n_copy);
	  n_from -= n_copy;
	  n_to -= n_copy;
	  from += n_copy;
	  to += n_copy;
	  b->current_length += n_copy;
	  if (b != hb)
	    hb->total_length_not_including_first_buffer += n_copy;

	  if (n_from == 0 && PREDICT_FALSE (next_flag_bmp[0] & desc_bit))
	    {
	      from = ++orf[0].ptr;
	      n_from = ++len[0];
	      desc_bit <<= 1;
	      if (desc_bit == 0)
		{
		  next_flag_bmp++;
		  desc_bit = 1;
		}
	    }

	  if (n_to == 0)
	    {
	      u32 bi;
	      if (PREDICT_FALSE (vlib_buffer_alloc (vm, &bi, 1) != 1))
		{
		  u32 n_ok = bufs - buffers;
		  vlib_buffer_free (vm, bufs, ptd->n_packets - n_ok);
		  vlib_error_count (vm, node->node_index,
				    MEMIF_INPUT_ERROR_BUFFER_ALLOC_FAIL,
				    ptd->n_packets - n_ok);
		  ptd->n_packets = n_ok;
		  goto done;
		}
	      b = vlib_get_buffer (vm, bi);
	      b->flags |= VLIB_BUFFER_NEXT_PRESENT;
	      b->next_buffer = bi;
	      n_to = buffer_size;
	      to = b->data;
	    }
	}

    next:
      len++;
      orf++;
      bufs++;
      desc_bit <<= 1;
      n_left -= 1;
      if (desc_bit == 0)
	{
	  next_flag_bmp++;
	  desc_bit = 1;
	}
    }
done:
  ptd->n_bytes = n_bytes;
}

static void
memif_trace (vlib_main_t *vm, vlib_node_runtime_t *node,
	     memif_per_thread_data_t *ptd, memif_if_t *mif, memif_queue_t *mq,
	     u32 *bi, u32 ni)
{
  u32 n_left, n_trace = vlib_get_trace_count (vm, node);
  u16 *next;

  if (PREDICT_TRUE (n_trace == 0))
    return;

  n_left = ptd->n_packets;
  next = ptd->nexts;

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
	  tr->ring = mq->queue_index;
	  n_trace--;
	}

      /* next */
      n_left--;
      bi++;
      next++;
    }
  vlib_set_trace_count (vm, node, n_trace);
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
memif_refill_zc (vlib_main_t *vm, vlib_node_runtime_t *node, memif_if_t *mif,
		 memif_queue_t *mq, i16 start_offset)
{
  u16 buffer_length = vlib_buffer_get_default_data_size (vm) - start_offset;
  memif_desc_t desc_template = {}, *dt = &desc_template;
  memif_ring_t *ring = mq->ring;
  u64 offset;
  u16 n_alloc, head = ring->head;
  u16 ring_size = 1 << mq->log2_ring_size;
  u16 mask = ring_size - 1;
  u16 n_slots = ring_size - head + mq->last_tail;
  u16 slot = head & mask;

  if (n_slots < 32)
    return;

  n_slots &= ~7;

  dt->length = buffer_length + start_offset;
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

static_always_inline void
memif_refill (memif_if_t *mif, memif_queue_t *mq)
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

static_always_inline void
memif_process_ip_hdr_type (vlib_main_t *vm, vlib_node_runtime_t *node,
			   memif_per_thread_data_t *ptd)
{
  u32 *bi = ptd->bufs;
  u16 *next = ptd->nexts;
  u32 n_left = ptd->n_packets;
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
memif_device_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			   memif_per_thread_data_t *ptd, memif_if_t *mif,
			   memif_queue_t *mq)
{
  memif_ring_t *ring = mq->ring;
  u32 *buffers;
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  vlib_buffer_t _bt, *bt = &_bt;
  u16 next, n_slots, n_alloc;
  i16 start_off;
  int is_slave = (mif->flags & MEMIF_IF_FLAG_IS_SLAVE) != 0;
  int is_ip = mif->mode == MEMIF_INTERFACE_MODE_IP;

  start_off = (is_ip) ? MEMIF_IP_OFFSET : 0;

  if (is_slave)
    {
      next = mq->last_tail;
      n_slots = __atomic_load_n (&ring->tail, __ATOMIC_ACQUIRE) - next;
    }
  else
    {
      next = mq->last_head;
      n_slots = __atomic_load_n (&ring->head, __ATOMIC_ACQUIRE) - next;
    }

  if (n_slots == 0)
    goto done;

  if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
    memif_parse_desc (ptd, mif, mq, &next, n_slots, 1);
  else
    memif_parse_desc (ptd, mif, mq, &next, n_slots, 0);

  if (ptd->n_descs == 0)
    goto done;

  /* prepare buffer template and next indices */
  memif_init_buffer_template (vm, mif, mq, bt, &next_index, start_off);

  if (is_ip)
    buffers = ptd->bufs;
  else
    buffers = memif_get_new_next_frame (vm, node, mif, next_index);

  /* allocate free buffers */
  n_alloc = vlib_buffer_alloc_from_pool (vm, buffers, ptd->n_packets,
					 mq->buffer_pool_index);

  if (PREDICT_FALSE (n_alloc != ptd->n_packets))
    {
      if (n_alloc)
	vlib_buffer_free (vm, ptd->bufs, n_alloc);
      vlib_error_count (vm, node->node_index,
			MEMIF_INPUT_ERROR_BUFFER_ALLOC_FAIL, 1);
      goto done;
    }

  if (ptd->n_packets < ptd->n_descs)
    memif_process_desc (vm, node, ptd, buffers, bt, start_off,
			/* maybe_next */ 1);
  else
    memif_process_desc (vm, node, ptd, buffers, bt, start_off,
			/* maybe_next */ 0);

  /* release slots from the ring */
  if (is_slave)
    {
      mq->last_tail = next;
    }
  else
    {
      __atomic_store_n (&ring->tail, next, __ATOMIC_RELEASE);
      mq->last_head = next;
    }

  if (is_ip)
    memif_process_ip_hdr_type (vm, node, ptd);

  memif_trace (vm, node, ptd, mif, mq, buffers, next_index);

  if (is_ip)
    vlib_buffer_enqueue_to_next (vm, node, ptd->bufs, ptd->nexts,
				 ptd->n_packets);
  else
    vlib_put_next_frame (vm, node, next_index,
			 VLIB_FRAME_SIZE - ptd->n_packets);

done:

  if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
    memif_refill (mif, mq);
}

static_always_inline void
memif_device_input_zc_dequeue (vlib_main_t *vm, memif_per_thread_data_t *ptd,
			       memif_queue_t *mq, u32 *buffers,
			       vlib_buffer_t *bt, i16 start_off, u32 n_slots,
			       u16 *next_p)
{
  u32 n_rx_packets = 0, n_rx_bytes = 0;
  u16 next = *next_p;
  memif_ring_t *ring = mq->ring;
  u16 mask = pow2_mask (mq->log2_ring_size);

  /* process ring slots */
  while (n_slots && n_rx_packets < MEMIF_RX_VECTOR_SZ)
    {
      vlib_buffer_t *hb, *b;
      u32 bi0;
      u16 slot;
      memif_desc_t *d;

      slot = next & mask;
      bi0 = mq->buffers[slot];
      buffers[n_rx_packets++] = bi0;

      clib_prefetch_load (ring->desc + ((next + 8) & mask));
      d = ring->desc + slot;
      hb = b = vlib_get_buffer (vm, bi0);
      vlib_buffer_copy_template (b, bt);
      b->current_length = d->length;
      n_rx_bytes += d->length;

      next++;
      n_slots--;
      if (PREDICT_FALSE ((d->flags & MEMIF_DESC_FLAG_NEXT) && n_slots))
	{
	  hb->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
	next_slot:
	  slot = next & mask;
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

	  next++;
	  n_slots--;
	  if ((d->flags & MEMIF_DESC_FLAG_NEXT) && n_slots)
	    goto next_slot;
	}
    }

  *next_p = next;
  ptd->n_bytes = n_rx_bytes;
  ptd->n_packets = n_rx_packets;
}

static_always_inline void
memif_device_input_zc_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			      memif_per_thread_data_t *ptd, memif_if_t *mif,
			      memif_queue_t *mq)
{
  memif_ring_t *ring = mq->ring;
  vlib_buffer_t _bt, *bt = &_bt;
  u32 next_index;
  u16 next, n_slots;
  i16 start_off;
  u32 *buffers;
  int is_ip = mif->mode == MEMIF_INTERFACE_MODE_IP;

  start_off = (is_ip) ? MEMIF_IP_OFFSET : 0;

  next = mq->last_tail;
  n_slots = __atomic_load_n (&ring->tail, __ATOMIC_ACQUIRE) - next;

  if (n_slots == 0)
    goto done;

  next_index = VNET_DEVICE_INPUT_NEXT_IP6_INPUT;
  memif_init_buffer_template (vm, mif, mq, bt, &next_index, start_off);

  if (is_ip)
    buffers = ptd->bufs;
  else
    buffers = memif_get_new_next_frame (vm, node, mif, next_index);

  memif_device_input_zc_dequeue (vm, ptd, mq, buffers, bt, start_off, n_slots,
				 &next);

  /* release slots from the ring */
  mq->last_tail = next;

  if (is_ip)
    memif_process_ip_hdr_type (vm, node, ptd);

  memif_trace (vm, node, ptd, mif, mq, buffers, next_index);

  if (is_ip)
    vlib_buffer_enqueue_to_next (vm, node, ptd->bufs, ptd->nexts,
				 ptd->n_packets);
  else
    vlib_put_next_frame (vm, node, next_index,
			 VLIB_FRAME_SIZE - ptd->n_packets);

done:
  memif_refill_zc (vm, node, mif, mq, start_off);
}

VLIB_NODE_FN (memif_input_node) (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * frame)
{
  u32 n_rx = 0;
  memif_main_t *mm = &memif_main;
  vnet_main_t *vnm = vnet_get_main ();
  vlib_combined_counter_main_t *ccm =
    vnm->interface_main.combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX;
  memif_per_thread_data_t *ptd =
    vec_elt_at_index (mm->per_thread_data, vm->thread_index);

  vnet_hw_if_rxq_poll_vector_t *pv;
  pv = vnet_hw_if_get_rxq_poll_vector (vm, node);
  for (u32 i = 0; i < vec_len (pv); i++)
    {
      memif_if_t *mif;
      memif_queue_t *mq;
      u32 flags_match = (MEMIF_IF_FLAG_ADMIN_UP | MEMIF_IF_FLAG_CONNECTED);
      u32 flags_mask = (MEMIF_IF_FLAG_ERROR | MEMIF_IF_FLAG_ADMIN_UP |
			MEMIF_IF_FLAG_CONNECTED);

      mif = vec_elt_at_index (mm->interfaces, pv[i].dev_instance);

      if ((mif->flags & flags_mask) != flags_match)
	continue;

      mq = vec_elt_at_index (mif->rx_queues, pv[i].queue_id);
      ptd->n_packets = 0;

      if (mif->flags & MEMIF_IF_FLAG_ZERO_COPY)
	memif_device_input_zc_inline (vm, node, ptd, mif, mq);
      else
	memif_device_input_inline (vm, node, ptd, mif, mq);

      if (ptd->n_packets == 0)
	continue;

      vlib_increment_combined_counter (ccm, vm->thread_index, mif->sw_if_index,
				       ptd->n_packets, ptd->n_bytes);
      n_rx += ptd->n_packets;
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
