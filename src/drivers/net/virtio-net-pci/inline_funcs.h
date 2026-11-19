/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <virtio_net_pci.h>

/* the virtio-net header of a TX packet sits in the headroom right before the packet data */
static_always_inline virtio_net_hdr_t *
virtio_net_hdr (vlib_buffer_t *b)
{
  ASSERT (b->current_data >= VIRTIO_NET_HDR_V1_SZ - VLIB_BUFFER_PRE_DATA_SIZE);
  return vlib_buffer_get_current (b) - VIRTIO_NET_HDR_V1_SZ;
}

/* adds val to the elements of an array, the element count is rounded up to the vector width, so
 * the array must be padded */
static_always_inline void
vnp_u16_add (u16 *p, u32 n_elts, u16 val)
{
#if defined(CLIB_HAVE_VEC512)
  u16x32 v = u16x32_splat (val);

  for (u32 i = 0; i < n_elts; i += 32)
    *(u16x32u *) (p + i) += v;
#elif defined(CLIB_HAVE_VEC256)
  u16x16 v = u16x16_splat (val);

  for (u32 i = 0; i < n_elts; i += 16)
    *(u16x16u *) (p + i) += v;
#elif defined(CLIB_HAVE_VEC128)
  u16x8 v = u16x8_splat (val);

  for (u32 i = 0; i < n_elts; i += 8)
    *(u16x8u *) (p + i) += v;
#else
  for (u32 i = 0; i < n_elts; i++)
    p[i] += val;
#endif
}

/* indirect descriptor table of a TX slot */
static_always_inline void *
vnp_txq_indirect (vnp_txq_t *q, u16 head)
{
  return q->indirect + head * VNP_INDIRECT_STRIDE;
}

static_always_inline u64
vnp_txq_indirect_dma (vnp_txq_t *q, u16 head)
{
  return q->indirect_dma + head * VNP_INDIRECT_STRIDE * sizeof (virtq_desc_t);
}

static_always_inline u32
vnp_used_offset (u16 size)
{
  return round_pow2 (size * sizeof (virtq_desc_t) + 6 + 2 * size, 4);
}

static_always_inline u32
vnp_ring_size (u16 size)
{
  return round_pow2 (vnp_used_offset (size) + 6 + 8 * size, 64);
}

static_always_inline u8
vnp_reg_rd8 (u8 *r)
{
  return __atomic_load_n (r, __ATOMIC_RELAXED);
}

static_always_inline void
vnp_reg_wr8 (u8 *r, u8 v)
{
  __atomic_store_n (r, v, __ATOMIC_RELEASE);
}

static_always_inline u16
vnp_reg_rd16 (u16 *r)
{
  return __atomic_load_n (r, __ATOMIC_RELAXED);
}

static_always_inline void
vnp_reg_wr16 (u16 *r, u16 v)
{
  __atomic_store_n (r, v, __ATOMIC_RELEASE);
}

static_always_inline u32
vnp_reg_rd32 (u32 *r)
{
  return __atomic_load_n (r, __ATOMIC_RELAXED);
}

static_always_inline void
vnp_reg_wr32 (u32 *r, u32 v)
{
  __atomic_store_n (r, v, __ATOMIC_RELEASE);
}

static_always_inline void
vnp_rxq_packed_publish (vnp_rxq_t *q, u16 size)
{
  u16 mask = size - 1, avail = q->packed_avail;
  u8 wrap = q->avail_wrap;

  while (q->published != q->avail_index)
    {
      u16 head = q->avail->ring[q->published & mask];
      u16 id = head, first = avail, first_flags = 0, n = 0;

      while (1)
	{
	  virtq_desc_t d = q->desc[id];
	  u16 flags = d.flags;
	  u16 packed_flags = flags | (wrap ? VRING_DESC_F_AVAIL : VRING_DESC_F_USED);

	  q->packed[avail].addr = d.addr;
	  q->packed[avail].len = d.len;
	  q->packed[avail].id = head;

	  if (n == 0)
	    first_flags = packed_flags;
	  else
	    __atomic_store_n (&q->packed[avail].flags, packed_flags, __ATOMIC_RELEASE);

	  n++;

	  if (++avail == size)
	    {
	      avail = 0;
	      wrap ^= 1;
	    }

	  if (!(flags & VRING_DESC_F_NEXT))
	    break;

	  id = d.next;
	}

      q->packed_count[head] = n;
      q->packed_outstanding += n;
      ASSERT (q->packed_outstanding <= size);
      __atomic_store_n (&q->packed[first].flags, first_flags, __ATOMIC_RELEASE);
      q->published++;
    }

  q->packed_avail = avail;
  q->avail_wrap = wrap;
}

static_always_inline void
vnp_rxq_sync_used (vnp_rxq_t *q, u16 size)
{
  u16 mask = size - 1, used, index;
  u8 wrap;

  if (!q->packed)
    return;

  used = q->packed_used;
  wrap = q->used_wrap;
  index = q->used->idx;

  while (q->packed_outstanding && (u16) (index - q->last_used) < size)
    {
      u16 flags = __atomic_load_n (&q->packed[used].flags, __ATOMIC_ACQUIRE);
      u16 head, count;

      if (((flags >> 7) & 1) != wrap || ((flags >> 15) & 1) != wrap)
	break;

      head = q->packed[used].id;

      if (head >= size || !q->packed_count[head])
	break;

      count = q->packed_count[head];
      q->used->ring[index++ & mask] = (virtq_used_elem_t) {
	.id = head,
	.len = q->packed[used].len,
      };
      q->packed_count[head] = 0;
      q->packed_outstanding -= count;
      used += count;

      if (used >= size)
	{
	  used -= size;
	  wrap ^= 1;
	}
    }

  q->packed_used = used;
  q->used_wrap = wrap;
  __atomic_store_n (&q->used->idx, index, __ATOMIC_RELEASE);
}

static_always_inline void
vnp_rxq_publish (vnp_rxq_t *q, u16 size)
{
  if (q->packed)
    vnp_rxq_packed_publish (q, size);

  __atomic_store_n (&q->avail->idx, q->avail_index, __ATOMIC_RELEASE);
  vnp_reg_wr16 (q->notify, q->id);
}

static_always_inline void
vnp_txq_packed_publish (vnp_txq_t *q, u16 size)
{
  u16 mask = size - 1, avail = q->packed_avail;
  u8 wrap = q->avail_wrap;

  while (q->published != q->avail_index)
    {
      u16 head = q->avail->ring[q->published & mask];
      u16 id = head, first = avail, first_flags = 0, n = 0;

      while (1)
	{
	  virtq_desc_t d = q->desc[id];
	  u16 flags = d.flags;
	  u16 packed_flags = flags | (wrap ? VRING_DESC_F_AVAIL : VRING_DESC_F_USED);

	  q->packed[avail].addr = d.addr;
	  q->packed[avail].len = d.len;
	  q->packed[avail].id = head;

	  if (n == 0)
	    first_flags = packed_flags;
	  else
	    __atomic_store_n (&q->packed[avail].flags, packed_flags, __ATOMIC_RELEASE);

	  n++;

	  if (++avail == size)
	    {
	      avail = 0;
	      wrap ^= 1;
	    }

	  if (!(flags & VRING_DESC_F_NEXT))
	    break;

	  id = d.next;
	}

      q->packed_count[head] = n;
      q->packed_outstanding += n;
      ASSERT (q->packed_outstanding <= size);
      __atomic_store_n (&q->packed[first].flags, first_flags, __ATOMIC_RELEASE);
      q->published++;
    }

  q->packed_avail = avail;
  q->avail_wrap = wrap;
}

static_always_inline void
vnp_txq_sync_used (vnp_txq_t *q, u16 size)
{
  u16 mask = size - 1, used, index;
  u8 wrap;

  if (!q->packed)
    return;

  used = q->packed_used;
  wrap = q->used_wrap;
  index = q->used->idx;

  while (q->packed_outstanding && (u16) (index - q->last_used) < size)
    {
      u16 flags = __atomic_load_n (&q->packed[used].flags, __ATOMIC_ACQUIRE);
      u16 head, count;

      if (((flags >> 7) & 1) != wrap || ((flags >> 15) & 1) != wrap)
	break;

      head = q->packed[used].id;

      if (head >= size || !q->packed_count[head])
	break;

      count = q->packed_count[head];
      q->used->ring[index++ & mask] = (virtq_used_elem_t) {
	.id = head,
	.len = q->packed[used].len,
      };
      q->packed_count[head] = 0;
      q->packed_outstanding -= count;
      used += count;

      if (used >= size)
	{
	  used -= size;
	  wrap ^= 1;
	}
    }

  q->packed_used = used;
  q->used_wrap = wrap;
  __atomic_store_n (&q->used->idx, index, __ATOMIC_RELEASE);
}

static_always_inline u32
vnp_txq_reclaim (vlib_main_t *vm, vnp_txq_t *q, u16 size)
{
  u16 mask = size - 1, used;

  vnp_txq_sync_used (q, size);
  used = __atomic_load_n (&q->used->idx, __ATOMIC_ACQUIRE);

  if (PREDICT_FALSE ((u16) (used - q->last_used) > size))
    return 1;

  while (q->last_used != used)
    {
      u32 head = q->used->ring[q->last_used++ & mask].id;
      u16 id;

      if (PREDICT_FALSE (head >= size || q->buffer_indices[head] == VLIB_BUFFER_INVALID_INDEX))
	return 1;

      vlib_buffer_free (vm, q->buffer_indices + head, 1);
      q->buffer_indices[head] = VLIB_BUFFER_INVALID_INDEX;
      id = head;

      while (1)
	{
	  virtq_desc_t d = q->desc[id];
	  q->free_ids[q->n_free++] = id;

	  if (!(d.flags & VRING_DESC_F_NEXT))
	    break;

	  id = d.next;
	}
    }

  return 0;
}

static_always_inline u32
vnp_rxq_refill (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnp_rxq_t *q = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_t *dev = rxq->port->dev;
  u32 buffers[256];
  vlib_buffer_t *bufs[256];
  uword dma[256];
  u16 n_free = q->n_free, avail_index = q->avail_index, mask = rxq->size - 1;
  u32 wanted = clib_min (n_free, ARRAY_LEN (buffers));
  u32 n = vlib_buffer_alloc_from_pool (vm, buffers, wanted,
				       vnet_dev_get_rx_queue_buffer_pool_index (rxq));

  vlib_get_buffers (vm, buffers, bufs, n);
  vnet_dev_va_to_iova (dev, (void **) dma, (void **) bufs, n,
		       STRUCT_OFFSET_OF (vlib_buffer_t, data) - VIRTIO_NET_HDR_V1_SZ);

  for (u32 i = 0; i < n; i++)
    {
      u16 id = q->free_ids[--n_free];
      vlib_buffer_t *b = bufs[i];
      void *header = b->data - VIRTIO_NET_HDR_V1_SZ;

      q->buffer_indices[id] = buffers[i];
      clib_memset (header, 0, VIRTIO_NET_HDR_V1_SZ);
      q->desc[id].addr = dma[i];
      q->avail->ring[avail_index++ & mask] = id;
    }

  q->n_free = n_free;
  q->avail_index = avail_index;

  if (n)
    vnp_rxq_publish (q, rxq->size);

  return wanted - n;
}

static_always_inline void
vnp_rxq_irq (vlib_main_t *vm __clib_unused, vnet_dev_rx_queue_t *rxq, u8 enable)
{
  vnp_rxq_t *q = vnet_dev_get_rx_queue_data (rxq);
  u16 event = enable ? VRING_EVENT_F_ENABLE : VRING_EVENT_F_DISABLE;
  u8 pending;

  __atomic_store_n (&q->avail->flags, event, __ATOMIC_RELEASE);

  if (q->packed)
    __atomic_store_n (&q->driver_event->flags, event, __ATOMIC_RELEASE);

  CLIB_MEMORY_BARRIER ();
  pending = __atomic_load_n (&q->used->idx, __ATOMIC_ACQUIRE) != q->last_used;

  if (q->packed && q->packed_outstanding)
    {
      u16 flags = __atomic_load_n (&q->packed[q->packed_used].flags, __ATOMIC_ACQUIRE);
      pending |= ((flags & VRING_DESC_F_AVAIL) != 0) == q->used_wrap &&
		 ((flags & VRING_DESC_F_USED) != 0) == q->used_wrap;
    }

  if (enable && pending)
    vlib_node_set_interrupt_pending (vlib_get_main_by_index (rxq->rx_thread_index),
				     vnet_dev_get_port_rx_node_index (rxq->port));
}
