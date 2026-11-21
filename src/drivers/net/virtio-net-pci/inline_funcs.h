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

static_always_inline virtio_net_hdr_t *
virtio_net_rx_hdr (vlib_buffer_t *b)
{
  return (virtio_net_hdr_t *) (b->data - VIRTIO_NET_HDR_V1_SZ);
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
vnp_rxq_publish (vnp_rxq_t *q)
{
  if (q->packed)
    {
      __atomic_thread_fence (__ATOMIC_SEQ_CST);

      if (__atomic_load_n (&q->device_event->flags, __ATOMIC_RELAXED) == VRING_EVENT_F_DISABLE)
	return;
    }
  else
    {
      __atomic_store_n (&q->avail->idx, q->avail_index, __ATOMIC_RELEASE);
      __atomic_thread_fence (__ATOMIC_SEQ_CST);

      if (__atomic_load_n (&q->used->flags, __ATOMIC_RELAXED) & VRING_USED_F_NO_NOTIFY)
	return;
    }

  vnp_reg_wr16 (q->notify, q->id);
}

/* free running index, the wrap counter is the bit above the ring position */
static_always_inline u16
vnp_packed_avail_flags (u16 index, u16 size)
{
  return (index & size) ? VRING_DESC_F_USED : VRING_DESC_F_AVAIL;
}

static_always_inline u8
vnp_packed_is_used (u16 flags, u16 index, u16 size)
{
  u16 both = VRING_DESC_F_AVAIL | VRING_DESC_F_USED;

  return (flags & both) == ((index & size) ? 0 : both);
}

static_always_inline void
vnp_txq_sync_used (vnp_txq_t *q, u16 size)
{
  u16 mask = size - 1, used, index, last_used = q->last_used, outstanding = q->packed_outstanding;
  u16 *packed_count = q->packed_count;
  pvirtq_desc_t *packed = q->packed;
  virtq_used_elem_t *ring = q->used->ring;

  if (!packed)
    return;

  used = q->packed_used;
  index = q->used->idx;

  while (outstanding && (u16) (index - last_used) < size)
    {
      pvirtq_desc_t *d = packed + (used & mask);
      u16 flags = __atomic_load_n (&d->flags, __ATOMIC_ACQUIRE);
      u16 head, count;

      if (!vnp_packed_is_used (flags, used, size))
	break;

      head = d->id;

      if (head >= size || !packed_count[head])
	break;

      count = packed_count[head];
      ring[index++ & mask] = (virtq_used_elem_t) {
	.id = head,
	.len = d->len,
      };
      packed_count[head] = 0;
      outstanding -= count;
      used += count;
    }

  q->packed_outstanding = outstanding;
  q->packed_used = used;
  __atomic_store_n (&q->used->idx, index, __ATOMIC_RELEASE);
}

static_always_inline void
vnp_txq_reclaim (vlib_main_t *vm, vnp_txq_t *q, u16 size)
{
  u16 mask = size - 1, used, last_used, n_free = q->n_free, *free_ids = q->free_ids;
  u32 buffers[64], n_buffers = 0, *buffer_indices = q->buffer_indices;
  virtq_used_elem_t *ring = q->used->ring;
  virtq_desc_t *desc = q->desc;

  vnp_txq_sync_used (q, size);
  last_used = q->last_used;
  used = __atomic_load_n (&q->used->idx, __ATOMIC_ACQUIRE);
  ASSERT ((u16) (used - last_used) <= size);

  while (last_used != used)
    {
      u32 head = ring[last_used++ & mask].id;
      u16 id = head;

      ASSERT (head < size && buffer_indices[head] != VLIB_BUFFER_INVALID_INDEX);

      buffers[n_buffers++] = buffer_indices[head];
      buffer_indices[head] = VLIB_BUFFER_INVALID_INDEX;

      if (n_buffers == ARRAY_LEN (buffers))
	{
	  /* coverity[overrun-buffer-val] - flushed when n_buffers reaches ARRAY_LEN */
	  vlib_buffer_free (vm, buffers, n_buffers);
	  n_buffers = 0;
	}

      while (1)
	{
	  virtq_desc_t d = desc[id];
	  free_ids[n_free++] = id;

	  if (!(d.flags & VRING_DESC_F_NEXT))
	    break;

	  id = d.next;
	}
    }

  q->last_used = last_used;
  q->n_free = n_free;

  if (n_buffers)
    /* coverity[overrun-buffer-val] - n_buffers is at most ARRAY_LEN (buffers) */
    vlib_buffer_free (vm, buffers, n_buffers);
}

static_always_inline u32
vnp_rxq_alloc_batch (vlib_main_t *vm, vnet_dev_t *dev, u8 pool_index, u32 *buffers,
		     vlib_buffer_t **bufs, uword *dma)
{
  const u32 batch_sz = VNP_RX_REFILL_BATCH_SZ;

  if (!vlib_buffer_strict_alloc_from_pool (vm, buffers, batch_sz, pool_index))
    return 0;

  vlib_get_buffers (vm, buffers, bufs, batch_sz);
  vnet_dev_va_to_iova (dev, (void **) dma, (void **) bufs, batch_sz,
		       STRUCT_OFFSET_OF (vlib_buffer_t, data) - VIRTIO_NET_HDR_V1_SZ);

  return 1;
}

static_always_inline u32
vnp_rxq_refill_batch_packed (vlib_main_t *vm, vnp_rxq_t *q, vnet_dev_t *dev, u8 pool_index,
			     u16 size, u16 *n_free_p, u16 *packed_avail_p)
{
  u32 buffers[VNP_RX_REFILL_BATCH_SZ];
  vlib_buffer_t *bufs[VNP_RX_REFILL_BATCH_SZ];
  uword dma[VNP_RX_REFILL_BATCH_SZ];
  u16 mask = size - 1, n_free = *n_free_p, packed_avail = *packed_avail_p, desc_len = q->desc_len;
  u16 *free_ids = q->free_ids;
  u32 *buffer_indices = q->buffer_indices;
  pvirtq_desc_t *packed = q->packed, *first = packed + (packed_avail & mask);
  u16 first_flags = VRING_DESC_F_WRITE | vnp_packed_avail_flags (packed_avail, size);
  u16 id = free_ids[--n_free];

  if (!vnp_rxq_alloc_batch (vm, dev, pool_index, buffers, bufs, dma))
    return 0;

  buffer_indices[id] = buffers[0];
  *virtio_net_rx_hdr (bufs[0]) = (virtio_net_hdr_t) {};
  first->addr = dma[0];
  first->len = desc_len;
  first->id = id;

  packed_avail++;

  for (u32 i = 1; i < VNP_RX_REFILL_BATCH_SZ; i++, packed_avail++)
    {
      pvirtq_desc_t *d = packed + (packed_avail & mask);

      id = free_ids[--n_free];
      buffer_indices[id] = buffers[i];
      *virtio_net_rx_hdr (bufs[i]) = (virtio_net_hdr_t) {};
      d->addr = dma[i];
      d->len = desc_len;
      d->id = id;
      __atomic_store_n (&d->flags, VRING_DESC_F_WRITE | vnp_packed_avail_flags (packed_avail, size),
			__ATOMIC_RELAXED);
    }

  __atomic_store_n (&first->flags, first_flags, __ATOMIC_RELEASE);

  *n_free_p = n_free;
  *packed_avail_p = packed_avail;

  return 1;
}

static_always_inline u32
vnp_rxq_refill_batch_split (vlib_main_t *vm, vnp_rxq_t *q, vnet_dev_t *dev, u8 pool_index, u16 size,
			    u16 *n_free_p, u16 *avail_index_p)
{
  u32 buffers[VNP_RX_REFILL_BATCH_SZ];
  vlib_buffer_t *bufs[VNP_RX_REFILL_BATCH_SZ];
  uword dma[VNP_RX_REFILL_BATCH_SZ];
  u16 mask = size - 1, n_free = *n_free_p, avail_index = *avail_index_p;
  u16 *free_ids = q->free_ids, *ring = q->avail->ring;
  u32 *buffer_indices = q->buffer_indices;
  virtq_desc_t *desc = q->desc;

  if (!vnp_rxq_alloc_batch (vm, dev, pool_index, buffers, bufs, dma))
    return 0;

  for (u32 i = 0; i < VNP_RX_REFILL_BATCH_SZ; i++)
    {
      u16 id = free_ids[--n_free];

      buffer_indices[id] = buffers[i];
      *virtio_net_rx_hdr (bufs[i]) = (virtio_net_hdr_t) {};
      desc[id].addr = dma[i];
      ring[avail_index++ & mask] = id;
    }

  *n_free_p = n_free;
  *avail_index_p = avail_index;

  return 1;
}

static_always_inline u32
vnp_rxq_refill (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnp_rxq_t *q = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_t *dev = rxq->port->dev;
  u16 n_free = q->n_free, avail_index = q->avail_index, packed_avail = q->packed_avail;
  u8 pool_index = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  const u32 batch_sz = VNP_RX_REFILL_BATCH_SZ;

  if (q->packed)
    {
      while (n_free >= batch_sz)
	if (!vnp_rxq_refill_batch_packed (vm, q, dev, pool_index, rxq->size, &n_free,
					  &packed_avail))
	  break;
    }
  else
    {
      while (n_free >= batch_sz)
	if (!vnp_rxq_refill_batch_split (vm, q, dev, pool_index, rxq->size, &n_free, &avail_index))
	  break;
    }

  if (n_free != q->n_free)
    {
      q->n_free = n_free;
      q->avail_index = avail_index;
      q->packed_avail = packed_avail;
      vnp_rxq_publish (q);
    }

  return n_free >= batch_sz ? batch_sz : 0;
}

static_always_inline void
vnp_rxq_irq (vlib_main_t *vm __clib_unused, vnet_dev_rx_queue_t *rxq, u8 enable)
{
  vnp_rxq_t *q = vnet_dev_get_rx_queue_data (rxq);
  u16 event = enable ? VRING_EVENT_F_ENABLE : VRING_EVENT_F_DISABLE;
  u8 pending;

  if (q->packed)
    {
      u16 flags;

      __atomic_store_n (&q->driver_event->flags, event, __ATOMIC_RELEASE);
      CLIB_MEMORY_BARRIER ();
      flags =
	__atomic_load_n (&q->packed[q->packed_used & (rxq->size - 1)].flags, __ATOMIC_ACQUIRE);
      pending = vnp_packed_is_used (flags, q->packed_used, rxq->size);
    }
  else
    {
      __atomic_store_n (&q->avail->flags, event, __ATOMIC_RELEASE);
      CLIB_MEMORY_BARRIER ();
      pending = __atomic_load_n (&q->used->idx, __ATOMIC_ACQUIRE) != q->last_used;
    }

  if (enable && pending)
    vlib_node_set_interrupt_pending (vlib_get_main_by_index (rxq->rx_thread_index),
				     vnet_dev_get_port_rx_node_index (rxq->port));
}
