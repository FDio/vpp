/* SPDX-License-Identifier: Apache-2.0 */
#include <inline_funcs.h>

vnet_dev_rv_t
vnp_rxq_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  vnp_dev_t *vd = vnet_dev_get_data (dev);
  vnp_rxq_t *q = vnet_dev_get_rx_queue_data (rxq);
  u16 size = rxq->size;
  void *mem, *packed;
  vnet_dev_rv_t rv;

  rv = vnet_dev_dma_mem_alloc (vm, dev, vnp_ring_size (size), 4096, &mem, "virtio rx queue %u",
			       rxq->queue_id);
  if (rv)
    return rv;

  if (vd->features & VIRTIO_F_RING_PACKED_BIT)
    {
      rv = vnet_dev_dma_mem_alloc (vm, dev, size * sizeof (pvirtq_desc_t) + 8, 4096, &packed,
				   "virtio rx packed queue %u", rxq->queue_id);
      if (rv)
	{
	  vnet_dev_dma_mem_free (vm, dev, mem);
	  return rv;
	}

      q->packed = packed;
      vec_validate (q->packed_count, size - 1);
    }

  q->desc = mem;
  q->avail = mem + size * sizeof (virtq_desc_t);
  q->used = mem + vnp_used_offset (size);
  q->id = rxq->queue_id * 2;
  vec_validate (q->free_ids, size - 1);
  vec_validate (q->buffer_indices, size - 1);

  for (u32 i = 0; i < size; i++)
    q->buffer_indices[i] = VLIB_BUFFER_INVALID_INDEX;

  return VNET_DEV_OK;
}

static vnet_dev_rv_t
vnp_txq_ring_alloc (vlib_main_t *vm, vnet_dev_t *dev, vnp_txq_t *q, u16 size, u16 id, u8 indirect)
{
  vnp_dev_t *vd = vnet_dev_get_data (dev);
  u32 ring_size = vnp_ring_size (size);
  u32 indirect_size = indirect ? size * VNP_INDIRECT_STRIDE * sizeof (virtq_desc_t) : 0;
  void *mem, *packed;
  vnet_dev_rv_t rv;

  rv = vnet_dev_dma_mem_alloc (vm, dev, ring_size + indirect_size, 4096, &mem, "virtio tx queue %u",
			       id);
  if (rv)
    return rv;

  if (vd->features & VIRTIO_F_RING_PACKED_BIT)
    {
      rv = vnet_dev_dma_mem_alloc (vm, dev, size * sizeof (pvirtq_desc_t) + 8, 4096, &packed,
				   "virtio tx packed queue %u", id);
      if (rv)
	{
	  vnet_dev_dma_mem_free (vm, dev, mem);
	  return rv;
	}

      q->packed = packed;
      vec_validate (q->packed_count, size - 1);
    }

  q->desc = mem;
  q->avail = mem + size * sizeof (virtq_desc_t);
  q->used = mem + vnp_used_offset (size);

  if (indirect)
    q->indirect = mem + ring_size;

  q->id = id;
  vec_validate (q->free_ids, size - 1);
  vec_validate (q->buffer_indices, size - 1);

  for (u32 i = 0; i < size; i++)
    q->buffer_indices[i] = VLIB_BUFFER_INVALID_INDEX;

  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnp_txq_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  vnp_dev_t *vd = vnet_dev_get_data (dev);

  return vnp_txq_ring_alloc (vm, dev, vnet_dev_get_tx_queue_data (txq), txq->size,
			     txq->queue_id * 2 + 1,
			     (vd->features & VIRTIO_RING_F_INDIRECT_DESC_BIT) != 0);
}

void
vnp_rxq_release (vlib_main_t *vm, vnp_rxq_t *q, u16 size)
{
  for (u32 i = 0; i < size; i++)
    if (q->buffer_indices[i] != VLIB_BUFFER_INVALID_INDEX)
      {
	vlib_buffer_free (vm, q->buffer_indices + i, 1);
	q->buffer_indices[i] = VLIB_BUFFER_INVALID_INDEX;
      }
}

void
vnp_txq_release (vlib_main_t *vm, vnp_txq_t *q, u16 size)
{
  for (u32 i = 0; i < size; i++)
    if (q->buffer_indices[i] != VLIB_BUFFER_INVALID_INDEX)
      {
	vlib_buffer_free (vm, q->buffer_indices + i, 1);
	q->buffer_indices[i] = VLIB_BUFFER_INVALID_INDEX;
      }
}

static void
vnp_rxq_ring_free (vlib_main_t *vm, vnet_dev_t *dev, vnp_rxq_t *q, u16 size)
{
  vnp_rxq_release (vm, q, size);

  if (q->desc)
    vnet_dev_dma_mem_free (vm, dev, q->desc);

  if (q->packed)
    vnet_dev_dma_mem_free (vm, dev, q->packed);

  vec_free (q->packed_count);
  vec_free (q->free_ids);
  vec_free (q->buffer_indices);
  *q = (vnp_rxq_t) {};
}

static void
vnp_txq_ring_free (vlib_main_t *vm, vnet_dev_t *dev, vnp_txq_t *q, u16 size)
{
  vnp_txq_release (vm, q, size);

  if (q->desc)
    vnet_dev_dma_mem_free (vm, dev, q->desc);

  if (q->packed)
    vnet_dev_dma_mem_free (vm, dev, q->packed);

  vec_free (q->packed_count);
  vec_free (q->free_ids);
  vec_free (q->buffer_indices);
  *q = (vnp_txq_t) {};
}

void
vnp_rxq_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnp_rxq_ring_free (vm, rxq->port->dev, vnet_dev_get_rx_queue_data (rxq), rxq->size);
}

void
vnp_txq_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnp_txq_ring_free (vm, txq->port->dev, vnet_dev_get_tx_queue_data (txq), txq->size);
}

vnet_dev_rv_t
vnp_queue_enable (vlib_main_t *vm, vnet_dev_t *dev, u16 id, u16 size, void *desc_area,
		  void *driver_area, void *device_area, u16 **notify)
{
  vnp_dev_t *vd = vnet_dev_get_data (dev);
  virtio_pci_common_cfg_t *c = vd->common;
  u64 addr, notify_offset;

  vnp_reg_wr16 (&c->queue_select, id);

  if (vnp_reg_rd16 (&c->queue_size) < size)
    return VNET_DEV_ERR_NOT_SUPPORTED;

  notify_offset = (u64) vnp_reg_rd16 (&c->queue_notify_off) * vd->notify_multiplier;

  if ((notify_offset & 1) || notify_offset + 2 > vd->notify_length)
    return VNET_DEV_ERR_INVALID_DATA;

  *notify = vd->notify + notify_offset;
  vnp_reg_wr16 (&c->queue_size, size);
  vnp_reg_wr16 (&c->queue_msix_vector, 0xffff);
  addr = vnet_dev_get_dma_addr (vm, dev, desc_area);
  vnp_reg_wr32 (&c->queue_desc_lo, addr);
  vnp_reg_wr32 (&c->queue_desc_hi, addr >> 32);
  addr = vnet_dev_get_dma_addr (vm, dev, driver_area);
  vnp_reg_wr32 (&c->queue_driver_lo, addr);
  vnp_reg_wr32 (&c->queue_driver_hi, addr >> 32);
  addr = vnet_dev_get_dma_addr (vm, dev, device_area);
  vnp_reg_wr32 (&c->queue_device_lo, addr);
  vnp_reg_wr32 (&c->queue_device_hi, addr >> 32);
  vnp_reg_wr16 (&c->queue_enable, 1);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnp_rxq_start (vlib_main_t *vm, vnet_dev_t *dev, vnp_rxq_t *q, u16 size, u16 desc_len)
{
  vnp_dev_t *vd = vnet_dev_get_data (dev);
  void *desc_area = q->desc, *driver_area = q->avail, *device_area = q->used;

  q->last_used = q->avail_index = 0;
  q->n_free = size;
  q->packed_avail = q->packed_used = q->published = q->packed_outstanding = 0;

  if (q->packed_count)
    clib_memset (q->packed_count, 0, size * sizeof (q->packed_count[0]));

  q->avail_wrap = q->used_wrap = 1;
  q->mrg_rxbuf = (vd->features & VIRTIO_NET_F_MRG_RXBUF_BIT) != 0;

  if (q->packed)
    {
      pvirtq_event_suppress_t *driver_event = (void *) (q->packed + size);

      clib_memset (q->packed, 0, size * sizeof (q->packed[0]) + 8);
      driver_event->flags = VRING_EVENT_F_DISABLE;
      q->driver_event = driver_event;
      desc_area = q->packed;
      driver_area = driver_event;
      device_area = driver_event + 1;
    }

  clib_memset (q->avail, 0, 6 + 2 * size);
  clib_memset (q->used, 0, 6 + 8 * size);
  q->avail->flags = VRING_AVAIL_F_NO_INTERRUPT;

  for (u32 i = 0; i < size; i++)
    {
      q->free_ids[i] = i;
      q->desc[i] = (virtq_desc_t) {
	.len = desc_len,
	.flags = VRING_DESC_F_WRITE,
      };
      ASSERT (q->buffer_indices[i] == VLIB_BUFFER_INVALID_INDEX);
    }

  return vnp_queue_enable (vm, dev, q->id, size, desc_area, driver_area, device_area, &q->notify);
}

vnet_dev_rv_t
vnp_txq_start (vlib_main_t *vm, vnet_dev_t *dev, vnp_txq_t *q, u16 size)
{
  void *desc_area = q->desc, *driver_area = q->avail, *device_area = q->used;

  q->last_used = q->avail_index = 0;
  q->n_free = size;
  q->packed_avail = q->packed_used = q->published = q->packed_outstanding = 0;

  if (q->packed_count)
    clib_memset (q->packed_count, 0, size * sizeof (q->packed_count[0]));

  q->avail_wrap = q->used_wrap = 1;
  if (q->indirect)
    q->indirect_dma = vnet_dev_get_dma_addr (vm, dev, q->indirect);

  if (q->packed)
    {
      pvirtq_event_suppress_t *driver_event = (void *) (q->packed + size);

      clib_memset (q->packed, 0, size * sizeof (q->packed[0]) + 8);
      driver_event->flags = VRING_EVENT_F_DISABLE;
      desc_area = q->packed;
      driver_area = driver_event;
      device_area = driver_event + 1;
    }

  clib_memset (q->avail, 0, 6 + 2 * size);
  clib_memset (q->used, 0, 6 + 8 * size);
  q->avail->flags = VRING_AVAIL_F_NO_INTERRUPT;

  for (u32 i = 0; i < size; i++)
    {
      q->free_ids[i] = i;
      q->desc[i] = (virtq_desc_t) {};
      ASSERT (q->buffer_indices[i] == VLIB_BUFFER_INVALID_INDEX);
    }

  return vnp_queue_enable (vm, dev, q->id, size, desc_area, driver_area, device_area, &q->notify);
}
