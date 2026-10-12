/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/platform.h>
#include <vlib/buffer_funcs.h>
#include <qppe.h>

VLIB_REGISTER_LOG_CLASS (qppe_log, static) = {
  .class_name = "qppe",
  .subclass_name = "edma",
};

#define log_debug(dev, f, ...)                                                                     \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, qppe_log.class, "%U" f, format_vnet_dev_log, (dev),              \
	    clib_string_skip_prefix (__func__, "qppe_"), ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                                       \
  vlib_log (VLIB_LOG_LEVEL_ERR, qppe_log.class, "%U" f, format_vnet_dev_log, (dev), 0,             \
	    ##__VA_ARGS__)

void
qppe_edma_rx_ring_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);
  u32 mask = rxq->size - 1;
  u32 slot = (qr->fill_prod - qr->n_buffers) & mask;

  if (qr->buffer_indices)
    {
      u32 i;

      for (i = 0; i < qr->n_buffers; i++)
	{
	  vlib_buffer_free (vm, &qr->buffer_indices[slot], 1);
	  slot++;
	  if (slot == rxq->size)
	    slot = 0;
	}
      clib_mem_free (qr->buffer_indices);
      qr->buffer_indices = 0;
      qr->n_buffers = 0;
    }

  if (qr->fill_descs)
    vnet_dev_dma_mem_free (vm, dev, qr->fill_descs);
  if (qr->primary_descs)
    vnet_dev_dma_mem_free (vm, dev, qr->primary_descs);
  if (qr->secondary_descs)
    vnet_dev_dma_mem_free (vm, dev, qr->secondary_descs);
  qr->fill_descs = 0;
  qr->primary_descs = 0;
  qr->secondary_descs = 0;
}

static vnet_dev_rv_t
qppe_edma_rx_queue_mapping_configure (vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_port_t *qp = vnet_dev_get_port_data (rxq->port);
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);
  u32 profile = qp->source_profile;
  u32 ring_profile = qr->desc_ring_id - PPE_EDMA_RXDESC_RING_START;
  u32 queue_base = profile * PPE_EDMA_RX_QUEUES_PER_RING;
  u32 offset, value, i;

  if (profile >= PPE_EDMA_RX_RING_COUNT || profile != ring_profile ||
      rxq->port->port_id >= PPE_MAX_PORTS)
    {
      log_err (dev, "cannot map RX queue %u on port %u source profile %u to EDMA ring %u",
	       rxq->queue_id, rxq->port->port_id, profile, qr->desc_ring_id);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  if (qd->n_active_rx_queues == 0)
    {
      for (i = 0; i < PPE_EDMA_RX_RING_COUNT; i++)
	{
	  u32 queue_map[PPE_EDMA_RING_Q_MAP_WORDS] = {};
	  u32 queue_first = i * PPE_EDMA_RX_QUEUES_PER_RING;
	  u32 j;

	  for (j = 0; j < PPE_EDMA_RX_QUEUES_PER_RING; j++)
	    queue_map[(queue_first + j) / 32] |= 1u << ((queue_first + j) % 32);

	  for (j = 0; j < PPE_EDMA_RING_Q_MAP_WORDS; j++)
	    {
	      offset = PPE_REG_RING_Q_MAP_TBL (PPE_EDMA_RXDESC_RING_START + i) + j * sizeof (u32);
	      qppe_mmio_write32 (qd, offset, queue_map[j]);
	    }
	}

      for (i = 0; i < PPE_EDMA_QID2RID_WORD_COUNT; i++)
	{
	  u32 queue_id = i * 4;
	  u32 ring_id = PPE_EDMA_RXDESC_RING_START + (queue_id / PPE_EDMA_RX_QUEUES_PER_RING);

	  value = PPE_EDMA_QID2RID_WORD (ring_id, ring_id, ring_id, ring_id);
	  offset = PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_QID2RID_TABLE (queue_id);
	  qppe_mmio_write32 (qd, offset, value);
	  if (qppe_mmio_read32 (qd, offset) != value)
	    {
	      log_err (dev, "EDMA queue-to-ring map readback failed at offset 0x%x", offset);
	      return VNET_DEV_ERR_INIT_FAILED;
	    }
	}
    }

  for (i = 0; i < 16; i++)
    {
      value = clib_min (i, PPE_EDMA_RX_QUEUES_PER_RING - 1);
      offset = PPE_REG_UCAST_PRIORITY_MAP_TBL (profile, i);
      qppe_mmio_write32 (qd, offset, value);
      if (qppe_mmio_read32 (qd, offset) != value)
	{
	  log_err (dev, "PPE RX priority map readback failed at offset 0x%x", offset);
	  return VNET_DEV_ERR_INIT_FAILED;
	}
    }

  for (i = 0; i < 256; i++)
    {
      offset = PPE_REG_UCAST_HASH_MAP_TBL (profile, i);
      qppe_mmio_write32 (qd, offset, 0);
    }

  {
    ppe_reg_ucast_queue_map_t queue_map = {
      .fields.profile_id = profile,
      .fields.queue_id = queue_base,
    };

    offset = PPE_REG_UCAST_QUEUE_MAP_TBL (profile, 0);
    qppe_mmio_write32 (qd, offset, queue_map.as_u32);
    if (qppe_mmio_read32 (qd, offset) != queue_map.as_u32)
      {
	log_err (dev, "PPE RX queue base readback failed at offset 0x%x", offset);
	return VNET_DEV_ERR_INIT_FAILED;
      }
  }

  offset = PPE_REG_MRU_MTU_CTRL_W1 (rxq->port->port_id);
  {
    ppe_reg_mru_mtu_ctrl_w1_t source_profile = {
      .as_u32 = qppe_mmio_read32 (qd, offset),
    };

    source_profile.fields.source_profile = profile;
    qppe_mmio_write32 (qd, offset, source_profile.as_u32);
    if (((ppe_reg_mru_mtu_ctrl_w1_t) { .as_u32 = qppe_mmio_read32 (qd, offset) })
	  .fields.source_profile != profile)
      {
	log_err (dev, "PPE source profile for port %u did not update", rxq->port->port_id);
	return VNET_DEV_ERR_INIT_FAILED;
      }
  }

  log_debug (dev,
	     "mapped port %u to PPE source profile %u, CPU queue IDs %u-%u, PPE ring %u, "
	     "EDMA descriptor ring %u",
	     rxq->port->port_id, profile, queue_base, queue_base + PPE_EDMA_RX_QUEUES_PER_RING - 1,
	     qr->desc_ring_id, qr->desc_ring_id);

  return VNET_DEV_OK;
}

vnet_dev_rv_t
qppe_edma_rx_ring_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);
  vlib_buffer_pool_t *buffer_pool;
  vnet_dev_rv_t rv;
  u32 desc_size, buffer_size;
  u32 i;
  u8 buffer_pool_index = vlib_buffer_pool_get_default_for_numa (vm, dev->numa_node);

  desc_size = rxq->size * sizeof (ppe_edma_rxfill_desc_t);
  rv = vnet_dev_dma_mem_alloc_coherent (vm, dev, desc_size, CLIB_CACHE_LINE_BYTES,
					(void **) &qr->fill_descs, "EDMA RX fill descriptors");
  if (rv != VNET_DEV_OK)
    return rv;
  qr->fill_dma = vnet_dev_get_dma_addr (vm, dev, qr->fill_descs);

  /* Hardware writes these descriptors; software only ever reads them.
   * Allocate from the coherent arena so a CPU cache line can never serve
   * stale content from before the EDMA engine's write. */
  desc_size = rxq->size * sizeof (ppe_edma_rx_desc_t);
  rv =
    vnet_dev_dma_mem_alloc_coherent (vm, dev, desc_size, CLIB_CACHE_LINE_BYTES,
				     (void **) &qr->primary_descs, "EDMA RX primary descriptors");
  if (rv != VNET_DEV_OK)
    {
      qppe_edma_rx_ring_free (vm, rxq);
      return rv;
    }
  qr->primary_dma = vnet_dev_get_dma_addr (vm, dev, qr->primary_descs);

  rv = vnet_dev_dma_mem_alloc_coherent (vm, dev, desc_size, CLIB_CACHE_LINE_BYTES,
					(void **) &qr->secondary_descs,
					"EDMA RX secondary descriptors");
  if (rv != VNET_DEV_OK)
    {
      qppe_edma_rx_ring_free (vm, rxq);
      return rv;
    }
  qr->secondary_dma = vnet_dev_get_dma_addr (vm, dev, qr->secondary_descs);

  buffer_pool = vlib_get_buffer_pool (vm, buffer_pool_index);
  if (buffer_pool->data_size == 0 || buffer_pool->data_size > 0xffff)
    {
      log_err (dev, "VPP buffer pool %u data size %u cannot be represented by EDMA RX descriptor",
	       buffer_pool_index, buffer_pool->data_size);
      qppe_edma_rx_ring_free (vm, rxq);
      return VNET_DEV_ERR_NOT_SUPPORTED;
    }
  buffer_size = buffer_pool->data_size;

  for (i = 0; i < rxq->size; i++)
    {
      ppe_edma_rxfill_desc_t *desc = &qr->fill_descs[i];

      desc->buffer_size = buffer_size;
      desc->opaque_high = i;
    }

  qr->buffer_indices = clib_mem_alloc_aligned (rxq->size * sizeof (u32), CLIB_CACHE_LINE_BYTES);
  if (qr->buffer_indices == 0)
    {
      log_err (dev, "cannot allocate buffer index table for %u EDMA RX buffers", rxq->size);
      qppe_edma_rx_ring_free (vm, rxq);
      return VNET_DEV_ERR_BUFFER_ALLOC_FAIL;
    }
  clib_memset_u32 (qr->buffer_indices, ~0, rxq->size);

  if (!vlib_buffer_strict_alloc_from_pool (vm, qr->buffer_indices, rxq->size, buffer_pool_index))
    {
      clib_memset_u32 (qr->buffer_indices, ~0, rxq->size);
      log_err (dev, "cannot allocate %u EDMA RX buffers from VPP buffer pool %u", rxq->size,
	       buffer_pool_index);
      qppe_edma_rx_ring_free (vm, rxq);
      return VNET_DEV_ERR_BUFFER_ALLOC_FAIL;
    }
  qr->n_buffers = rxq->size;

  for (i = 0; i < rxq->size; i++)
    {
      u32 buffer_index = qr->buffer_indices[i];
      vlib_buffer_t *buffer = vlib_get_buffer (vm, buffer_index);
      ppe_edma_rxfill_desc_t *desc = &qr->fill_descs[i];
      uword buffer_dma = vnet_dev_get_dma_addr (vm, dev, buffer->data);

      if (i == 0)
	qr->first_buffer_dma = buffer_dma;
      qr->last_buffer_dma = buffer_dma;

      desc->buffer_address = buffer_dma;
      desc->opaque_low = buffer_index;
    }

  log_debug (dev,
	     "allocated RX ring storage: %u descriptors, fill VA %p DMA 0x%lx (%u bytes), "
	     "primary VA %p DMA 0x%lx (%u bytes), secondary VA %p DMA 0x%lx (%u bytes); "
	     "VPP pool %u supplied %u of %u initial packet buffers at %u bytes each, "
	     "first/last DMA 0x%lx/0x%lx; "
	     "fill descriptors initialized; hardware remains disabled and unconfigured",
	     rxq->size, qr->fill_descs, qr->fill_dma, rxq->size * sizeof (ppe_edma_rxfill_desc_t),
	     qr->primary_descs, qr->primary_dma, rxq->size * sizeof (ppe_edma_rx_desc_t),
	     qr->secondary_descs, qr->secondary_dma, rxq->size * sizeof (ppe_edma_rx_desc_t),
	     buffer_pool_index, qr->n_buffers, rxq->size, buffer_size, qr->first_buffer_dma,
	     qr->last_buffer_dma);

  return VNET_DEV_OK;
}

vnet_dev_rv_t
qppe_edma_rx_ring_configure (vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);
  ppe_reg_edma_ring_base_t rxfill_base = {
    .fields.dma_address = qr->fill_dma,
  };
  ppe_reg_edma_ring_base_t rxdesc_base = {
    .fields.dma_address = qr->primary_dma,
  };
  ppe_reg_edma_ring_base_t rxdesc_preheader_base = {
    .fields.dma_address = qr->secondary_dma,
  };
  ppe_reg_edma_rxfill_ring_size_t rxfill_size = {
    .fields.ring_size = rxq->size,
  };
  ppe_reg_edma_rxdesc_ring_size_t rxdesc_size = {
    .fields.ring_size = rxq->size,
  };
  ppe_reg_edma_rxfill_ring_enable_t rxfill_enable = {};
  ppe_reg_edma_rxdesc_control_t rxdesc_control = {};
  u32 offset;
  u32 value;

  if (qd->hw_state.edma_port_control.fields.edma_enable)
    {
      log_err (dev, "cannot configure RX rings while EDMA port control is enabled (0x%08x)",
	       qd->hw_state.edma_port_control.as_u32);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  if (qr->fill_dma > 0xffffffff || qr->primary_dma > 0xffffffff || qr->secondary_dma > 0xffffffff)
    {
      log_err (dev, "RX descriptor DMA addresses exceed EDMA's 32-bit ring base fields");
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_RXFILL_RING_EN (qr->fill_ring_id);
  rxfill_enable.as_u32 = qppe_mmio_read32 (qd, offset);
  log_debug (dev, "read RX fill ring %u enable at offset 0x%x: 0x%08x, %s", qr->fill_ring_id,
	     offset, rxfill_enable.as_u32, rxfill_enable.fields.enable ? "enabled" : "disabled");
  if (rxfill_enable.fields.enable)
    {
      log_err (dev, "cannot configure RX fill ring %u while it is enabled", qr->fill_ring_id);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_RXDESC_CTRL (qr->desc_ring_id);
  rxdesc_control.as_u32 = qppe_mmio_read32 (qd, offset);
  log_debug (dev, "read RX descriptor ring %u control at offset 0x%x: 0x%08x, RX %s",
	     qr->desc_ring_id, offset, rxdesc_control.as_u32,
	     rxdesc_control.fields.rx_enable ? "enabled" : "disabled");
  if (rxdesc_control.fields.rx_enable)
    {
      log_err (dev, "cannot configure RX descriptor ring %u while RX is enabled", qr->desc_ring_id);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_RXFILL_BA (qr->fill_ring_id);
  log_debug (dev, "writing RX fill ring %u base at offset 0x%x: DMA 0x%08x", qr->fill_ring_id,
	     offset, rxfill_base.as_u32);
  qppe_mmio_write32 (qd, offset, rxfill_base.as_u32);
  value = qppe_mmio_read32 (qd, offset);
  log_debug (dev, "read RX fill ring %u base at offset 0x%x: 0x%08x", qr->fill_ring_id, offset,
	     value);
  if (value != rxfill_base.as_u32)
    {
      log_err (dev, "RX fill ring %u base readback mismatch: wrote 0x%08x, read 0x%08x",
	       qr->fill_ring_id, rxfill_base.as_u32, value);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_RXFILL_RING_SIZE (qr->fill_ring_id);
  log_debug (dev, "writing RX fill ring %u size at offset 0x%x: %u entries", qr->fill_ring_id,
	     offset, rxq->size);
  qppe_mmio_write32 (qd, offset, rxfill_size.as_u32);
  value = qppe_mmio_read32 (qd, offset);
  log_debug (dev, "read RX fill ring %u size at offset 0x%x: 0x%08x", qr->fill_ring_id, offset,
	     value);
  if (value != rxfill_size.as_u32)
    {
      log_err (dev, "RX fill ring %u size readback mismatch: wrote 0x%08x, read 0x%08x",
	       qr->fill_ring_id, rxfill_size.as_u32, value);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_RXDESC_BA (qr->desc_ring_id);
  log_debug (dev, "writing RX descriptor ring %u base at offset 0x%x: DMA 0x%08x", qr->desc_ring_id,
	     offset, rxdesc_base.as_u32);
  qppe_mmio_write32 (qd, offset, rxdesc_base.as_u32);
  value = qppe_mmio_read32 (qd, offset);
  log_debug (dev, "read RX descriptor ring %u base at offset 0x%x: 0x%08x", qr->desc_ring_id,
	     offset, value);
  if (value != rxdesc_base.as_u32)
    {
      log_err (dev, "RX descriptor ring %u base readback mismatch: wrote 0x%08x, read 0x%08x",
	       qr->desc_ring_id, rxdesc_base.as_u32, value);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_RXDESC_PREHEADER_BA (qr->desc_ring_id);
  log_debug (dev, "writing RX descriptor ring %u preheader base at offset 0x%x: DMA 0x%08x",
	     qr->desc_ring_id, offset, rxdesc_preheader_base.as_u32);
  qppe_mmio_write32 (qd, offset, rxdesc_preheader_base.as_u32);
  value = qppe_mmio_read32 (qd, offset);
  log_debug (dev, "read RX descriptor ring %u preheader base at offset 0x%x: 0x%08x",
	     qr->desc_ring_id, offset, value);
  if (value != rxdesc_preheader_base.as_u32)
    {
      log_err (dev,
	       "RX descriptor ring %u preheader base readback mismatch: wrote 0x%08x, read 0x%08x",
	       qr->desc_ring_id, rxdesc_preheader_base.as_u32, value);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_RXDESC_RING_SIZE (qr->desc_ring_id);
  log_debug (dev, "writing RX descriptor ring %u size at offset 0x%x: %u entries", qr->desc_ring_id,
	     offset, rxq->size);
  qppe_mmio_write32 (qd, offset, rxdesc_size.as_u32);
  value = qppe_mmio_read32 (qd, offset);
  log_debug (dev, "read RX descriptor ring %u size at offset 0x%x: 0x%08x", qr->desc_ring_id,
	     offset, value);
  if (value != rxdesc_size.as_u32)
    {
      log_err (dev, "RX descriptor ring %u size readback mismatch: wrote 0x%08x, read 0x%08x",
	       qr->desc_ring_id, rxdesc_size.as_u32, value);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_RX_INT_CTRL (qr->desc_ring_id);
  qppe_mmio_write32 (qd, offset, PPE_EDMA_RX_NE_INT_EN);
  value = qppe_mmio_read32 (qd, offset);
  if (value != PPE_EDMA_RX_NE_INT_EN)
    {
      log_err (dev,
	       "RX descriptor ring %u opaque return control readback mismatch: "
	       "wrote 0x%08x, read 0x%08x",
	       qr->desc_ring_id, PPE_EDMA_RX_NE_INT_EN, value);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  log_debug (
    dev,
    "RX fill ring %u and RX descriptor ring %u base/size and opaque return mode configured; "
    "neither ring enabled, no producer index written, EDMA port control unchanged",
    qr->fill_ring_id, qr->desc_ring_id);

  return VNET_DEV_OK;
}

vnet_dev_rv_t
qppe_edma_rx_ring_start (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_rxq_t *qr;
  ppe_reg_edma_port_control_t port_control = qd->hw_state.edma_port_control;
  ppe_reg_edma_rxdesc_control_t rxdesc_control = {};
  ppe_reg_edma_rxfill_ring_enable_t rxfill_enable = {};
  u32 offset, value, i;

  qr = vnet_dev_get_rx_queue_data (rxq);
  if (qr->started)
    return VNET_DEV_OK;

  if (qr->n_buffers != rxq->size || qr->fill_descs == 0 || qr->primary_descs == 0)
    {
      log_err (dev, "cannot start RX queue %u: ring storage is incomplete", rxq->queue_id);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  /* primary_descs/secondary_descs are mapped non-cacheable: a bulk memset ()
   * can lower to a cache-maintenance zero instruction (e.g. ARM64 "dc zva"),
   * which faults on non-cacheable memory, so zero them element-by-element
   * with plain stores instead. */
  for (i = 0; i < rxq->size; i++)
    {
      qr->primary_descs[i] = (ppe_edma_rx_desc_t) {};
      qr->secondary_descs[i] = (ppe_edma_rx_desc_t) {};
    }
  qr->n_buffers = 0;
  for (i = 0; i < rxq->size; i++)
    {
      u32 buffer_index = qr->buffer_indices[i];
      vlib_buffer_t *buffer;
      ppe_edma_rxfill_desc_t *fill_desc;
      uword buffer_dma;

      if (buffer_index == ~0)
	continue;

      fill_desc = &qr->fill_descs[qr->n_buffers];
      buffer = vlib_get_buffer (vm, buffer_index);
      buffer_dma = vnet_dev_get_dma_addr (vm, dev, buffer->data);

      fill_desc->buffer_address = buffer_dma;
      fill_desc->opaque_low = buffer_index;
      qr->buffer_indices[qr->n_buffers] = buffer_index;
      qr->n_buffers++;
    }

  for (i = qr->n_buffers; i < rxq->size; i++)
    qr->buffer_indices[i] = ~0;
  qr->fill_prod = rxq->size;

  if (qppe_edma_rx_queue_mapping_configure (rxq) != VNET_DEV_OK)
    return VNET_DEV_ERR_INIT_FAILED;

  offset = PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_RXDESC2FILL_MAP_0 +
	   ((qr->desc_ring_id / 10) * sizeof (u32));
  value = qppe_mmio_read32 (qd, offset);
  value = (value & ~(0x7 << ((qr->desc_ring_id % 10) * 3))) |
	  (qr->fill_ring_id << ((qr->desc_ring_id % 10) * 3));
  qppe_mmio_write32 (qd, offset, value);
  if (qppe_mmio_read32 (qd, offset) != value)
    {
      log_err (dev, "RX descriptor-to-fill ring map readback failed at offset 0x%x", offset);
      return VNET_DEV_ERR_INIT_FAILED;
    }
  log_debug (dev, "mapped RX descriptor ring %u to fill ring %u at offset 0x%x: 0x%08x",
	     qr->desc_ring_id, qr->fill_ring_id, offset, value);

  qr->desc_cons = 0;
  offset = qr->rxdesc_cons_offset;
  qppe_mmio_write32 (qd, offset, qr->desc_cons);
  log_debug (dev, "initialized RX descriptor ring %u consumer index at offset 0x%x to %u",
	     qr->desc_ring_id, offset, qr->desc_cons);

  offset = qr->rxfill_prod_offset;
  __atomic_thread_fence (__ATOMIC_RELEASE);
  qppe_mmio_write32 (qd, offset, qr->fill_prod);
  value = qppe_mmio_read32 (qd, offset) & PPE_EDMA_RX_PROD_CONS_MASK;
  if (value != qr->fill_prod)
    {
      log_err (dev, "RX fill ring %u producer readback mismatch: wrote %u, read %u",
	       qr->fill_ring_id, qr->fill_prod, value);
      return VNET_DEV_ERR_INIT_FAILED;
    }
  log_debug (dev, "published %u RX fill descriptors on ring %u at offset 0x%x; producer %u",
	     qr->n_buffers, qr->fill_ring_id, offset, qr->fill_prod);
  qr->fill_prod = 0;

  offset = PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_RXDESC_CTRL (qr->desc_ring_id);
  rxdesc_control.as_u32 = qppe_mmio_read32 (qd, offset);
  rxdesc_control.fields.rx_enable = 1;
  qppe_mmio_write32 (qd, offset, rxdesc_control.as_u32);
  if (!((ppe_reg_edma_rxdesc_control_t) { .as_u32 = qppe_mmio_read32 (qd, offset) })
	 .fields.rx_enable)
    {
      log_err (dev, "RX descriptor ring %u did not enable at offset 0x%x", qr->desc_ring_id,
	       offset);
      return VNET_DEV_ERR_INIT_FAILED;
    }
  log_debug (dev, "enabled RX descriptor ring %u at offset 0x%x: 0x%08x", qr->desc_ring_id, offset,
	     rxdesc_control.as_u32);

  offset = PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_RXFILL_RING_EN (qr->fill_ring_id);
  rxfill_enable.as_u32 = qppe_mmio_read32 (qd, offset);
  rxfill_enable.fields.enable = 1;
  qppe_mmio_write32 (qd, offset, rxfill_enable.as_u32);
  if (!((ppe_reg_edma_rxfill_ring_enable_t) { .as_u32 = qppe_mmio_read32 (qd, offset) })
	 .fields.enable)
    {
      log_err (dev, "RX fill ring %u did not enable at offset 0x%x", qr->fill_ring_id, offset);
      rxdesc_control.fields.rx_enable = 0;
      qppe_mmio_write32 (qd, PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_RXDESC_CTRL (qr->desc_ring_id),
			 rxdesc_control.as_u32);
      return VNET_DEV_ERR_INIT_FAILED;
    }
  log_debug (dev, "enabled RX fill ring %u at offset 0x%x: 0x%08x", qr->fill_ring_id, offset,
	     rxfill_enable.as_u32);

  if (!port_control.fields.edma_enable)
    {
      port_control.fields.edma_enable = 1;
      offset = PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_PORT_CTRL_ADDR;
      qppe_mmio_write32 (qd, offset, port_control.as_u32);
      qd->hw_state.edma_port_control = port_control;
      if (!((ppe_reg_edma_port_control_t) { .as_u32 = qppe_mmio_read32 (qd, offset) })
	     .fields.edma_enable)
	{
	  log_err (dev, "EDMA did not enable at offset 0x%x", offset);
	  qppe_edma_rx_ring_stop (rxq);
	  return VNET_DEV_ERR_INIT_FAILED;
	}
      log_debug (dev, "enabled EDMA at offset 0x%x: 0x%08x", offset, port_control.as_u32);
    }
  qr->started = 1;
  qd->n_active_rx_queues++;

  return VNET_DEV_OK;
}

void
qppe_edma_rx_ring_stop (vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);
  ppe_reg_edma_port_control_t port_control = qd->hw_state.edma_port_control;
  ppe_reg_edma_rxdesc_control_t rxdesc_control = {};
  ppe_reg_edma_rxfill_ring_enable_t rxfill_enable = {};
  u32 offset;

  offset = PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_RXFILL_RING_EN (qr->fill_ring_id);
  rxfill_enable.as_u32 = qppe_mmio_read32 (qd, offset);
  rxfill_enable.fields.enable = 0;
  qppe_mmio_write32 (qd, offset, rxfill_enable.as_u32);
  rxfill_enable.as_u32 = qppe_mmio_read32 (qd, offset);
  log_debug (dev, "disabled RX fill ring %u at offset 0x%x: 0x%08x", qr->fill_ring_id, offset,
	     rxfill_enable.as_u32);

  offset = PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_RXDESC_CTRL (qr->desc_ring_id);
  rxdesc_control.as_u32 = qppe_mmio_read32 (qd, offset);
  rxdesc_control.fields.rx_enable = 0;
  qppe_mmio_write32 (qd, offset, rxdesc_control.as_u32);
  rxdesc_control.as_u32 = qppe_mmio_read32 (qd, offset);
  log_debug (dev, "disabled RX descriptor ring %u at offset 0x%x: 0x%08x", qr->desc_ring_id, offset,
	     rxdesc_control.as_u32);
  if (qr->started)
    {
      qr->started = 0;
      ASSERT (qd->n_active_rx_queues > 0);
      qd->n_active_rx_queues--;
    }

  if (qd->n_active_rx_queues == 0 && qd->hw_state.edma_port_control.fields.edma_enable)
    {
      offset = PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_PORT_CTRL_ADDR;
      port_control.fields.edma_enable = 0;
      qppe_mmio_write32 (qd, offset, port_control.as_u32);
      qd->hw_state.edma_port_control = port_control;
      log_debug (dev, "disabled EDMA at offset 0x%x: 0x%08x", offset, port_control.as_u32);
    }
}
