/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/platform.h>
#include <vlib/buffer_funcs.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/format_table.h>
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

vnet_dev_rv_t
qppe_edma_init (vnet_dev_t *dev)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  ppe_reg_edma_port_control_t port_control = {};
  u32 version, offset;

  offset = EDMA_BASE_OFFSET + EDMA_REG_MAS_CTRL_ADDR;
  version = qppe_mmio_read32 (qd, offset);
  log_debug (dev, "read EDMA version at offset 0x%x: %u (0x%08x)", offset, version, version);
  if (version == 0xffffffff)
    {
      log_err (dev, "MMIO read check failed: EDMA version returned all ones");
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = EDMA_BASE_OFFSET + EDMA_REG_PORT_CTRL_ADDR;
  port_control.as_u32 = qppe_mmio_read32 (qd, offset);
  log_debug (dev, "read EDMA port control at offset 0x%x: 0x%08x, EDMA %s, TX padding %s", offset,
	     port_control.as_u32, port_control.edma_enable ? "enabled" : "disabled",
	     port_control.tx_padding_enable ? "enabled" : "disabled");
  if (port_control.as_u32 == 0xffffffff)
    {
      log_err (dev, "MMIO read check failed: EDMA port control returned all ones");
      return VNET_DEV_ERR_INIT_FAILED;
    }
  qd->edma_enabled = port_control.edma_enable;

  return VNET_DEV_OK;
}

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
  if (qr->descs)
    vnet_dev_dma_mem_free (vm, dev, qr->descs);
  if (qr->preheader_descs)
    vnet_dev_dma_mem_free (vm, dev, qr->preheader_descs);
  qr->fill_descs = 0;
  qr->descs = 0;
  qr->preheader_descs = 0;
}

static vnet_dev_rv_t
qppe_edma_rx_queue_mapping_configure (vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_port_t *qp = vnet_dev_get_port_data (rxq->port);
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);
  u32 profile = qp->source_profile;
  u32 ring_profile = qr->desc_ring_id - EDMA_RXDESC_RING_START;
  u32 offset, value, i;

  if (profile >= EDMA_RX_RING_COUNT || profile != ring_profile ||
      rxq->port->port_id >= PPE_MAX_PORTS)
    {
      log_err (dev, "cannot map RX queue %u on port %u source profile %u to EDMA ring %u",
	       rxq->queue_id, rxq->port->port_id, profile, qr->desc_ring_id);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  if (qd->n_active_rx_queues == 0)
    {
      for (i = 0; i < EDMA_RX_RING_COUNT; i++)
	{
	  u32 queue_map[EDMA_RING_Q_MAP_WORDS] = {};
	  u32 queue_first = i * EDMA_RX_QUEUES_PER_RING;
	  u32 j;

	  for (j = 0; j < EDMA_RX_QUEUES_PER_RING; j++)
	    queue_map[(queue_first + j) / 32] |= 1u << ((queue_first + j) % 32);

	  for (j = 0; j < EDMA_RING_Q_MAP_WORDS; j++)
	    {
	      offset = PPE_REG_RING_Q_MAP_TBL (EDMA_RXDESC_RING_START + i) + j * sizeof (u32);
	      qppe_mmio_write32 (qd, offset, queue_map[j]);
	    }
	}

      for (i = 0; i < EDMA_QID2RID_WORD_COUNT; i++)
	{
	  u32 queue_id = i * 4;
	  u32 ring_id = EDMA_RXDESC_RING_START + (queue_id / EDMA_RX_QUEUES_PER_RING);

	  value = EDMA_QID2RID_WORD (ring_id, ring_id, ring_id, ring_id);
	  offset = EDMA_BASE_OFFSET + EDMA_REG_QID2RID_TABLE (queue_id);
	  qppe_mmio_write32 (qd, offset, value);
	  if (qppe_mmio_read32 (qd, offset) != value)
	    {
	      log_err (dev, "EDMA queue-to-ring map readback failed at offset 0x%x", offset);
	      return VNET_DEV_ERR_INIT_FAILED;
	    }
	}

      for (i = 0; i < EDMA_RX_RING_COUNT; i++)
	{
	  u32 queue_id = PPE_CPU_MCAST_QUEUE_START + (i * PPE_CPU_MCAST_QUEUES_PER_PROFILE);
	  u32 ring_id = EDMA_RXDESC_RING_START + i;

	  value = EDMA_QID2RID_WORD (ring_id, ring_id, ring_id, ring_id);
	  offset = EDMA_BASE_OFFSET + EDMA_REG_QID2RID_TABLE (queue_id);
	  qppe_mmio_write32 (qd, offset, value);
	  if (qppe_mmio_read32 (qd, offset) != value)
	    {
	      log_err (dev, "EDMA multicast queue-to-ring map readback failed at offset 0x%x",
		       offset);
	      return VNET_DEV_ERR_INIT_FAILED;
	    }
	}

      /* The CPU port's own bridge entry gates whether the switch core will
       * deliver anything to the CPU at all; it defaults to disabled out of
       * reset and is otherwise never touched, so without this every frame
       * classified toward the CPU port would be silently dropped before it
       * ever reaches an EDMA ring, for every physical port alike. Its
       * isolation bitmap must also include all physical ports. */
      {
	ppe_reg_port_bridge_ctrl_t bridge_ctrl = {
	  .port_isolation_bitmap = ((1u << PPE_MAX_PORTS) - 1) & ~(1u << EDMA_CPU_PORT_ID),
	  .txmac_en = 1,
	};

	offset = PPE_REG_PORT_BRIDGE_CTRL (EDMA_CPU_PORT_ID);
	qppe_mmio_write32 (qd, offset, bridge_ctrl.as_u32);
	if (qppe_mmio_read32 (qd, offset) != bridge_ctrl.as_u32)
	  {
	    log_err (dev, "PPE CPU port bridge control readback failed at offset 0x%x", offset);
	    return VNET_DEV_ERR_INIT_FAILED;
	  }
      }
    }

  for (i = 0; i < 16; i++)
    {
      value = clib_min (i, EDMA_RX_QUEUES_PER_RING - 1);
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

  if (qppe_vsi_port_configure (rxq) != VNET_DEV_OK)
    return VNET_DEV_ERR_INIT_FAILED;

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
  uword fill_dma, rx_dma, secondary_dma, first_buffer_dma, last_buffer_dma;
  u8 buffer_pool_index = vlib_buffer_pool_get_default_for_numa (vm, dev->numa_node);

  desc_size = rxq->size * sizeof (edma_rxfill_desc_t);
  rv = vnet_dev_dma_mem_alloc_coherent (vm, dev, desc_size, CLIB_CACHE_LINE_BYTES,
					(void **) &qr->fill_descs, "EDMA RX fill descriptors");
  if (rv != VNET_DEV_OK)
    return rv;
  fill_dma = vnet_dev_get_dma_addr (vm, dev, qr->fill_descs);

  /* Hardware writes these descriptors; software only ever reads them.
   * Allocate from the coherent arena so a CPU cache line can never serve
   * stale content from before the EDMA engine's write. */
  desc_size = rxq->size * sizeof (edma_rx_desc_t);
  rv = vnet_dev_dma_mem_alloc_coherent (vm, dev, desc_size, CLIB_CACHE_LINE_BYTES,
					(void **) &qr->descs, "EDMA RX descriptors");
  if (rv != VNET_DEV_OK)
    {
      qppe_edma_rx_ring_free (vm, rxq);
      return rv;
    }
  rx_dma = vnet_dev_get_dma_addr (vm, dev, qr->descs);

  rv = vnet_dev_dma_mem_alloc_coherent (vm, dev, desc_size, CLIB_CACHE_LINE_BYTES,
					(void **) &qr->preheader_descs,
					"EDMA RX secondary descriptors");
  if (rv != VNET_DEV_OK)
    {
      qppe_edma_rx_ring_free (vm, rxq);
      return rv;
    }
  secondary_dma = vnet_dev_get_dma_addr (vm, dev, qr->preheader_descs);

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
      edma_rxfill_desc_t *desc = &qr->fill_descs[i];

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
      edma_rxfill_desc_t *desc = &qr->fill_descs[i];
      uword buffer_dma = vnet_dev_get_dma_addr (vm, dev, buffer->data);

      if (i == 0)
	first_buffer_dma = buffer_dma;
      last_buffer_dma = buffer_dma;

      desc->buffer_address = buffer_dma;
      desc->opaque_low = buffer_index;
    }

  log_debug (dev,
	     "allocated RX ring storage: %u descriptors, fill VA %p DMA 0x%lx (%u bytes), "
	     "RX descriptor VA %p DMA 0x%lx (%u bytes), preheader VA %p DMA 0x%lx (%u bytes); "
	     "VPP pool %u supplied %u of %u initial packet buffers at %u bytes each, "
	     "first/last DMA 0x%lx/0x%lx; "
	     "fill descriptors initialized; hardware remains disabled and unconfigured",
	     rxq->size, qr->fill_descs, fill_dma, rxq->size * sizeof (edma_rxfill_desc_t),
	     qr->descs, rx_dma, rxq->size * sizeof (edma_rx_desc_t), qr->preheader_descs,
	     secondary_dma, rxq->size * sizeof (edma_rx_desc_t), buffer_pool_index, qr->n_buffers,
	     rxq->size, buffer_size, first_buffer_dma, last_buffer_dma);

  return VNET_DEV_OK;
}

vnet_dev_rv_t
qppe_edma_rx_ring_configure (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);
  uword fill_dma = vnet_dev_get_dma_addr (vm, dev, qr->fill_descs);
  uword rx_dma = vnet_dev_get_dma_addr (vm, dev, qr->descs);
  uword secondary_dma = vnet_dev_get_dma_addr (vm, dev, qr->preheader_descs);
  u32 rxfill_base, rxdesc_base, rxdesc_preheader_base;
  u16 rxfill_size;
  ppe_reg_edma_rxdesc_ring_size_t rxdesc_size = {
    .ring_size = rxq->size,
  };
  ppe_reg_edma_rxfill_ring_enable_t rxfill_enable = {};
  ppe_reg_edma_rxdesc_control_t rxdesc_control = {};
  u32 offset;
  u32 value;

  if (qd->edma_enabled)
    {
      log_err (dev, "cannot configure RX rings while EDMA is enabled");
      return VNET_DEV_ERR_INIT_FAILED;
    }

  if (fill_dma > 0xffffffff || rx_dma > 0xffffffff || secondary_dma > 0xffffffff)
    {
      log_err (dev, "RX descriptor DMA addresses exceed EDMA's 32-bit ring base fields");
      return VNET_DEV_ERR_INIT_FAILED;
    }

  rxfill_base = fill_dma;
  rxdesc_base = rx_dma;
  rxdesc_preheader_base = secondary_dma;
  rxfill_size = rxq->size;

  offset = EDMA_BASE_OFFSET + EDMA_REG_RXFILL_RING_EN (qr->fill_ring_id);
  rxfill_enable.as_u32 = qppe_mmio_read32 (qd, offset);
  log_debug (dev, "read RX fill ring %u enable at offset 0x%x: 0x%08x, %s", qr->fill_ring_id,
	     offset, rxfill_enable.as_u32, rxfill_enable.enable ? "enabled" : "disabled");
  if (rxfill_enable.enable)
    {
      log_err (dev, "cannot configure RX fill ring %u while it is enabled", qr->fill_ring_id);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = EDMA_BASE_OFFSET + EDMA_REG_RXDESC_CTRL (qr->desc_ring_id);
  rxdesc_control.as_u32 = qppe_mmio_read32 (qd, offset);
  log_debug (dev, "read RX descriptor ring %u control at offset 0x%x: 0x%08x, RX %s",
	     qr->desc_ring_id, offset, rxdesc_control.as_u32,
	     rxdesc_control.rx_enable ? "enabled" : "disabled");
  if (rxdesc_control.rx_enable)
    {
      log_err (dev, "cannot configure RX descriptor ring %u while RX is enabled", qr->desc_ring_id);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = EDMA_BASE_OFFSET + EDMA_REG_RXFILL_BA (qr->fill_ring_id);
  log_debug (dev, "writing RX fill ring %u base at offset 0x%x: DMA 0x%08x", qr->fill_ring_id,
	     offset, rxfill_base);
  qppe_mmio_write32 (qd, offset, rxfill_base);
  value = qppe_mmio_read32 (qd, offset);
  log_debug (dev, "read RX fill ring %u base at offset 0x%x: 0x%08x", qr->fill_ring_id, offset,
	     value);
  if (value != rxfill_base)
    {
      log_err (dev, "RX fill ring %u base readback mismatch: wrote 0x%08x, read 0x%08x",
	       qr->fill_ring_id, rxfill_base, value);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = EDMA_BASE_OFFSET + EDMA_REG_RXFILL_RING_SIZE (qr->fill_ring_id);
  log_debug (dev, "writing RX fill ring %u size at offset 0x%x: %u entries", qr->fill_ring_id,
	     offset, rxq->size);
  qppe_mmio_write32 (qd, offset, rxfill_size);
  value = qppe_mmio_read32 (qd, offset);
  log_debug (dev, "read RX fill ring %u size at offset 0x%x: 0x%08x", qr->fill_ring_id, offset,
	     value);
  if (value != rxfill_size)
    {
      log_err (dev, "RX fill ring %u size readback mismatch: wrote 0x%08x, read 0x%08x",
	       qr->fill_ring_id, rxfill_size, value);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = EDMA_BASE_OFFSET + EDMA_REG_RXDESC_BA (qr->desc_ring_id);
  log_debug (dev, "writing RX descriptor ring %u base at offset 0x%x: DMA 0x%08x", qr->desc_ring_id,
	     offset, rxdesc_base);
  qppe_mmio_write32 (qd, offset, rxdesc_base);
  value = qppe_mmio_read32 (qd, offset);
  log_debug (dev, "read RX descriptor ring %u base at offset 0x%x: 0x%08x", qr->desc_ring_id,
	     offset, value);
  if (value != rxdesc_base)
    {
      log_err (dev, "RX descriptor ring %u base readback mismatch: wrote 0x%08x, read 0x%08x",
	       qr->desc_ring_id, rxdesc_base, value);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = EDMA_BASE_OFFSET + EDMA_REG_RXDESC_PREHEADER_BA (qr->desc_ring_id);
  log_debug (dev, "writing RX descriptor ring %u preheader base at offset 0x%x: DMA 0x%08x",
	     qr->desc_ring_id, offset, rxdesc_preheader_base);
  qppe_mmio_write32 (qd, offset, rxdesc_preheader_base);
  value = qppe_mmio_read32 (qd, offset);
  log_debug (dev, "read RX descriptor ring %u preheader base at offset 0x%x: 0x%08x",
	     qr->desc_ring_id, offset, value);
  if (value != rxdesc_preheader_base)
    {
      log_err (dev,
	       "RX descriptor ring %u preheader base readback mismatch: wrote 0x%08x, read 0x%08x",
	       qr->desc_ring_id, rxdesc_preheader_base, value);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = EDMA_BASE_OFFSET + EDMA_REG_RXDESC_RING_SIZE (qr->desc_ring_id);
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

  offset = EDMA_BASE_OFFSET + EDMA_REG_RX_MOD_TIMER (qr->desc_ring_id);
  log_debug (dev, "writing RX descriptor ring %u mitigation timer at offset 0x%x: %u",
	     qr->desc_ring_id, offset, EDMA_RX_MOD_TIMER_VALUE);
  qppe_mmio_write32 (qd, offset, EDMA_RX_MOD_TIMER_VALUE);
  value = qppe_mmio_read32 (qd, offset);
  if (value != EDMA_RX_MOD_TIMER_VALUE)
    {
      log_err (dev, "RX descriptor ring %u mitigation timer readback mismatch: wrote %u, read %u",
	       qr->desc_ring_id, EDMA_RX_MOD_TIMER_VALUE, value);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = EDMA_BASE_OFFSET + EDMA_REG_RXDESC_UGT_THRE (qr->desc_ring_id);
  log_debug (dev, "writing RX descriptor ring %u mitigation packet count at offset 0x%x: %u",
	     qr->desc_ring_id, offset, EDMA_RX_MITIGATION_PKT_CNT);
  qppe_mmio_write32 (qd, offset, EDMA_RX_MITIGATION_PKT_CNT);
  value = qppe_mmio_read32 (qd, offset);
  if (value != EDMA_RX_MITIGATION_PKT_CNT)
    {
      log_err (dev,
	       "RX descriptor ring %u mitigation packet count readback mismatch: wrote %u, read %u",
	       qr->desc_ring_id, EDMA_RX_MITIGATION_PKT_CNT, value);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = EDMA_BASE_OFFSET + EDMA_REG_RX_INT_CTRL (qr->desc_ring_id);
  qppe_mmio_write32 (qd, offset, EDMA_RX_NE_INT_EN);
  value = qppe_mmio_read32 (qd, offset);
  if (value != EDMA_RX_NE_INT_EN)
    {
      log_err (dev,
	       "RX descriptor ring %u opaque return control readback mismatch: "
	       "wrote 0x%08x, read 0x%08x",
	       qr->desc_ring_id, EDMA_RX_NE_INT_EN, value);
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
  ppe_reg_edma_port_control_t port_control = {};
  ppe_reg_edma_rxdesc_control_t rxdesc_control = {};
  ppe_reg_edma_rxfill_ring_enable_t rxfill_enable = {};
  qppe_bm_port_config_t bm_port_config = {
    .ceil = PPE_BM_PHYS_PORT_CEIL,
    .weight = PPE_BM_PHYS_PORT_WEIGHT,
    .resume_offset = PPE_BM_PHYS_PORT_RESUME_OFFSET,
    .dynamic = 1,
    .react_limit = PPE_BM_PHYS_PORT_REACT_LIMIT,
    .enable = 1,
  };
  vnet_dev_rv_t rv;
  u8 buffer_pool_index = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  u32 buffer_size = vlib_get_buffer_pool (vm, buffer_pool_index)->data_size;
  u32 offset, value, i;

  qr = vnet_dev_get_rx_queue_data (rxq);
  if (qr->started)
    return VNET_DEV_OK;
  port_control.as_u32 = qppe_mmio_read32 (qd, EDMA_BASE_OFFSET + EDMA_REG_PORT_CTRL_ADDR);

  if (qr->n_buffers != rxq->size || qr->fill_descs == 0 || qr->descs == 0)
    {
      log_err (dev, "cannot start RX queue %u: ring storage is incomplete", rxq->queue_id);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  /* rx_descs/preheader_descs are mapped non-cacheable: a bulk memset ()
   * can lower to a cache-maintenance zero instruction (e.g. ARM64 "dc zva"),
   * which faults on non-cacheable memory, so zero them element-by-element
   * with plain stores instead. */
  for (i = 0; i < rxq->size; i++)
    {
      qr->descs[i] = (edma_rx_desc_t) {};
      qr->preheader_descs[i] = (edma_rx_sec_desc_t) {};
    }
  qr->n_buffers = 0;
  for (i = 0; i < rxq->size; i++)
    {
      u32 buffer_index = qr->buffer_indices[i];
      vlib_buffer_t *buffer;
      edma_rxfill_desc_t *fill_desc;
      uword buffer_dma;

      if (buffer_index == ~0)
	continue;

      fill_desc = &qr->fill_descs[qr->n_buffers];
      buffer = vlib_get_buffer (vm, buffer_index);
      buffer_dma = vnet_dev_get_dma_addr (vm, dev, buffer->data);
      qppe_dma_cache_clean_invalidate (buffer->data, buffer_size);

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

  /* Give this port its share of the shared BM buffer pool now that it's
   * actually starting, so a port that never comes up doesn't hold back
   * buffers other running ports could use. */
  rv = qppe_bm_port_configure (dev, PPE_BM_PORT_ID_PHYS_BASE + rxq->port->port_id, &bm_port_config);
  if (rv != VNET_DEV_OK)
    return rv;

  offset = EDMA_BASE_OFFSET + EDMA_REG_RXDESC2FILL_MAP_0 + ((qr->desc_ring_id / 10) * sizeof (u32));
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
#if defined(__aarch64__)
  asm volatile ("dsb osh" : : : "memory");
#endif
  qppe_mmio_write32 (qd, offset, qr->fill_prod);
  value = qppe_mmio_read32 (qd, offset) & EDMA_RX_PROD_CONS_MASK;
  if (value != qr->fill_prod)
    {
      log_err (dev, "RX fill ring %u producer readback mismatch: wrote %u, read %u",
	       qr->fill_ring_id, qr->fill_prod, value);
      return VNET_DEV_ERR_INIT_FAILED;
    }
  log_debug (dev, "published %u RX fill descriptors on ring %u at offset 0x%x; producer %u",
	     qr->n_buffers, qr->fill_ring_id, offset, qr->fill_prod);
  qr->fill_prod = 0;

  offset = EDMA_BASE_OFFSET + EDMA_REG_RXDESC_CTRL (qr->desc_ring_id);
  rxdesc_control.as_u32 = qppe_mmio_read32 (qd, offset);
  rxdesc_control.rx_enable = 1;
  qppe_mmio_write32 (qd, offset, rxdesc_control.as_u32);
  if (!((ppe_reg_edma_rxdesc_control_t) { .as_u32 = qppe_mmio_read32 (qd, offset) }).rx_enable)
    {
      log_err (dev, "RX descriptor ring %u did not enable at offset 0x%x", qr->desc_ring_id,
	       offset);
      return VNET_DEV_ERR_INIT_FAILED;
    }
  log_debug (dev, "enabled RX descriptor ring %u at offset 0x%x: 0x%08x", qr->desc_ring_id, offset,
	     rxdesc_control.as_u32);

  offset = EDMA_BASE_OFFSET + EDMA_REG_RXFILL_RING_EN (qr->fill_ring_id);
  rxfill_enable.as_u32 = qppe_mmio_read32 (qd, offset);
  rxfill_enable.enable = 1;
  qppe_mmio_write32 (qd, offset, rxfill_enable.as_u32);
  if (!((ppe_reg_edma_rxfill_ring_enable_t) { .as_u32 = qppe_mmio_read32 (qd, offset) }).enable)
    {
      log_err (dev, "RX fill ring %u did not enable at offset 0x%x", qr->fill_ring_id, offset);
      rxdesc_control.rx_enable = 0;
      qppe_mmio_write32 (qd, EDMA_BASE_OFFSET + EDMA_REG_RXDESC_CTRL (qr->desc_ring_id),
			 rxdesc_control.as_u32);
      return VNET_DEV_ERR_INIT_FAILED;
    }
  log_debug (dev, "enabled RX fill ring %u at offset 0x%x: 0x%08x", qr->fill_ring_id, offset,
	     rxfill_enable.as_u32);

  if (!port_control.edma_enable)
    {
      port_control.edma_enable = 1;
      offset = EDMA_BASE_OFFSET + EDMA_REG_PORT_CTRL_ADDR;
      qppe_mmio_write32 (qd, offset, port_control.as_u32);
      if (!((ppe_reg_edma_port_control_t) { .as_u32 = qppe_mmio_read32 (qd, offset) }).edma_enable)
	{
	  log_err (dev, "EDMA did not enable at offset 0x%x", offset);
	  qppe_edma_rx_ring_stop (rxq);
	  return VNET_DEV_ERR_INIT_FAILED;
	}
      qd->edma_enabled = 1;
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
  ppe_reg_edma_port_control_t port_control = {};
  ppe_reg_edma_rxdesc_control_t rxdesc_control = {};
  ppe_reg_edma_rxfill_ring_enable_t rxfill_enable = {};
  qppe_bm_port_config_t bm_port_config = {};
  u32 offset;

  offset = EDMA_BASE_OFFSET + EDMA_REG_RXFILL_RING_EN (qr->fill_ring_id);
  rxfill_enable.as_u32 = qppe_mmio_read32 (qd, offset);
  rxfill_enable.enable = 0;
  qppe_mmio_write32 (qd, offset, rxfill_enable.as_u32);
  rxfill_enable.as_u32 = qppe_mmio_read32 (qd, offset);
  log_debug (dev, "disabled RX fill ring %u at offset 0x%x: 0x%08x", qr->fill_ring_id, offset,
	     rxfill_enable.as_u32);

  offset = EDMA_BASE_OFFSET + EDMA_REG_RXDESC_CTRL (qr->desc_ring_id);
  rxdesc_control.as_u32 = qppe_mmio_read32 (qd, offset);
  rxdesc_control.rx_enable = 0;
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

  if (qd->n_active_rx_queues == 0 && qd->n_active_tx_queues == 0 && qd->edma_enabled)
    {
      offset = EDMA_BASE_OFFSET + EDMA_REG_PORT_CTRL_ADDR;
      port_control.as_u32 = qppe_mmio_read32 (qd, offset);
      port_control.edma_enable = 0;
      qppe_mmio_write32 (qd, offset, port_control.as_u32);
      qd->edma_enabled = 0;
      log_debug (dev, "disabled EDMA at offset 0x%x: 0x%08x", offset, port_control.as_u32);
    }

  /* Free this port's share of the shared BM buffer pool back for the
   * ports still running. */
  qppe_bm_port_configure (dev, PPE_BM_PORT_ID_PHYS_BASE + rxq->port->port_id, &bm_port_config);
}

void
qppe_edma_tx_ring_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  qppe_txq_t *tq = vnet_dev_get_tx_queue_data (txq);

  if (tq->descs)
    vnet_dev_dma_mem_free (vm, dev, tq->descs);
  if (tq->sec_descs)
    vnet_dev_dma_mem_free (vm, dev, tq->sec_descs);
  if (tq->cmpl_descs)
    vnet_dev_dma_mem_free (vm, dev, tq->cmpl_descs);
  tq->descs = 0;
  tq->sec_descs = 0;
  tq->cmpl_descs = 0;
}

vnet_dev_rv_t
qppe_edma_tx_ring_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  qppe_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  vnet_dev_rv_t rv;
  u32 desc_size;

  desc_size = txq->size * sizeof (edma_tx_desc_t);
  rv = vnet_dev_dma_mem_alloc_coherent (vm, dev, desc_size, CLIB_CACHE_LINE_BYTES,
					(void **) &tq->descs, "EDMA TX descriptors");
  if (rv != VNET_DEV_OK)
    return rv;

  desc_size = txq->size * sizeof (edma_tx_sec_desc_t);
  rv = vnet_dev_dma_mem_alloc_coherent (vm, dev, desc_size, CLIB_CACHE_LINE_BYTES,
					(void **) &tq->sec_descs, "EDMA TX secondary descriptors");
  if (rv != VNET_DEV_OK)
    {
      qppe_edma_tx_ring_free (vm, txq);
      return rv;
    }

  /* hardware writes these; software only ever reads them, so allocate from
   * the coherent arena the same way RX descriptors are (see the comment in
   * qppe_edma_rx_ring_alloc). */
  desc_size = txq->size * sizeof (edma_txcmpl_desc_t);
  rv =
    vnet_dev_dma_mem_alloc_coherent (vm, dev, desc_size, CLIB_CACHE_LINE_BYTES,
				     (void **) &tq->cmpl_descs, "EDMA TX completion descriptors");
  if (rv != VNET_DEV_OK)
    {
      qppe_edma_tx_ring_free (vm, txq);
      return rv;
    }

  log_debug (dev,
	     "allocated TX ring storage: %u descriptors, TX VA %p, secondary VA %p, "
	     "completion VA %p; hardware remains disabled and unconfigured",
	     txq->size, tq->descs, tq->sec_descs, tq->cmpl_descs);

  return VNET_DEV_OK;
}

vnet_dev_rv_t
qppe_edma_tx_ring_configure (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  uword desc_dma = vnet_dev_get_dma_addr (vm, dev, tq->descs);
  uword sec_dma = vnet_dev_get_dma_addr (vm, dev, tq->sec_descs);
  uword cmpl_dma = vnet_dev_get_dma_addr (vm, dev, tq->cmpl_descs);
  u32 desc_base, sec_base, cmpl_base;
  u32 offset, value;

  /* every field here is the same for every packet this queue ever sends;
   * qppe_tx_fill_desc only ever has to overwrite buffer_address, data_length,
   * more and opaque_low on top of this. */
  tq->desc_template = (edma_tx_desc_t) {
    .service_code = EDMA_SC_BYPASS_ID,
    .int_pri_valid = 1,
    .destination_type = EDMA_TX_DST_PORT_TYPE,
    .destination_port_id = txq->port->port_id,
  };

  if (qd->edma_enabled)
    {
      log_err (dev, "cannot configure TX rings while EDMA is enabled");
      return VNET_DEV_ERR_INIT_FAILED;
    }

  if (desc_dma > 0xffffffff || sec_dma > 0xffffffff || cmpl_dma > 0xffffffff)
    {
      log_err (dev, "TX descriptor DMA addresses exceed EDMA's 32-bit ring base fields");
      return VNET_DEV_ERR_INIT_FAILED;
    }

  desc_base = desc_dma;
  sec_base = sec_dma;
  cmpl_base = cmpl_dma;

  offset = EDMA_BASE_OFFSET + EDMA_REG_TXDESC_BA (tq->desc_ring_id);
  qppe_mmio_write32 (qd, offset, desc_base);
  if (qppe_mmio_read32 (qd, offset) != desc_base)
    {
      log_err (dev, "TX descriptor ring %u base readback failed at offset 0x%x", tq->desc_ring_id,
	       offset);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = EDMA_BASE_OFFSET + EDMA_REG_TXDESC_BA2 (tq->desc_ring_id);
  qppe_mmio_write32 (qd, offset, sec_base);
  if (qppe_mmio_read32 (qd, offset) != sec_base)
    {
      log_err (dev, "TX descriptor ring %u secondary base readback failed at offset 0x%x",
	       tq->desc_ring_id, offset);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = EDMA_BASE_OFFSET + EDMA_REG_TXDESC_RING_SIZE (tq->desc_ring_id);
  value = txq->size & EDMA_TX_PROD_CONS_MASK;
  qppe_mmio_write32 (qd, offset, value);
  if (qppe_mmio_read32 (qd, offset) != value)
    {
      log_err (dev, "TX descriptor ring %u size readback failed at offset 0x%x", tq->desc_ring_id,
	       offset);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = EDMA_BASE_OFFSET + EDMA_REG_TXCMPL_BA (tq->cmpl_ring_id);
  qppe_mmio_write32 (qd, offset, cmpl_base);
  if (qppe_mmio_read32 (qd, offset) != cmpl_base)
    {
      log_err (dev, "TX completion ring %u base readback failed at offset 0x%x", tq->cmpl_ring_id,
	       offset);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = EDMA_BASE_OFFSET + EDMA_REG_TXCMPL_RING_SIZE (tq->cmpl_ring_id);
  qppe_mmio_write32 (qd, offset, value);
  if (qppe_mmio_read32 (qd, offset) != value)
    {
      log_err (dev, "TX completion ring %u size readback failed at offset 0x%x", tq->cmpl_ring_id,
	       offset);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = EDMA_BASE_OFFSET + EDMA_REG_TXCMPL_CTRL (tq->cmpl_ring_id);
  qppe_mmio_write32 (qd, offset, EDMA_TXCMPL_RETMODE_OPAQUE);

  offset = EDMA_BASE_OFFSET + EDMA_REG_TX_INT_CTRL (tq->cmpl_ring_id);
  qppe_mmio_write32 (qd, offset, EDMA_TX_NE_INT_EN);

  log_debug (dev,
	     "TX descriptor ring %u and TX completion ring %u base/size and opaque return mode "
	     "configured; neither ring enabled, no producer index written, EDMA port control "
	     "unchanged",
	     tq->desc_ring_id, tq->cmpl_ring_id);

  return VNET_DEV_OK;
}

/* Configure EDMA_SC_BYPASS_ID once so CPU-originated (EDMA TX) frames
 * skip every switch-core stage that only makes sense for frames the switch
 * itself is bridging/routing, matching the vendor driver's ppe_servcode_init.
 * The ingress/egress bitmaps bypass every stage except those the vendor
 * driver also leaves active: my-MAC check, service-code re-lookup and fake
 * L2 protocol insertion on ingress, and post-routing ACL check on egress.
 * Unlike that vendor default, fake MAC header insertion (bit 8) is also
 * bypassed here: the vendor only relies on that stage for traffic marked
 * via the TX descriptor's own fake_mac bit (set for L3-only traffic with
 * no real Ethernet header), which this driver never sends - every CPU TX
 * frame here already has one. Leaving that stage active anyway silently
 * dropped every CPU-bypass frame addressed to a real unicast destination
 * before it ever reached the port's TX MAC, while broadcast/multicast
 * frames were delivered normally; bypassing it fixed unicast delivery. */
static void
qppe_servcode_init (vnet_dev_t *dev, qppe_device_t *qd)
{
  u32 sc = EDMA_SC_BYPASS_ID;
  ppe_reg_service_tbl_bypass_bitmap_t ingress_bypass = { .as_u32 = ~0 };
  ppe_reg_eg_bypass_bitmap_t egress_bypass = { .as_u32 = ~0 };
  ppe_reg_in_l2_service_tbl_w0_t in_l2;
  u32 offset;

  ingress_bypass.my_mac_check_byp = 0;
  ingress_bypass.service_code_byp = 0;
  ingress_bypass.fake_l2_proto_byp = 0;

  egress_bypass.acl_post_routing_check_byp = 0;
  in_l2 = (ppe_reg_in_l2_service_tbl_w0_t) {
    .egress_bypass_bitmap = egress_bypass.as_u32,
  };

  offset = PPE_REG_IN_L2_SERVICE_TBL (sc);
  qppe_mmio_write32 (qd, offset, in_l2.as_u32);

  offset = PPE_REG_SERVICE_TBL (sc);
  qppe_mmio_write32 (qd, offset, ingress_bypass.as_u32);
  qppe_mmio_write32 (qd, offset + 4, 0);

  offset = PPE_REG_EG_SERVICE_TBL (sc);
  qppe_mmio_write32 (qd, offset, 0);
  qppe_mmio_write32 (qd, offset + 4, 0);

  offset = PPE_REG_TL_SERVICE_TBL (sc);
  qppe_mmio_write32 (qd, offset, 0);

  log_debug (dev, "initialized PPE service code %u for bypassed CPU-originated TX (0x%08x/0x%08x)",
	     sc, in_l2.as_u32, ingress_bypass.as_u32);
}

u8 *
format_qppe_service_tbl (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 3, "sc", "bypass_bitmap", "rx_counting_en");
  for (u32 sc = 0; sc < 256; sc++)
    {
      u32 offset = PPE_REG_SERVICE_TBL (sc);
      u32 bypass_bitmap = qppe_mmio_read32 (qd, offset);
      ppe_reg_service_tbl_w1_t w1;

      if (bypass_bitmap == 0)
	continue;

      w1.as_u32 = qppe_mmio_read32 (qd, offset + 4);

      table_format_cell (&table, row, 0, "%u", sc);
      table_format_cell (&table, row, 1, "0x%08x", bypass_bitmap);
      table_format_cell (&table, row, 2, "%u", w1.rx_counting_en);
      row++;
    }
  u32 indent = format_get_indent (s);
  s = format (s, "PPE SERVICE_TBL:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

u8 *
format_qppe_in_l2_service_tbl (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 6, "sc", "dst_port_id", "direction", "egress_bypass_bitmap",
		     "rx_cnt_en", "tx_cnt_en");
  for (u32 sc = 0; sc < 256; sc++)
    {
      ppe_reg_in_l2_service_tbl_w0_t w0 = {
	.as_u32 = qppe_mmio_read32 (qd, PPE_REG_IN_L2_SERVICE_TBL (sc)),
      };

      if (w0.as_u32 == 0)
	continue;

      uword *egress_bypass_bitmap = clib_bitmap_set_multiple (0, 0, w0.egress_bypass_bitmap, 32);

      table_format_cell (&table, row, 0, "%u", sc);
      table_format_cell (&table, row, 1, w0.dst_port_id_valid ? "%u" : "-", w0.dst_port_id);
      table_format_cell (&table, row, 2, "%u", w0.dst_direction);
      table_format_cell (&table, row, 3, "%U", format_bitmap_list, egress_bypass_bitmap);
      clib_bitmap_free (egress_bypass_bitmap);
      table_format_cell (&table, row, 4, "%u", w0.rx_cnt_en);
      table_format_cell (&table, row, 5, "%u", w0.tx_cnt_en);
      row++;
    }
  u32 indent = format_get_indent (s);
  s = format (s, "PPE IN_L2_SERVICE_TBL:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

u8 *
format_qppe_eg_service_tbl (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 6, "sc", "field_update_action", "next_sc", "hw_services", "offset_sel",
		     "tx_counting_en");
  for (u32 sc = 0; sc < 256; sc++)
    {
      u32 offset = PPE_REG_EG_SERVICE_TBL (sc);
      u32 field_update_action = qppe_mmio_read32 (qd, offset);
      ppe_reg_eg_service_tbl_w1_t w1;

      if (field_update_action == 0)
	continue;

      w1.as_u32 = qppe_mmio_read32 (qd, offset + 4);

      table_format_cell (&table, row, 0, "%u", sc);
      table_format_cell (&table, row, 1, "0x%08x", field_update_action);
      table_format_cell (&table, row, 2, "%u", w1.next_service_code);
      table_format_cell (&table, row, 3, "%u", w1.hw_services);
      table_format_cell (&table, row, 4, "%u", w1.offset_sel);
      table_format_cell (&table, row, 5, "%u", w1.tx_counting_en);
      row++;
    }
  u32 indent = format_get_indent (s);
  s = format (s, "PPE EG_SERVICE_TBL:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

u8 *
format_qppe_tl_service_tbl (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 2, "sc", "bypass_bitmap");
  for (u32 sc = 0; sc < 256; sc++)
    {
      u32 bypass_bitmap = qppe_mmio_read32 (qd, PPE_REG_TL_SERVICE_TBL (sc));

      if (bypass_bitmap == 0)
	continue;

      table_format_cell (&table, row, 0, "%u", sc);
      table_format_cell (&table, row, 1, "0x%08x", bypass_bitmap);
      row++;
    }
  u32 indent = format_get_indent (s);
  s = format (s, "PPE TL_SERVICE_TBL:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

u8 *
format_qppe_uni_drop_cnt_tbl (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 3, "queue", "pkts dropped", "bytes dropped");
  for (u32 q = 0; q < PPE_UNI_DROP_CNT_TBL_ENTRIES; q++)
    {
      u32 offset = PPE_REG_UNI_DROP_CNT_TBL (q);
      u32 pkt = qppe_mmio_read32 (qd, offset);
      u32 byte_lo = qppe_mmio_read32 (qd, offset + 4);
      u64 byte = ((u64) (qppe_mmio_read32 (qd, offset + 8) & 0xff) << 32) | byte_lo;

      if (pkt == 0 && byte == 0)
	continue;

      table_format_cell (&table, row, 0, "%u", q);
      table_format_cell (&table, row, 1, "%u", pkt);
      table_format_cell (&table, row, 2, "%llu", byte);
      row++;
    }
  u32 indent = format_get_indent (s);
  s = format (s, "PPE UNI_DROP_CNT_TBL (queues with drops, if any):");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

vnet_dev_rv_t
qppe_edma_tx_ring_start (vlib_main_t *vm __clib_unused, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  ppe_reg_edma_port_control_t port_control = {};
  ppe_reg_edma_txdesc_ctrl_t txdesc_ctrl = {};
  u32 offset, value;

  if (tq->started)
    return VNET_DEV_OK;
  port_control.as_u32 = qppe_mmio_read32 (qd, EDMA_BASE_OFFSET + EDMA_REG_PORT_CTRL_ADDR);

  if (tq->descs == 0 || tq->sec_descs == 0 || tq->cmpl_descs == 0)
    {
      log_err (dev, "cannot start TX queue %u: ring storage is incomplete", txq->queue_id);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  if (qd->n_active_tx_queues == 0)
    {
      u32 i;

      /* clear the global TXDESC-to-TXCMPL ring map before any ring claims an
       * entry in it, same as the RXDESC-to-fill map is cleared once in
       * qppe_edma_rx_queue_mapping_configure. */
      for (i = 0; i < 6; i++)
	qppe_mmio_write32 (qd, EDMA_BASE_OFFSET + EDMA_REG_TXDESC2CMPL_MAP_0 + i * 4, 0);

      qppe_servcode_init (dev, qd);
    }

  offset = EDMA_BASE_OFFSET + EDMA_REG_TXDESC2CMPL_MAP_0 +
	   (tq->desc_ring_id / EDMA_TXDESC2CMPL_MAP_RINGS_PER_WORD) * sizeof (u32);
  value = qppe_mmio_read32 (qd, offset);
  value |=
    (tq->cmpl_ring_id & ((1u << EDMA_TXDESC2CMPL_MAP_RING_BITS) - 1))
    << ((tq->desc_ring_id % EDMA_TXDESC2CMPL_MAP_RINGS_PER_WORD) * EDMA_TXDESC2CMPL_MAP_RING_BITS);
  qppe_mmio_write32 (qd, offset, value);
  log_debug (dev, "mapped TX descriptor ring %u to TX completion ring %u at offset 0x%x: 0x%08x",
	     tq->desc_ring_id, tq->cmpl_ring_id, offset, value);

  tq->prod = 0;
  tq->cmpl_cons = 0;
  tq->avail_desc = 0;

  offset = EDMA_BASE_OFFSET + EDMA_REG_TXDESC_PROD_IDX (tq->desc_ring_id);
  qppe_mmio_write32 (qd, offset, 0);

  offset = EDMA_BASE_OFFSET + EDMA_REG_TXCMPL_CONS_IDX (tq->cmpl_ring_id);
  qppe_mmio_write32 (qd, offset, 0);

  offset = EDMA_BASE_OFFSET + EDMA_REG_TXDESC_CTRL (tq->desc_ring_id);
  txdesc_ctrl.as_u32 = qppe_mmio_read32 (qd, offset);
  txdesc_ctrl.fc_grp_id = txq->port->port_id;
  txdesc_ctrl.tx_enable = 1;
  qppe_mmio_write32 (qd, offset, txdesc_ctrl.as_u32);
  if (!((ppe_reg_edma_txdesc_ctrl_t) { .as_u32 = qppe_mmio_read32 (qd, offset) }).tx_enable)
    {
      log_err (dev, "TX descriptor ring %u did not enable at offset 0x%x", tq->desc_ring_id,
	       offset);
      return VNET_DEV_ERR_INIT_FAILED;
    }
  log_debug (dev, "enabled TX descriptor ring %u at offset 0x%x: 0x%08x", tq->desc_ring_id, offset,
	     txdesc_ctrl.as_u32);

  if (!port_control.edma_enable)
    {
      port_control.edma_enable = 1;
      offset = EDMA_BASE_OFFSET + EDMA_REG_PORT_CTRL_ADDR;
      qppe_mmio_write32 (qd, offset, port_control.as_u32);
      if (!((ppe_reg_edma_port_control_t) { .as_u32 = qppe_mmio_read32 (qd, offset) }).edma_enable)
	{
	  log_err (dev, "EDMA did not enable at offset 0x%x", offset);
	  qppe_edma_tx_ring_stop (txq);
	  return VNET_DEV_ERR_INIT_FAILED;
	}
      qd->edma_enabled = 1;
      log_debug (dev, "enabled EDMA at offset 0x%x: 0x%08x", offset, port_control.as_u32);
    }
  tq->started = 1;
  qd->n_active_tx_queues++;

  return VNET_DEV_OK;
}

void
qppe_edma_tx_ring_stop (vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  ppe_reg_edma_port_control_t port_control = {};
  ppe_reg_edma_txdesc_ctrl_t txdesc_ctrl = {};
  u32 offset;

  offset = EDMA_BASE_OFFSET + EDMA_REG_TXDESC_CTRL (tq->desc_ring_id);
  txdesc_ctrl.as_u32 = qppe_mmio_read32 (qd, offset);
  txdesc_ctrl.tx_enable = 0;
  qppe_mmio_write32 (qd, offset, txdesc_ctrl.as_u32);
  txdesc_ctrl.as_u32 = qppe_mmio_read32 (qd, offset);
  log_debug (dev, "disabled TX descriptor ring %u at offset 0x%x: 0x%08x", tq->desc_ring_id, offset,
	     txdesc_ctrl.as_u32);

  if (tq->started)
    {
      tq->started = 0;
      ASSERT (qd->n_active_tx_queues > 0);
      qd->n_active_tx_queues--;
    }

  if (qd->n_active_rx_queues == 0 && qd->n_active_tx_queues == 0 && qd->edma_enabled)
    {
      offset = EDMA_BASE_OFFSET + EDMA_REG_PORT_CTRL_ADDR;
      port_control.as_u32 = qppe_mmio_read32 (qd, offset);
      port_control.edma_enable = 0;
      qppe_mmio_write32 (qd, offset, port_control.as_u32);
      qd->edma_enabled = 0;
      log_debug (dev, "disabled EDMA at offset 0x%x: 0x%08x", offset, port_control.as_u32);
    }
}
