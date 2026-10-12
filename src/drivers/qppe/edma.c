/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
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

static u32
qppe_edma_reg_read32 (qppe_device_t *qd, u32 offset)
{
  volatile u32 *regs = qd->regs;

  return regs[offset / sizeof (u32)];
}

static void
qppe_edma_reg_write32 (qppe_device_t *qd, u32 offset, u32 value)
{
  volatile u32 *regs = qd->regs;

  regs[offset / sizeof (u32)] = value;
}

void
qppe_edma_rx_ring_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);

  if (qr->buffer_indices)
    {
      if (qr->n_buffers)
	vlib_buffer_free (vm, qr->buffer_indices, qr->n_buffers);
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

vnet_dev_rv_t
qppe_edma_rx_ring_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);
  vlib_buffer_pool_t *buffer_pool;
  vnet_dev_rv_t rv;
  u32 desc_size;
  u32 n_allocated;
  u32 i;

  desc_size = rxq->size * sizeof (qppe_edma_rxfill_desc_t);
  rv = vnet_dev_dma_mem_alloc (vm, dev, desc_size, CLIB_CACHE_LINE_BYTES, (void **) &qr->fill_descs,
			       "EDMA RX fill descriptors");
  if (rv != VNET_DEV_OK)
    return rv;
  qr->fill_dma = vnet_dev_get_dma_addr (vm, dev, qr->fill_descs);

  desc_size = rxq->size * sizeof (qppe_edma_rx_desc_t);
  rv = vnet_dev_dma_mem_alloc (vm, dev, desc_size, CLIB_CACHE_LINE_BYTES,
			       (void **) &qr->primary_descs, "EDMA RX primary descriptors");
  if (rv != VNET_DEV_OK)
    {
      qppe_edma_rx_ring_free (vm, rxq);
      return rv;
    }
  qr->primary_dma = vnet_dev_get_dma_addr (vm, dev, qr->primary_descs);

  rv = vnet_dev_dma_mem_alloc (vm, dev, desc_size, CLIB_CACHE_LINE_BYTES,
			       (void **) &qr->secondary_descs, "EDMA RX secondary descriptors");
  if (rv != VNET_DEV_OK)
    {
      qppe_edma_rx_ring_free (vm, rxq);
      return rv;
    }
  qr->secondary_dma = vnet_dev_get_dma_addr (vm, dev, qr->secondary_descs);

  qr->buffer_pool_index = vlib_buffer_pool_get_default_for_numa (vm, dev->numa_node);
  buffer_pool = vlib_get_buffer_pool (vm, qr->buffer_pool_index);
  if (buffer_pool->data_size < QPPE_EDMA_RX_BUFFER_SIZE)
    {
      log_err (dev, "VPP buffer pool %u data size %u is smaller than EDMA RX buffer size %u",
	       qr->buffer_pool_index, buffer_pool->data_size, QPPE_EDMA_RX_BUFFER_SIZE);
      qppe_edma_rx_ring_free (vm, rxq);
      return VNET_DEV_ERR_BUFFER_ALLOC_FAIL;
    }

  qr->buffer_indices = clib_mem_alloc_aligned (rxq->size * sizeof (u32), CLIB_CACHE_LINE_BYTES);
  if (qr->buffer_indices == 0)
    {
      log_err (dev, "cannot allocate buffer index table for %u EDMA RX buffers", rxq->size);
      qppe_edma_rx_ring_free (vm, rxq);
      return VNET_DEV_ERR_BUFFER_ALLOC_FAIL;
    }

  n_allocated =
    vlib_buffer_alloc_from_pool (vm, qr->buffer_indices, rxq->size - 1, qr->buffer_pool_index);
  qr->n_buffers = n_allocated;
  if (n_allocated != rxq->size - 1)
    {
      log_err (dev, "allocated %u of %u EDMA RX buffers from VPP buffer pool %u", n_allocated,
	       rxq->size - 1, qr->buffer_pool_index);
      qppe_edma_rx_ring_free (vm, rxq);
      return VNET_DEV_ERR_BUFFER_ALLOC_FAIL;
    }

  for (i = 0; i < rxq->size - 1; i++)
    {
      u32 buffer_index = qr->buffer_indices[i];
      vlib_buffer_t *buffer = vlib_get_buffer (vm, buffer_index);
      qppe_edma_rxfill_desc_t *desc = &qr->fill_descs[i];
      uword buffer_dma = vnet_dev_get_dma_addr (vm, dev, buffer->data);

      if (buffer_dma > 0xffffffff)
	{
	  log_err (dev, "EDMA RX buffer %u DMA address 0x%lx exceeds the 32-bit descriptor field",
		   i, buffer_dma);
	  qppe_edma_rx_ring_free (vm, rxq);
	  return VNET_DEV_ERR_INIT_FAILED;
	}

      if (i == 0)
	qr->first_buffer_dma = buffer_dma;
      qr->last_buffer_dma = buffer_dma;

      desc->buffer_address.as_u32 = buffer_dma;
      desc->length.fields.buffer_size = QPPE_EDMA_RX_BUFFER_SIZE;
      desc->opaque_low = buffer_index;
    }

  log_debug (dev,
	     "allocated RX ring storage: %u descriptors, fill VA %p DMA 0x%lx (%u bytes), "
	     "primary VA %p DMA 0x%lx (%u bytes), secondary VA %p DMA 0x%lx (%u bytes); "
	     "VPP pool %u supplied %u of %u initial packet buffers at %u bytes each, "
	     "first/last DMA 0x%lx/0x%lx; "
	     "fill descriptors initialized; hardware remains disabled and unconfigured",
	     rxq->size, qr->fill_descs, qr->fill_dma, rxq->size * sizeof (qppe_edma_rxfill_desc_t),
	     qr->primary_descs, qr->primary_dma, rxq->size * sizeof (qppe_edma_rx_desc_t),
	     qr->secondary_descs, qr->secondary_dma, rxq->size * sizeof (qppe_edma_rx_desc_t),
	     qr->buffer_pool_index, qr->n_buffers, rxq->size - 1, QPPE_EDMA_RX_BUFFER_SIZE,
	     qr->first_buffer_dma, qr->last_buffer_dma);

  return VNET_DEV_OK;
}

vnet_dev_rv_t
qppe_edma_rx_ring_configure (vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);
  qppe_reg_edma_ring_base_t rxfill_base = {
    .fields.dma_address = qr->fill_dma,
  };
  qppe_reg_edma_ring_base_t rxdesc_base = {
    .fields.dma_address = qr->primary_dma,
  };
  qppe_reg_edma_ring_base_t rxdesc_preheader_base = {
    .fields.dma_address = qr->secondary_dma,
  };
  qppe_reg_edma_rxfill_ring_size_t rxfill_size = {
    .fields.ring_size = rxq->size,
  };
  qppe_reg_edma_rxdesc_ring_size_t rxdesc_size = {
    .fields.ring_size = rxq->size,
  };
  qppe_reg_edma_rxfill_ring_enable_t rxfill_enable = {};
  qppe_reg_edma_rxdesc_control_t rxdesc_control = {};
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

  offset = QPPE_EDMA_BASE_OFFSET + QPPE_EDMA_REG_RXFILL_RING_EN (QPPE_EDMA_RXFILL_RING_ID);
  rxfill_enable.as_u32 = qppe_edma_reg_read32 (qd, offset);
  log_debug (dev, "read RX fill ring %u enable at offset 0x%x: 0x%08x, %s",
	     QPPE_EDMA_RXFILL_RING_ID, offset, rxfill_enable.as_u32,
	     rxfill_enable.fields.enable ? "enabled" : "disabled");
  if (rxfill_enable.fields.enable)
    {
      log_err (dev, "cannot configure RX fill ring %u while it is enabled",
	       QPPE_EDMA_RXFILL_RING_ID);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = QPPE_EDMA_BASE_OFFSET + QPPE_EDMA_REG_RXDESC_CTRL (QPPE_EDMA_RXDESC_RING_ID);
  rxdesc_control.as_u32 = qppe_edma_reg_read32 (qd, offset);
  log_debug (dev, "read RX descriptor ring %u control at offset 0x%x: 0x%08x, RX %s",
	     QPPE_EDMA_RXDESC_RING_ID, offset, rxdesc_control.as_u32,
	     rxdesc_control.fields.rx_enable ? "enabled" : "disabled");
  if (rxdesc_control.fields.rx_enable)
    {
      log_err (dev, "cannot configure RX descriptor ring %u while RX is enabled",
	       QPPE_EDMA_RXDESC_RING_ID);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = QPPE_EDMA_BASE_OFFSET + QPPE_EDMA_REG_RXFILL_BA (QPPE_EDMA_RXFILL_RING_ID);
  log_debug (dev, "writing RX fill ring %u base at offset 0x%x: DMA 0x%08x",
	     QPPE_EDMA_RXFILL_RING_ID, offset, rxfill_base.as_u32);
  qppe_edma_reg_write32 (qd, offset, rxfill_base.as_u32);
  value = qppe_edma_reg_read32 (qd, offset);
  log_debug (dev, "read RX fill ring %u base at offset 0x%x: 0x%08x", QPPE_EDMA_RXFILL_RING_ID,
	     offset, value);
  if (value != rxfill_base.as_u32)
    {
      log_err (dev, "RX fill ring %u base readback mismatch: wrote 0x%08x, read 0x%08x",
	       QPPE_EDMA_RXFILL_RING_ID, rxfill_base.as_u32, value);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = QPPE_EDMA_BASE_OFFSET + QPPE_EDMA_REG_RXFILL_RING_SIZE (QPPE_EDMA_RXFILL_RING_ID);
  log_debug (dev, "writing RX fill ring %u size at offset 0x%x: %u entries",
	     QPPE_EDMA_RXFILL_RING_ID, offset, rxq->size);
  qppe_edma_reg_write32 (qd, offset, rxfill_size.as_u32);
  value = qppe_edma_reg_read32 (qd, offset);
  log_debug (dev, "read RX fill ring %u size at offset 0x%x: 0x%08x", QPPE_EDMA_RXFILL_RING_ID,
	     offset, value);
  if (value != rxfill_size.as_u32)
    {
      log_err (dev, "RX fill ring %u size readback mismatch: wrote 0x%08x, read 0x%08x",
	       QPPE_EDMA_RXFILL_RING_ID, rxfill_size.as_u32, value);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = QPPE_EDMA_BASE_OFFSET + QPPE_EDMA_REG_RXDESC_BA (QPPE_EDMA_RXDESC_RING_ID);
  log_debug (dev, "writing RX descriptor ring %u base at offset 0x%x: DMA 0x%08x",
	     QPPE_EDMA_RXDESC_RING_ID, offset, rxdesc_base.as_u32);
  qppe_edma_reg_write32 (qd, offset, rxdesc_base.as_u32);
  value = qppe_edma_reg_read32 (qd, offset);
  log_debug (dev, "read RX descriptor ring %u base at offset 0x%x: 0x%08x",
	     QPPE_EDMA_RXDESC_RING_ID, offset, value);
  if (value != rxdesc_base.as_u32)
    {
      log_err (dev, "RX descriptor ring %u base readback mismatch: wrote 0x%08x, read 0x%08x",
	       QPPE_EDMA_RXDESC_RING_ID, rxdesc_base.as_u32, value);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = QPPE_EDMA_BASE_OFFSET + QPPE_EDMA_REG_RXDESC_PREHEADER_BA (QPPE_EDMA_RXDESC_RING_ID);
  log_debug (dev, "writing RX descriptor ring %u preheader base at offset 0x%x: DMA 0x%08x",
	     QPPE_EDMA_RXDESC_RING_ID, offset, rxdesc_preheader_base.as_u32);
  qppe_edma_reg_write32 (qd, offset, rxdesc_preheader_base.as_u32);
  value = qppe_edma_reg_read32 (qd, offset);
  log_debug (dev, "read RX descriptor ring %u preheader base at offset 0x%x: 0x%08x",
	     QPPE_EDMA_RXDESC_RING_ID, offset, value);
  if (value != rxdesc_preheader_base.as_u32)
    {
      log_err (dev,
	       "RX descriptor ring %u preheader base readback mismatch: wrote 0x%08x, read 0x%08x",
	       QPPE_EDMA_RXDESC_RING_ID, rxdesc_preheader_base.as_u32, value);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = QPPE_EDMA_BASE_OFFSET + QPPE_EDMA_REG_RXDESC_RING_SIZE (QPPE_EDMA_RXDESC_RING_ID);
  log_debug (dev, "writing RX descriptor ring %u size at offset 0x%x: %u entries",
	     QPPE_EDMA_RXDESC_RING_ID, offset, rxq->size);
  qppe_edma_reg_write32 (qd, offset, rxdesc_size.as_u32);
  value = qppe_edma_reg_read32 (qd, offset);
  log_debug (dev, "read RX descriptor ring %u size at offset 0x%x: 0x%08x",
	     QPPE_EDMA_RXDESC_RING_ID, offset, value);
  if (value != rxdesc_size.as_u32)
    {
      log_err (dev, "RX descriptor ring %u size readback mismatch: wrote 0x%08x, read 0x%08x",
	       QPPE_EDMA_RXDESC_RING_ID, rxdesc_size.as_u32, value);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  log_debug (dev,
	     "RX fill ring %u and RX descriptor ring %u base/size configured and verified; "
	     "neither ring enabled, no producer index written, EDMA port control unchanged",
	     QPPE_EDMA_RXFILL_RING_ID, QPPE_EDMA_RXDESC_RING_ID);

  return VNET_DEV_OK;
}
