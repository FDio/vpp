/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vlib/buffer_funcs.h>
#include <edma_hw.h>
#include <qppe.h>

VLIB_REGISTER_LOG_CLASS (qppe_log, static) = {
  .class_name = "qppe",
  .subclass_name = "rxfill",
};

static void
qppe_rxfill_buffers_free (vlib_main_t *vm, vnet_dev_t *dev, qppe_rxfill_ring_t *rfr)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 mask = rfr->size - 1;
  u16 cons;
  u32 n_buffers;

  if (!rfr->buffers_posted)
    return;

  cons = qppe_mmio_read32 (qd, rfr->cons_mmio_off);
  ASSERT (rfr->n_refill <= rfr->size);
  n_buffers = rfr->size - rfr->n_refill;
  while (n_buffers--)
    {
      u32 bi = rfr->descs[cons & mask].opaque_low;

      vlib_buffer_free (vm, &bi, 1);
      cons++;
    }
  rfr->prod = cons;
  rfr->n_refill = 0;
  rfr->buffers_posted = 0;
  qppe_mmio_write32 (qd, rfr->prod_mmio_off, cons);
}

vnet_dev_rv_t
qppe_edma_rxfill_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);
  qppe_rxfill_ring_t *rfr;
  vnet_dev_rv_t rv;
  u32 fill_ring_sz = clib_args_get_uint32_val_by_name (dev->args, "fill_ring_size");
  u8 pool_index = vlib_buffer_pool_get_default_for_numa (vm, dev->numa_node);
  u32 buffer_size = vlib_buffer_get_default_data_size (vm);

  if (!is_pow2 (fill_ring_sz))
    {
      log_err (dev, "fill_ring_size must be a power of two, got %u", fill_ring_sz);
      return VNET_DEV_ERR_INVALID_ARG;
    }
  if (buffer_size == 0 || buffer_size > 0xffff)
    return VNET_DEV_ERR_NOT_SUPPORTED;
  if (rxq->rx_thread_index >= ARRAY_LEN (qd->rxfill_rings))
    {
      log_err (dev, "RX thread %u exceeds the %u RX fill rings", rxq->rx_thread_index,
	       ARRAY_LEN (qd->rxfill_rings));
      return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
    }
  if (qd->edma_enabled)
    return VNET_DEV_ERR_PORT_STARTED;

  rfr = &qd->rxfill_rings[rxq->rx_thread_index];
  if (rfr->n_rx_queues && rfr->buffer_pool_index != pool_index)
    return VNET_DEV_ERR_NOT_SUPPORTED;
  if (rfr->n_rx_queues == 0)
    {
      *rfr = (qppe_rxfill_ring_t) {
	.size = fill_ring_sz,
	.ring_id = rxq->rx_thread_index,
	.buffer_pool_index = pool_index,
	.prod_mmio_off = EDMA_BASE_OFFSET + EDMA_REG_RXFILL_PROD_IDX (rxq->rx_thread_index),
	.cons_mmio_off = EDMA_BASE_OFFSET + EDMA_REG_RXFILL_CONS_IDX (rxq->rx_thread_index),
      };
      rv = vnet_dev_dma_mem_alloc_coherent (vm, dev, rfr->size * sizeof (*rfr->descs),
					    CLIB_CACHE_LINE_BYTES, (void **) &rfr->descs,
					    "EDMA RX fill descriptors");
      if (rv != VNET_DEV_OK)
	return rv;
    }
  rfr->n_rx_queues++;
  qr->fill_ring_index = rxq->rx_thread_index;

  return VNET_DEV_OK;
}

u32
qppe_edma_rxfill_started_queues (vnet_dev_t *dev, qppe_rxfill_ring_t *rfr)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 fill_ring_index = rfr - qd->rxfill_rings;
  u32 count = 0;

  foreach_vnet_dev_port (port, dev)
    foreach_vnet_dev_port_rx_queue (rxq, port)
      {
	qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);

	if (qr->started && qr->fill_ring_index == fill_ring_index)
	  count++;
      }

  return count;
}

void
qppe_edma_rxfill_free (vlib_main_t *vm, vnet_dev_t *dev, qppe_rxfill_ring_t *rfr)
{
  ASSERT (rfr->n_rx_queues);
  if (--rfr->n_rx_queues == 0)
    {
      ASSERT (qppe_edma_rxfill_started_queues (dev, rfr) == 0);
      qppe_rxfill_buffers_free (vm, dev, rfr);
      vnet_dev_dma_mem_free (vm, dev, rfr->descs);
      *rfr = (qppe_rxfill_ring_t) {};
    }
}

vnet_dev_rv_t
qppe_edma_rxfill_configure (vlib_main_t *vm, vnet_dev_t *dev, qppe_rxfill_ring_t *rfr)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  uword dma = vnet_dev_get_dma_addr (vm, dev, rfr->descs);
  const qppe_reg_val_t regs[] = {
    {
      .off = EDMA_BASE_OFFSET + EDMA_REG_RXFILL_BA (rfr->ring_id),
      .val = dma,
    },
    {
      .off = EDMA_BASE_OFFSET + EDMA_REG_RXFILL_RING_SIZE (rfr->ring_id),
      .val = rfr->size,
    },
  };

  if (qd->edma_enabled)
    return VNET_DEV_ERR_PORT_STARTED;
  if (dma > 0xffffffff)
    return VNET_DEV_ERR_INIT_FAILED;
  return qppe_mmio_write_validate (dev, regs, ARRAY_LEN (regs));
}

vnet_dev_rv_t
qppe_edma_rxfill_start (vlib_main_t *vm, vnet_dev_t *dev, qppe_rxfill_ring_t *rfr)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);

  if (qppe_edma_rxfill_started_queues (dev, rfr) == 0)
    {
      ppe_reg_edma_rxfill_ring_enable_t enable = {
	.enable = 1,
      };
      u32 buffer_size = vlib_buffer_get_default_data_size (vm);
      u32 *indices = 0;
      u32 mask = rfr->size - 1;

      ASSERT (!rfr->buffers_posted);
      ASSERT (rfr->n_refill == 0);
      rfr->prod = qppe_mmio_read32 (qd, rfr->cons_mmio_off);
      qppe_mmio_write32 (qd, rfr->prod_mmio_off, rfr->prod);
      vec_validate (indices, rfr->size - 1);
      if (!vlib_buffer_strict_alloc_from_pool (vm, indices, rfr->size, rfr->buffer_pool_index))
	{
	  vec_free (indices);
	  return VNET_DEV_ERR_BUFFER_ALLOC_FAIL;
	}
      for (u32 i = 0; i < rfr->size; i++)
	{
	  vlib_buffer_t *b = vlib_get_buffer (vm, indices[i]);
	  edma_rxfill_desc_t *desc = &rfr->descs[(rfr->prod + i) & mask];

	  qppe_dma_cache_clean_invalidate (b->data, buffer_size);
	  *desc = (edma_rxfill_desc_t) {
	    .buffer_address = vnet_dev_get_dma_addr (vm, dev, b->data),
	    .buffer_size = buffer_size,
	    .opaque_low = indices[i],
	  };
	}
      rfr->prod += rfr->size;
      asm volatile ("dsb osh" : : : "memory");
      qppe_mmio_write32 (qd, rfr->prod_mmio_off, rfr->prod);
      rfr->buffers_posted = 1;
      rfr->prod &= mask;
      vec_free (indices);
      qppe_edma_reg_wr (qd, EDMA_REG_RXFILL_RING_EN (rfr->ring_id), enable.as_u32);
      enable.as_u32 = qppe_edma_reg_rd (qd, EDMA_REG_RXFILL_RING_EN (rfr->ring_id));
      if (!enable.enable)
	{
	  qppe_rxfill_buffers_free (vm, dev, rfr);
	  return VNET_DEV_ERR_INIT_FAILED;
	}
    }
  return VNET_DEV_OK;
}

void
qppe_edma_rxfill_stop (vlib_main_t *vm, vnet_dev_t *dev, qppe_rxfill_ring_t *rfr)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);

  if (qppe_edma_rxfill_started_queues (dev, rfr) == 0)
    {
      ppe_reg_edma_rxfill_ring_enable_t enable = {};

      qppe_edma_reg_wr (qd, EDMA_REG_RXFILL_RING_EN (rfr->ring_id), enable.as_u32);
      qppe_edma_reg_rd (qd, EDMA_REG_RXFILL_RING_EN (rfr->ring_id));
      qppe_rxfill_buffers_free (vm, dev, rfr);
    }
}
