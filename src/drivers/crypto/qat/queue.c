/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <qat.h>

VLIB_REGISTER_LOG_CLASS (qat_log, static) = {
  .class_name = "qat",
  .subclass_name = "queue",
};

#define QAT_QUEUE_STOP_TIMEOUT 1.0

static u8
qat_ring_size_code (u32 n_bytes)
{
  /* 128 bytes is encoded as 1, each next power of 2 adds 1 */
  return min_log2 (n_bytes) - min_log2 (QAT_RING_MIN_SIZE_BYTES) + 1;
}

static void
qat_ring_program (qat_device_t *qd, u8 bank, u8 ring, u64 dma_addr, qat_ring_config_t cfg)
{
  u64 base = dma_addr >> qd->cfg->ring_base_shift;

  qat_reg_write (qd->bar0, qat_ring_cfg_reg (qd, bank, QAT_RING_CSR_CONFIG (ring)), cfg.as_u32);
  qat_reg_write (qd->bar0, qat_ring_cfg_reg (qd, bank, QAT_RING_CSR_BASE_LO (ring)), (u32) base);
  qat_reg_write (qd->bar0, qat_ring_cfg_reg (qd, bank, QAT_RING_CSR_BASE_HI (ring)), base >> 32);
}

static void
qat_ring_arb_enable (qat_device_t *qd, qat_ring_pair_t *rp, u8 enable)
{
  u32 reg = qat_bank_reg (qd, rp->bank, QAT_RING_CSR_SRV_ARB_EN);
  u32 arb = qat_reg_read (qd->bar0, reg);

  /* one enable bit per request ring of the bank */
  arb = enable ? arb | (1 << rp->tx_ring) : arb & ~(1 << rp->tx_ring);
  qat_reg_write (qd->bar0, reg, arb);
}

vnet_dev_rv_t
qat_ring_pair_reset (vlib_main_t *vm, vnet_dev_t *dev, qat_ring_pair_t *rp)
{
  qat_device_t *qd = vnet_dev_get_data (dev);
  u8 rings[] = { rp->tx_ring, rp->rx_ring };

  if (qd->gen == QAT_GEN4)
    return qat_pfvf_ring_pair_reset (vm, dev, rp->bank);

  qat_ring_arb_enable (qd, rp, 0);
  FOREACH_ARRAY_ELT (r, rings)
    {
      qat_ring_program (qd, rp->bank, *r, 0, (qat_ring_config_t) {});
      qat_reg_write (qd->bar0, qat_bank_reg (qd, rp->bank, QAT_RING_CSR_HEAD (*r)), 0);
      qat_reg_write (qd->bar0, qat_bank_reg (qd, rp->bank, QAT_RING_CSR_TAIL (*r)), 0);
    }
  return VNET_DEV_OK;
}

void
qat_queue_deinit (vlib_main_t *vm, vnet_dev_crypto_queue_t *cq)
{
  qat_queue_t *q = vnet_dev_get_crypto_queue_data (cq);
  vnet_dev_t *dev = cq->dev;

  if (q->tx_ring)
    vnet_dev_dma_mem_free (vm, dev, q->tx_ring);
  if (q->rx_ring)
    vnet_dev_dma_mem_free (vm, dev, q->rx_ring);
  if (q->sgl)
    vnet_dev_dma_mem_free (vm, dev, q->sgl);
  vec_free (q->fifo);
  q->tx_ring = 0;
  q->rx_ring = 0;
  q->sgl = 0;
}

vnet_dev_rv_t
qat_queue_init (vlib_main_t *vm, vnet_dev_crypto_queue_t *cq)
{
  qat_queue_t *q = vnet_dev_get_crypto_queue_data (cq);
  vnet_dev_t *dev = cq->dev;
  qat_device_t *qd = vnet_dev_get_data (dev);
  u32 n = cq->size;
  u32 tx_sz = n * QAT_TX_MSG_SIZE, rx_sz = n * QAT_RX_MSG_SIZE;
  vnet_dev_rv_t rv;

  ASSERT (is_pow2 (n));

  /* the ring pair was given when the queue was added */
  *q = (qat_queue_t) {
    .rp = q->rp,
    .mask = n - 1,
    .max_inflight = n - 1,
    .va_dma = dev->va_dma,
  };

  /* rings must be aligned to their size */
  rv = vnet_dev_dma_mem_alloc (vm, dev, tx_sz, tx_sz, (void **) &q->tx_ring, "qat queue %u tx ring",
			       cq->index);
  if (rv != VNET_DEV_OK)
    goto error;

  rv = vnet_dev_dma_mem_alloc (vm, dev, rx_sz, rx_sz, (void **) &q->rx_ring, "qat queue %u rx ring",
			       cq->index);
  if (rv != VNET_DEV_OK)
    goto error;

  rv = vnet_dev_dma_mem_alloc (vm, dev, n * sizeof (qat_sgl_t), CLIB_CACHE_LINE_BYTES,
			       (void **) &q->sgl, "qat queue %u sgl", cq->index);
  if (rv != VNET_DEV_OK)
    goto error;

  vec_validate_aligned (q->fifo, n - 1, CLIB_CACHE_LINE_BYTES);

  clib_memset (q->tx_ring, 0, tx_sz);
  clib_memset_u8 (q->rx_ring, QAT_RING_EMPTY_SIG_BYTE, rx_sz);

  q->tx_ring_dma = vnet_dev_get_dma_addr (vm, dev, q->tx_ring);
  q->rx_ring_dma = vnet_dev_get_dma_addr (vm, dev, q->rx_ring);
  q->sgl_dma = vnet_dev_get_dma_addr (vm, dev, q->sgl);
  q->tx_tail_csr =
    (u32 *) ((u8 *) qd->bar0 + qat_bank_reg (qd, q->rp.bank, QAT_RING_CSR_TAIL (q->rp.tx_ring)));
  q->rx_head_csr =
    (u32 *) ((u8 *) qd->bar0 + qat_bank_reg (qd, q->rp.bank, QAT_RING_CSR_HEAD (q->rp.rx_ring)));

  log_debug (dev, "queue %u: bank %u rings %u/%u, %u descriptors", cq->index, q->rp.bank,
	     q->rp.tx_ring, q->rp.rx_ring, n);
  return VNET_DEV_OK;

error:
  qat_queue_deinit (vm, cq);
  return rv;
}

vnet_dev_rv_t
qat_queue_start (vlib_main_t *vm __clib_unused, vnet_dev_crypto_queue_t *cq)
{
  qat_queue_t *q = vnet_dev_get_crypto_queue_data (cq);
  qat_device_t *qd = vnet_dev_get_data (cq->dev);
  u32 n = cq->size;
  qat_ring_config_t tx_cfg = {
    .ring_size = qat_ring_size_code (n * QAT_TX_MSG_SIZE),
  };
  qat_ring_config_t rx_cfg = {
    .ring_size = qat_ring_size_code (n * QAT_RX_MSG_SIZE),
    .near_full_wm = QAT_RING_NEAR_WATERMARK_512,
  };

  qat_ring_program (qd, q->rp.bank, q->rp.tx_ring, q->tx_ring_dma, tx_cfg);
  qat_ring_program (qd, q->rp.bank, q->rp.rx_ring, q->rx_ring_dma, rx_cfg);
  qat_ring_arb_enable (qd, &q->rp, 1);
  log_debug (cq->dev, "queue %u started: tx %U", cq->index, format_qat_ring_csrs, qd, q->rp.bank,
	     q->rp.tx_ring);
  log_debug (cq->dev, "queue %u started: rx %U", cq->index, format_qat_ring_csrs, qd, q->rp.bank,
	     q->rp.rx_ring);
  return VNET_DEV_OK;
}

/* frames of requests still on the ring are dropped */
void
qat_queue_stop (vlib_main_t *vm, vnet_dev_crypto_queue_t *cq)
{
  qat_queue_t *q = vnet_dev_get_crypto_queue_data (cq);
  qat_device_t *qd = vnet_dev_get_data (cq->dev);
  f64 timeout = vlib_time_now (vm) + QAT_QUEUE_STOP_TIMEOUT;
  u32 n_frames = q->fifo_tail - q->fifo_head;

  while (q->n_enq != q->n_deq)
    {
      qat_fw_resp_t *r = q->rx_ring + (q->rx_head & q->mask);

      if (__atomic_load_n ((u32 *) r, __ATOMIC_ACQUIRE) != QAT_RING_EMPTY_SIG)
	{
	  clib_memset_u8 (r, QAT_RING_EMPTY_SIG_BYTE, sizeof (*r));
	  q->rx_head++;
	  q->n_deq++;
	  continue;
	}

      if (vlib_time_now (vm) > timeout)
	{
	  log_err (cq->dev, "queue %u: timeout waiting for %u requests", cq->index,
		   q->n_enq - q->n_deq);
	  break;
	}
      CLIB_PAUSE ();
    }

  qat_reg_write (qd->bar0, qat_bank_reg (qd, q->rp.bank, QAT_RING_CSR_HEAD (q->rp.rx_ring)),
		 (q->rx_head & q->mask) * QAT_RX_MSG_SIZE);
  qat_ring_arb_enable (qd, &q->rp, 0);

  if (n_frames)
    log_warn (cq->dev, "queue %u: %u crypto frames dropped", cq->index, n_frames);

  for (u32 i = q->fifo_head; i != q->fifo_tail; i++)
    vec_free (q->fifo[i & q->mask].status);

  q->fifo_head = q->fifo_tail = 0;
  q->n_deq = q->n_enq;
  log_debug (cq->dev, "queue %u stopped", cq->index);
}
