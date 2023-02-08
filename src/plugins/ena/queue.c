/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>

#include <ena/ena.h>
#include <ena/ena_inlines.h>

VLIB_REGISTER_LOG_CLASS (ena_log, static) = {
  .class_name = "ena",
  .subclass_name = "queue",
};

clib_error_t *
ena_rx_queue_alloc (vlib_main_t *vm, ena_device_t *ed, u16 log2_n_desc,
		    u16 *queue_index)
{
  clib_error_t *err;
  ena_rxq_t *rxq;
  u16 n_desc = 1U << log2_n_desc;
  u32 sq_alloc_sz = n_desc * sizeof (ena_rx_desc_t);
  u32 cq_alloc_sz = n_desc * sizeof (ena_rx_cdesc_t);
  u16 qi;

  pool_get_zero (ed->rxqs, rxq);
  rxq->log2_n_desc = log2_n_desc;
  qi = rxq - ed->rxqs;

  ena_log_debug (ed, "rx_queue_alloc[%u]: depth %u", qi, n_desc);

  cq_alloc_sz = round_pow2 (cq_alloc_sz, CLIB_CACHE_LINE_BYTES);
  sq_alloc_sz = round_pow2 (sq_alloc_sz, CLIB_CACHE_LINE_BYTES);

  if (rxq->cqes == 0)
    {
      rxq->cqes = vlib_physmem_alloc_aligned_on_numa (
	vm, cq_alloc_sz, CLIB_CACHE_LINE_BYTES, ed->numa_node);

      if (rxq->cqes == 0)
	goto error;

      ena_log_debug (
	ed, "rx_queue_alloc[%u]: %u bytes of cq memory allocard at %p (0%lx)",
	qi, cq_alloc_sz, rxq->cqes, ena_dma_addr (vm, ed, rxq->cqes));
    }

  if (rxq->sqes == 0)
    {
      rxq->sqes = vlib_physmem_alloc_aligned_on_numa (
	vm, sq_alloc_sz, CLIB_CACHE_LINE_BYTES, ed->numa_node);

      if (rxq->sqes == 0)
	goto error;

      ena_log_debug (
	ed, "rx_queue_alloc[%u]: %u bytes of sq memory allocard at %p (0%lx)",
	qi, sq_alloc_sz, rxq->sqes, ena_dma_addr (vm, ed, rxq->sqes));
    }

  clib_memset (rxq->cqes, 0, cq_alloc_sz);
  clib_memset (rxq->sqes, 0, sq_alloc_sz);

  vec_validate_aligned (rxq->buffers, n_desc - 1, CLIB_CACHE_LINE_BYTES);

  if (queue_index)
    *queue_index = qi;

  return 0;

error:
  err = vlib_physmem_last_error (vm);
  if (rxq->cqes)
    vlib_physmem_free (vm, rxq->cqes);
  if (rxq->sqes)
    vlib_physmem_free (vm, rxq->sqes);
  return err;
}

clib_error_t *
ena_tx_queue_alloc (vlib_main_t *vm, ena_device_t *ed, u16 log2_n_desc,
		    u16 *queue_index)
{
  clib_error_t *err;
  ena_txq_t *txq;
  u16 n_desc = 1U << log2_n_desc;
  u32 cq_alloc_sz = n_desc * sizeof (ena_tx_cdesc_t);
  u32 sq_alloc_sz = n_desc * sizeof (ena_tx_desc_t);
  u16 qi;

  pool_get_zero (ed->txqs, txq);
  txq->log2_n_desc = log2_n_desc;
  qi = txq - ed->txqs;

  ena_log_debug (ed, "tx_queue_alloc[%u]: depth %u", qi, n_desc);

  sq_alloc_sz = round_pow2 (sq_alloc_sz, CLIB_CACHE_LINE_BYTES);
  cq_alloc_sz = round_pow2 (cq_alloc_sz, CLIB_CACHE_LINE_BYTES);

  if (txq->cqes == 0)
    {
      txq->cqes = vlib_physmem_alloc_aligned_on_numa (
	vm, cq_alloc_sz, CLIB_CACHE_LINE_BYTES, ed->numa_node);

      if (txq->cqes == 0)
	goto error;

      ena_log_debug (
	ed, "tx_queue_alloc[%u]: %u bytes of cq memory allocard at %p (0%lx)",
	qi, cq_alloc_sz, txq->cqes, ena_dma_addr (vm, ed, txq->cqes));
    }

  if (txq->sqes == 0)
    {
      txq->sqes = vlib_physmem_alloc_aligned_on_numa (
	vm, sq_alloc_sz, CLIB_CACHE_LINE_BYTES, ed->numa_node);

      if (txq->sqes == 0)
	goto error;

      ena_log_debug (
	ed, "tx_queue_alloc[%u]: %u bytes of sq memory allocard at %p (0%lx)",
	qi, sq_alloc_sz, txq->sqes, ena_dma_addr (vm, ed, txq->sqes));
    }

  clib_memset (txq->cqes, 0, cq_alloc_sz);
  clib_memset (txq->sqes, 0, sq_alloc_sz);

  vec_validate_aligned (txq->buffers, n_desc - 1, CLIB_CACHE_LINE_BYTES);

  if (queue_index)
    *queue_index = qi;

  return 0;

error:
  err = vlib_physmem_last_error (vm);
  if (txq->cqes)
    vlib_physmem_free (vm, txq->cqes);
  if (txq->sqes)
    vlib_physmem_free (vm, txq->sqes);
  return err;
}

void
ena_rx_queue_free (vlib_main_t *vm, ena_device_t *ed, u16 queue_index)
{
  ena_rxq_t *rxq = pool_elt_at_index (ed->rxqs, queue_index);
  vlib_physmem_free (vm, rxq->cqes);
  vlib_physmem_free (vm, rxq->sqes);
  vec_free (rxq->buffers);
  pool_put_index (ed->rxqs, queue_index);
  if (pool_elts (ed->rxqs) == 0)
    pool_free (ed->rxqs);
}

void
ena_tx_queue_free (vlib_main_t *vm, ena_device_t *ed, u16 queue_index)
{
  ena_txq_t *txq = pool_elt_at_index (ed->txqs, queue_index);
  vlib_physmem_free (vm, txq->cqes);
  vlib_physmem_free (vm, txq->sqes);
  vec_free (txq->buffers);
  pool_put_index (ed->txqs, queue_index);
  if (pool_elts (ed->txqs) == 0)
    pool_free (ed->txqs);
}

void
ena_rx_queue_enable (vlib_main_t *vm, ena_device_t *ed, u16 queue_index)
{
  clib_error_t *err;
  ena_rxq_t *rxq = pool_elt_at_index (ed->rxqs, queue_index);
  u16 buffer_size = vlib_buffer_get_default_data_size (vm);
  u16 n_desc = 1U << rxq->log2_n_desc;
  ena_admin_create_cq_resp_t cqresp;
  ena_admin_create_sq_resp_t sqresp;

  ena_admin_create_cq_cmd_t cqcmd = {
    .interrupt_mode_enabled = 1,
    .cq_entry_size_words = sizeof (ena_rx_cdesc_t) / 4,
    .cq_depth = n_desc,
    .msix_vector = ~0,
  };

  ena_admin_create_sq_cmd_t sqcmd = {
    .sq_direction = ENA_ADMIN_SQ_DIRECTION_RX,
    .placement_policy = ENA_ADMIN_SQ_PLACEMENT_POLICY_HOST,
    .completion_policy = ENA_ADMIN_SQ_COMPLETION_POLICY_DESC,
    .is_physically_contiguous = 1,
    .sq_depth = n_desc,
  };

  if (rxq->state != ENA_QUEUE_STATE_DISABLED)
    return;

  /* Create Completion Queue */
  ena_set_mem_addr (vm, ed, &cqcmd.cq_ba, rxq->cqes);
  if ((err = ena_admin_create_cq (vm, ed, &cqcmd, &cqresp)))
    goto error;

  rxq->cq_created = 1;
  rxq->cq_idx = cqresp.cq_idx;

  ena_log_debug (ed, "rx_queue_enable[%u]: cq %u created", queue_index,
		 rxq->cq_idx);

  /* Create Submission Queue */
  sqcmd.cq_idx = cqresp.cq_idx;
  ena_set_mem_addr (vm, ed, &sqcmd.sq_ba, rxq->sqes);
  if ((err = ena_admin_create_sq (vm, ed, &sqcmd, &sqresp)))
    goto error;

  rxq->sq_created = 1;
  rxq->sq_idx = sqresp.sq_idx;
  rxq->sq_db = (u32 *) ((u8 *) ed->reg_bar + sqresp.sq_doorbell_offset);

  ena_log_debug (ed, "rx_queue_enable[%u]: sq %u created, sq_db %p",
		 queue_index, rxq->sq_idx, rxq->sq_db);

  /* Enqueue Buffers */
  rxq->buffer_pool_index =
    vlib_buffer_pool_get_default_for_numa (vm, ed->numa_node);
  rxq->n_enq = vlib_buffer_alloc_from_pool (vm, rxq->buffers, n_desc,
					    rxq->buffer_pool_index);

  if (rxq->n_enq == 0)
    {
      err = clib_error_return (
	0, "Unable to allocate at least one buffer for rx queue");
      goto error;
    }

  rxq->desc_template.length = buffer_size;
  rxq->desc_template.comp_req = 1;

  ena_log_debug (ed, "rx_queue_enable[%u]: %u buffers enqueued", queue_index,
		 rxq->n_enq);

  for (int i = 0; i < rxq->n_enq; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, rxq->buffers[i]);
      ena_rx_desc_t t = rxq->desc_template;
      u64 pa;
      pa = ed->va_dma ? vlib_buffer_get_va (b) : vlib_buffer_get_pa (vm, b);
      ena_rx_desc_t *d = rxq->sqes + i;
      t.phase = 1;
      t.buff_addr_lo = pa;
      t.buff_addr_hi = pa >> 32;
      d->as_u32x4 = t.as_u32x4;
    }

  rxq->sq_next = 0;
  __atomic_store_n (rxq->sq_db, rxq->n_enq, __ATOMIC_RELEASE);

  ena_queue_state_set_ready (&rxq->state);

  return;

error:
  ena_log_err (ed, "rx_queue_enable: %U", format_clib_error, err);
  clib_error_free (err);
}

void
ena_tx_queue_enable (vlib_main_t *vm, ena_device_t *ed, u16 queue_index)
{
  clib_error_t *err;
  ena_txq_t *txq = pool_elt_at_index (ed->txqs, queue_index);
  u16 n_desc = 1U << txq->log2_n_desc;
  ena_admin_create_cq_resp_t cqresp;
  ena_admin_create_sq_resp_t sqresp;

  ena_admin_create_cq_cmd_t cqcmd = {
    .interrupt_mode_enabled = 1,
    .cq_entry_size_words = sizeof (ena_tx_cdesc_t) / 4,
    .cq_depth = n_desc,
    .msix_vector = ~0,
  };

  ena_admin_create_sq_cmd_t sqcmd = {
    .sq_direction = ENA_ADMIN_SQ_DIRECTION_TX,
    .placement_policy = ENA_ADMIN_SQ_PLACEMENT_POLICY_HOST,
    .completion_policy = ENA_ADMIN_SQ_COMPLETION_POLICY_DESC,
    .is_physically_contiguous = 1,
    .sq_depth = n_desc,
  };

  if (txq->state != ENA_QUEUE_STATE_DISABLED)
    return;

  /* Create Completion Queue */
  ena_set_mem_addr (vm, ed, &cqcmd.cq_ba, txq->cqes);
  if ((err = ena_admin_create_cq (vm, ed, &cqcmd, &cqresp)))
    goto error;

  txq->cq_created = 1;
  txq->cq_idx = cqresp.cq_idx;

  ena_log_debug (ed, "tx_queue_enable[%u]: cq %u created", queue_index,
		 txq->cq_idx);

  /* Create Submission Queue */
  sqcmd.cq_idx = cqresp.cq_idx;
  ena_set_mem_addr (vm, ed, &sqcmd.sq_ba, txq->sqes);
  if ((err = ena_admin_create_sq (vm, ed, &sqcmd, &sqresp)))
    goto error;

  txq->sq_created = 1;
  txq->sq_idx = sqresp.sq_idx;
  txq->sq_db = (u32 *) ((u8 *) ed->reg_bar + sqresp.sq_doorbell_offset);

  ena_log_debug (ed, "tx_queue_enable[%u]: sq %u created, sq_db %p",
		 queue_index, txq->sq_idx, txq->sq_db);

  txq->n_enq = 0;
  txq->cq_next = 0;
  txq->n_free = 0;

  ena_queue_state_set_ready (&txq->state);
  return;

error:
  ena_log_err (ed, "tx_queue_enable: %U", format_clib_error, err);
  clib_error_free (err);
}

void
ena_rx_queue_disable (vlib_main_t *vm, ena_device_t *ed, u16 queue_index)
{
  clib_error_t *err;
  ena_rxq_t *rxq = pool_elt_at_index (ed->rxqs, queue_index);

  if (rxq->state == ENA_QUEUE_STATE_DISABLED)
    return;

  ena_queue_state_set_disabled (&rxq->state);

  if (rxq->sq_created)
    {
      ena_admin_destroy_sq_cmd_t cmd = { .sq_idx = rxq->sq_idx,
					 .sq_direction =
					   ENA_ADMIN_SQ_DIRECTION_RX };

      if ((err = ena_admin_destroy_sq (vm, ed, &cmd)))
	{
	  ena_log_err (ed, "destroy_rx_queue: %U", format_clib_error, err);
	  clib_error_free (err);
	}
      rxq->sq_created = 0;
    };

  if (rxq->cq_created)
    {
      ena_admin_destroy_cq_cmd_t cmd = { .cq_idx = rxq->cq_idx };
      if ((err = ena_admin_destroy_cq (vm, ed, &cmd)))
	{
	  ena_log_err (ed, "destroy_rx_queue: %U", format_clib_error, err);
	  clib_error_free (err);
	}
      rxq->cq_created = 0;
    };

  if (rxq->n_enq)
    {
      vlib_buffer_free_from_ring_no_next (
	vm, rxq->buffers, rxq->sq_next & pow2_mask (rxq->log2_n_desc),
	1 << rxq->log2_n_desc, rxq->n_enq);
      rxq->n_enq = 0;
    }
}

void
ena_tx_queue_disable (vlib_main_t *vm, ena_device_t *ed, u16 queue_index)
{
  ena_txq_t *txq = pool_elt_at_index (ed->txqs, queue_index);
  clib_error_t *err;

  if (txq->state == ENA_QUEUE_STATE_DISABLED)
    return;

  ena_queue_state_set_disabled (&txq->state);

  if (txq->sq_created)
    {
      ena_admin_destroy_sq_cmd_t cmd = { .sq_idx = txq->sq_idx,
					 .sq_direction =
					   ENA_ADMIN_SQ_DIRECTION_TX };

      if ((err = ena_admin_destroy_sq (vm, ed, &cmd)))
	{
	  ena_log_err (ed, "destroy_rx_queue: %U", format_clib_error, err);
	  clib_error_free (err);
	}
    };

  if (txq->cq_created)
    {
      ena_admin_destroy_cq_cmd_t cmd = { .cq_idx = txq->cq_idx };
      if ((err = ena_admin_destroy_cq (vm, ed, &cmd)))
	{
	  ena_log_err (ed, "destroy_rx_queue: %U", format_clib_error, err);
	  clib_error_free (err);
	}
    };

  if (txq->n_enq)
    {
      vlib_buffer_free_from_ring_no_next (vm, txq->buffers,
					  (txq->sq_next - txq->n_enq) &
					    pow2_mask (txq->log2_n_desc),
					  1 << txq->log2_n_desc, txq->n_enq);
      txq->n_enq = 0;
    }
}
