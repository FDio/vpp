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
  ena_rxq_t *rxq, **rxqp;
  u16 n_desc = 1U << log2_n_desc;
  u32 sz, compl_sq_indices_off;
  u16 qi;

  sz = sizeof (ena_rxq_t);
  sz += round_pow2 (sizeof (rxq->sq_buffer_indices[0]) * n_desc,
		    CLIB_CACHE_LINE_BYTES);
  compl_sq_indices_off = sz;
  sz += round_pow2 (sizeof (u16) * n_desc, CLIB_CACHE_LINE_BYTES);

  rxq = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
  clib_memset (rxq, 0, sz);
  rxq->log2_n_desc = log2_n_desc;
  rxq->compl_sq_indices_off = compl_sq_indices_off;

  pool_get_zero (ed->rxqs, rxqp);
  rxq->qid = qi = rxqp - ed->rxqs;
  rxqp[0] = rxq;

  ena_log_debug (ed, "rx_queue_alloc[%u]: depth %u alloc_sz 0x%x", qi, n_desc,
		 sz);

  sz = round_pow2 (n_desc * sizeof (ena_rx_cdesc_t), CLIB_CACHE_LINE_BYTES);

  if (rxq->cqes == 0)
    {
      rxq->cqes = vlib_physmem_alloc_aligned_on_numa (
	vm, sz, CLIB_CACHE_LINE_BYTES, ed->numa_node);

      if (rxq->cqes == 0)
	goto error;

      ena_log_debug (
	ed, "rx_queue_alloc[%u]: %u bytes of cq memory allocard at %p (0%lx)",
	qi, sz, rxq->cqes, ena_dma_addr (vm, ed, rxq->cqes));
    }

  clib_memset (rxq->cqes, 0, sz);

  sz = round_pow2 (n_desc * sizeof (ena_rx_desc_t), CLIB_CACHE_LINE_BYTES);
  if (rxq->sqes == 0)
    {
      rxq->sqes = vlib_physmem_alloc_aligned_on_numa (
	vm, sz, CLIB_CACHE_LINE_BYTES, ed->numa_node);

      if (rxq->sqes == 0)
	goto error;

      ena_log_debug (
	ed, "rx_queue_alloc[%u]: %u bytes of sq memory allocard at %p (0%lx)",
	qi, sz, rxq->sqes, ena_dma_addr (vm, ed, rxq->sqes));
    }

  clib_memset (rxq->sqes, 0, sz);

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
  ena_txq_t *txq, **txqp;
  u16 n_desc = 1U << log2_n_desc;
  u32 sz, sqe_templates_offset;
  u16 qi;

  sz = sizeof (ena_txq_t);
  sz += round_pow2 (sizeof (txq->sq_buffer_indices[0]) * n_desc,
		    CLIB_CACHE_LINE_BYTES);
  sqe_templates_offset = sz;
  sz += round_pow2 (sizeof (txq->sqes[0].as_u64x2[0]) * n_desc,
		    CLIB_CACHE_LINE_BYTES);
  txq = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
  clib_memset (txq, 0, sz);
  txq->log2_n_desc = log2_n_desc;
  txq->sqe_templates_offset = sqe_templates_offset;

  pool_get_zero (ed->txqs, txqp);
  qi = txqp - ed->txqs;
  txqp[0] = txq;

  ena_log_debug (ed, "tx_queue_alloc[%u]: depth %u alloc_sz 0x%x", qi, n_desc,
		 sz);

  sz = round_pow2 (n_desc * sizeof (ena_tx_cdesc_t), CLIB_CACHE_LINE_BYTES);
  sz += round_pow2 (sizeof (txq->sq_buffer_indices[0]) * n_desc,
		    CLIB_CACHE_LINE_BYTES);

  if (txq->cqes == 0)
    {
      txq->cqes = vlib_physmem_alloc_aligned_on_numa (
	vm, sz, CLIB_CACHE_LINE_BYTES, ed->numa_node);

      if (txq->cqes == 0)
	goto error;

      ena_log_debug (
	ed, "tx_queue_alloc[%u]: %u bytes of cq memory allocard at %p (0%lx)",
	qi, sz, txq->cqes, ena_dma_addr (vm, ed, txq->cqes));
    }
  clib_memset (txq->cqes, 0, sz);

  sz = round_pow2 (n_desc * sizeof (ena_tx_desc_t), CLIB_CACHE_LINE_BYTES);

  if (txq->sqes == 0)
    {
      txq->sqes = vlib_physmem_alloc_aligned_on_numa (
	vm, sz, CLIB_CACHE_LINE_BYTES, ed->numa_node);

      if (txq->sqes == 0)
	goto error;

      ena_log_debug (
	ed, "tx_queue_alloc[%u]: %u bytes of sq memory allocard at %p (0%lx)",
	qi, sz, txq->sqes, ena_dma_addr (vm, ed, txq->sqes));
    }

  clib_memset (txq->sqes, 0, sz);

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
  ena_rxq_t *rxq = *pool_elt_at_index (ed->rxqs, queue_index);
  ena_log_debug (ed, "rx_queue_free[%u]:", queue_index);
  vlib_physmem_free (vm, rxq->cqes);
  vlib_physmem_free (vm, rxq->sqes);
  clib_mem_free (rxq);
  pool_put_index (ed->rxqs, queue_index);
  if (pool_elts (ed->rxqs) == 0)
    pool_free (ed->rxqs);
}

void
ena_tx_queue_free (vlib_main_t *vm, ena_device_t *ed, u16 queue_index)
{
  ena_txq_t *txq = *pool_elt_at_index (ed->txqs, queue_index);
  ena_log_debug (ed, "tx_queue_free[%u]:", queue_index);
  vlib_physmem_free (vm, txq->cqes);
  vlib_physmem_free (vm, txq->sqes);
  clib_mem_free (txq);
  pool_put_index (ed->txqs, queue_index);
  if (pool_elts (ed->txqs) == 0)
    pool_free (ed->txqs);
}

void
ena_rx_queue_enable (vlib_main_t *vm, ena_device_t *ed, u16 queue_index)
{
  clib_error_t *err;
  ena_rxq_t *rxq = *pool_elt_at_index (ed->rxqs, queue_index);
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

  ena_log_debug (ed, "rx_queue_enable[%u]:", queue_index);

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

  rxq->buffer_pool_index =
    vlib_buffer_pool_get_default_for_numa (vm, ed->numa_node);

  for (int i = 0; i < n_desc; i++)
    {
      rxq->sqes[i] = (ena_rx_desc_t){
	.lo = { .length = buffer_size,
		.comp_req = 1,
		.first = 1,
		.last = 1,
		.reserved5 = 1, /* ena_com says MBO */
		.req_id = i },
      };
      rxq->sq_buffer_indices[i] = VLIB_BUFFER_INVALID_INDEX;
    }

  rxq->sq_next = 0;
  rxq->n_compl_sqes = n_desc;
  for (u16 i = 0, *csi = ena_rxq_get_compl_sqe_indices (rxq); i < n_desc; i++)
    csi[i] = i;

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
  ena_txq_t *txq = *pool_elt_at_index (ed->txqs, queue_index);
  u64 *sqe_templates = ena_txq_get_sqe_templates (txq);
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

  ena_log_debug (ed, "tx_queue_enable[%u]:", queue_index);

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

  for (u32 i = 0; i < n_desc; i++)
    {
      sqe_templates[i] =
	(ena_tx_desc_t){ .req_id_lo = i, .req_id_hi = i >> 10, .comp_req = 1 }
	  .as_u64x2[0];

      txq->sq_buffer_indices[i] = VLIB_BUFFER_INVALID_INDEX;
    }

  ena_log_debug (ed, "tx_queue_enable[%u]: sq %u created, sq_db %p",
		 queue_index, txq->sq_idx, txq->sq_db);

  txq->sq_head = 0;
  txq->sq_tail = 0;
  txq->cq_next = 0;

  ena_queue_state_set_ready (&txq->state);
  return;

error:
  ena_log_err (ed, "tx_queue_enable: %U", format_clib_error, err);
  clib_error_free (err);
}

static void
ena_free_sq_buffer_indices (vlib_main_t *vm, u32 *sq_buffer_indices,
			    u32 n_desc)
{
  u32 *to = sq_buffer_indices;

  for (u32 *from = to; from < sq_buffer_indices + n_desc; from++)
    if (from[0] != VLIB_BUFFER_INVALID_INDEX)
      to++[0] = from[0];

  if (to - sq_buffer_indices > 0)
    vlib_buffer_free (vm, sq_buffer_indices, to - sq_buffer_indices);
}

void
ena_rx_queue_disable (vlib_main_t *vm, ena_device_t *ed, u16 queue_index)
{
  clib_error_t *err;
  ena_rxq_t *rxq = *pool_elt_at_index (ed->rxqs, queue_index);
  u16 n_desc = 1U << rxq->log2_n_desc;

  if (rxq->state == ENA_QUEUE_STATE_DISABLED)
    return;

  ena_log_debug (ed, "rx_queue_disable[%u]:", queue_index);

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

  if (rxq->n_compl_sqes < n_desc)
    ena_free_sq_buffer_indices (vm, rxq->sq_buffer_indices, n_desc);
}

void
ena_tx_queue_disable (vlib_main_t *vm, ena_device_t *ed, u16 queue_index)
{
  ena_txq_t *txq = *pool_elt_at_index (ed->txqs, queue_index);
  clib_error_t *err;
  u16 n_desc = 1U << txq->log2_n_desc;

  if (txq->state == ENA_QUEUE_STATE_DISABLED)
    return;

  ena_log_debug (ed, "tx_queue_disable[%u]:", queue_index);

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

  if (txq->sq_head != txq->sq_tail)
    ena_free_sq_buffer_indices (vm, txq->sq_buffer_indices, n_desc);
}
