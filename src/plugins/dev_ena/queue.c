/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>

#include <dev_ena/ena.h>
#include <dev_ena/ena_inlines.h>

VLIB_REGISTER_LOG_CLASS (ena_log, static) = {
  .class_name = "ena",
  .subclass_name = "queue",
};

void
ena_rx_queue_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  ena_rxq_t *eq = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_port_t *port = rxq->port;
  vnet_dev_t *dev = port->dev;

  ASSERT (rxq->started == 0);
  ASSERT (eq->cq_created == 0);
  ASSERT (eq->sq_created == 0);

  ena_log_debug (dev, "rx_queue_free[%u]:", rxq->queue_id);

  clib_mem_free (eq->buffer_indices);
  clib_mem_free (eq->compl_sqe_indices);
  vnet_dev_dma_mem_free (vm, dev, eq->cqes);
  vnet_dev_dma_mem_free (vm, dev, eq->sqes);
}

vnet_dev_rv_t
ena_rx_queue_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_port_t *port = rxq->port;
  vnet_dev_t *dev = port->dev;
  ena_rxq_t *eq = vnet_dev_get_rx_queue_data (rxq);
  u16 size = rxq->size;
  vnet_dev_rv_t rv;

  ASSERT (eq->buffer_indices != 0);
  ASSERT (eq->cqes != 0);
  ASSERT (eq->sqes != 0);

  rxq->queue_id = rxq->index;

  eq->buffer_indices = clib_mem_alloc_aligned (
    sizeof (eq->buffer_indices[0]) * size, CLIB_CACHE_LINE_BYTES);

  eq->compl_sqe_indices = clib_mem_alloc_aligned (
    sizeof (eq->compl_sqe_indices[0]) * size, CLIB_CACHE_LINE_BYTES);

  rv = vnet_dev_dma_mem_alloc (vm, dev, sizeof (eq->cqes[0]) * size, 0,
			       (void **) eq->cqes);

  if (rv != VNET_DEV_OK)
    goto err;

  rv = vnet_dev_dma_mem_alloc (vm, dev, sizeof (eq->sqes[0]) * size, 0,
			       (void **) eq->sqes);
  if (rv != VNET_DEV_OK)
    goto err;

  return VNET_DEV_OK;

err:
  ena_rx_queue_free (vm, rxq);
  return rv;
}

void
ena_tx_queue_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  ena_txq_t *eq = vnet_dev_get_tx_queue_data (txq);
  vnet_dev_port_t *port = txq->port;
  vnet_dev_t *dev = port->dev;

  // FIXME ASSERT (txq->started == 0);

  ena_log_debug (dev, "tx_queue_free[%u]:", txq->queue_id);

  clib_mem_free (eq->buffer_indices);
  clib_mem_free (eq->sqe_templates);
  vnet_dev_dma_mem_free (vm, dev, eq->cqes);
  vnet_dev_dma_mem_free (vm, dev, eq->sqes);
}

vnet_dev_rv_t
ena_tx_queue_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_port_t *port = txq->port;
  vnet_dev_t *dev = port->dev;
  ena_txq_t *eq = vnet_dev_get_tx_queue_data (txq);
  u16 size = txq->size;
  vnet_dev_rv_t rv;

  ASSERT (eq->buffer_indices != 0);
  ASSERT (eq->cqes != 0);
  ASSERT (eq->sqes != 0);

  txq->queue_id = txq->index;

  eq->buffer_indices = clib_mem_alloc_aligned (
    sizeof (eq->buffer_indices[0]) * size, CLIB_CACHE_LINE_BYTES);
  eq->sqe_templates = clib_mem_alloc_aligned (
    sizeof (eq->sqe_templates[0]) * size, CLIB_CACHE_LINE_BYTES);

  rv = vnet_dev_dma_mem_alloc (vm, dev, sizeof (eq->cqes[0]) * size, 0,
			       (void **) eq->cqes);

  if (rv != VNET_DEV_OK)
    goto err;

  rv = vnet_dev_dma_mem_alloc (vm, dev, sizeof (eq->sqes[0]) * size, 0,
			       (void **) eq->sqes);
  if (rv != VNET_DEV_OK)
    goto err;

  return VNET_DEV_OK;

err:
  ena_tx_queue_free (vm, txq);
  return rv;
}

vnet_dev_rv_t
ena_rx_queue_start (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  ena_rxq_t *eq = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_port_t *port = rxq->port;
  vnet_dev_t *dev = port->dev;
  ena_device_t *ed = vnet_dev_get_data (dev);
  u16 buffer_size = vlib_buffer_get_default_data_size (vm);
  u16 size = rxq->size;
  vnet_dev_rv_t rv;

  /* Create Completion Queue */
  ena_admin_create_cq_resp_t cqresp;
  ena_admin_create_cq_cmd_t cqcmd = {
    .interrupt_mode_enabled = 1,
    .cq_entry_size_words = sizeof (ena_rx_cdesc_t) / 4,
    .cq_depth = size,
    .msix_vector = ~0,
  };

  ena_set_mem_addr (vm, dev, &cqcmd.cq_ba, eq->cqes);
  if ((rv = ena_admin_create_cq (vm, dev, &cqcmd, &cqresp)))
    {
      ena_log_err (dev, "rx_queue_enable[%u]: cq creation failed",
		   rxq->queue_id);
      goto error;
    }

  eq->cq_idx = cqresp.cq_idx;
  eq->cq_created = 1;

  ena_log_debug (dev, "rx_queue_enable[%u]: cq %u created", rxq->queue_id,
		 eq->cq_idx);

  /* Create Submission Queue */
  ena_admin_create_sq_resp_t sqresp;
  ena_admin_create_sq_cmd_t sqcmd = {
    .sq_direction = ENA_ADMIN_SQ_DIRECTION_RX,
    .placement_policy = ENA_ADMIN_SQ_PLACEMENT_POLICY_HOST,
    .completion_policy = ENA_ADMIN_SQ_COMPLETION_POLICY_DESC,
    .is_physically_contiguous = 1,
    .sq_depth = size,
    .cq_idx = cqresp.cq_idx,
  };

  ena_set_mem_addr (vm, dev, &sqcmd.sq_ba, eq->sqes);
  if ((rv = ena_admin_create_sq (vm, dev, &sqcmd, &sqresp)))
    {
      ena_log_err (dev, "rx_queue_enable[%u]: sq creation failed",
		   rxq->queue_id);
      goto error;
    }

  eq->sq_idx = sqresp.sq_idx;
  eq->sq_db = (u32 *) ((u8 *) ed->reg_bar + sqresp.sq_doorbell_offset);
  eq->sq_created = 1;

  ena_log_debug (dev, "rx_queue_enable[%u]: sq %u created, sq_db %p",
		 rxq->queue_id, eq->sq_idx, eq->sq_db);

  for (int i = 0; i < size; i++)
    {
      eq->sqes[i] = (ena_rx_desc_t){
	.lo = {
          .length = buffer_size,
          .comp_req = 1,
          .first = 1,
          .last = 1,
          .reserved5 = 1, /* ena_com says MBO */
          .req_id = i,
        },
      };
      eq->buffer_indices[i] = VLIB_BUFFER_INVALID_INDEX;
      eq->compl_sqe_indices[i] = i;
    }

  eq->sq_next = 0;
  eq->n_compl_sqes = size;

  return VNET_DEV_OK;

error:
  ena_rx_queue_stop (vm, rxq);
  return rv;
}

vnet_dev_rv_t
ena_tx_queue_start (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  ena_txq_t *eq = vnet_dev_get_tx_queue_data (txq);
  vnet_dev_port_t *port = txq->port;
  vnet_dev_t *dev = port->dev;
  ena_device_t *ed = vnet_dev_get_data (dev);
  u16 size = txq->size;
  vnet_dev_rv_t rv;

  /* Create Completion Queue */
  ena_admin_create_cq_resp_t cqresp;
  ena_admin_create_cq_cmd_t cqcmd = {
    .interrupt_mode_enabled = 1,
    .cq_entry_size_words = sizeof (ena_tx_cdesc_t) / 4,
    .cq_depth = size,
    .msix_vector = ~0,
  };

  ena_set_mem_addr (vm, dev, &cqcmd.cq_ba, eq->cqes);
  if ((rv = ena_admin_create_cq (vm, dev, &cqcmd, &cqresp)))
    {
      ena_log_err (dev, "tx_queue_enable[%u]: cq creation failed",
		   txq->queue_id);
      goto error;
    }

  eq->cq_idx = cqresp.cq_idx;
  eq->cq_created = 1;

  ena_log_debug (dev, "tx_queue_enable[%u]: cq %u created", txq->queue_id,
		 eq->cq_idx);

  /* Create Submission Queue */
  ena_admin_create_sq_resp_t sqresp;
  ena_admin_create_sq_cmd_t sqcmd = {
    .sq_direction = ENA_ADMIN_SQ_DIRECTION_TX,
    .placement_policy = eq->llq ? ENA_ADMIN_SQ_PLACEMENT_POLICY_DEVICE :
				  ENA_ADMIN_SQ_PLACEMENT_POLICY_HOST,
    .completion_policy = ENA_ADMIN_SQ_COMPLETION_POLICY_DESC,
    .is_physically_contiguous = 1,
    .sq_depth = size,
    .cq_idx = cqresp.cq_idx,
  };

  if (eq->llq == 0)
    ena_set_mem_addr (vm, dev, &sqcmd.sq_ba, eq->sqes);
  if ((rv = ena_admin_create_sq (vm, dev, &sqcmd, &sqresp)))
    {
      ena_log_err (dev, "tx_queue_enable[%u]: sq creation failed",
		   txq->queue_id);
      goto error;
    }

  eq->sq_idx = sqresp.sq_idx;
  eq->sq_db = (u32 *) ((u8 *) ed->reg_bar + sqresp.sq_doorbell_offset);
  eq->sq_created = 1;

  ena_log_debug (dev, "tx_queue_enable[%u]: sq %u created, sq_db %p",
		 txq->queue_id, eq->sq_idx, eq->sq_db);

  for (u32 i = 0; i < size; i++)
    {
      eq->sqe_templates[i] =
	(ena_tx_desc_t){ .req_id_lo = i, .req_id_hi = i >> 10, .comp_req = 1 }
	  .as_u64x2[0];

      eq->buffer_indices[i] = VLIB_BUFFER_INVALID_INDEX;
    }

  eq->sq_head = 0;
  eq->sq_tail = 0;
  eq->cq_next = 0;

#if 0
  if (txq->llq)
    txq->llq_128b_descs =
      (ena_tx_llq_desc128_t *) ((u8 *) ed->mem_bar +
				sqresp.llq_descriptors_offset);


  ena_log_debug (
    ed, "tx_queue_enable[%u]: sq %u created, sq_db %p llq_desc %p",
    queue_index, txq->sq_idx, txq->sq_db, txq->llq ? txq->llq_128b_descs : 0);
#endif
error:
  ena_tx_queue_stop (vm, txq);
  return rv;
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
ena_rx_queue_stop (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  ena_rxq_t *eq = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_t *dev = rxq->port->dev;
  vnet_dev_rv_t rv;

  if (eq->sq_created)
    {
      ena_admin_destroy_sq_cmd_t cmd = {
	.sq_idx = eq->sq_idx,
	.sq_direction = ENA_ADMIN_SQ_DIRECTION_TX,
      };

      if ((rv = ena_admin_destroy_sq (vm, dev, &cmd)) != VNET_DEV_OK)
	ena_log_err (dev, "rx_queue_stop[%u]: failed to destroy sq %u",
		     rxq->queue_id, eq->sq_idx);
      eq->sq_created = 0;
    };

  if (eq->cq_created)
    {
      ena_admin_destroy_cq_cmd_t cmd = {
	.cq_idx = eq->cq_idx,
      };

      if ((rv = ena_admin_destroy_cq (vm, dev, &cmd)) != VNET_DEV_OK)
	ena_log_err (dev, "rx_queue_stop[%u]: failed to destroy cq %u",
		     rxq->queue_id, eq->cq_idx);
      eq->cq_created = 0;
    };

  if (eq->n_compl_sqes < rxq->size)
    ena_free_sq_buffer_indices (vm, eq->buffer_indices, rxq->size);
}

void
ena_tx_queue_stop (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  ena_txq_t *eq = vnet_dev_get_tx_queue_data (txq);
  vnet_dev_t *dev = txq->port->dev;
  vnet_dev_rv_t rv;

  if (eq->sq_created)
    {
      ena_admin_destroy_sq_cmd_t cmd = {
	.sq_idx = eq->sq_idx,
	.sq_direction = ENA_ADMIN_SQ_DIRECTION_TX,
      };

      if ((rv = ena_admin_destroy_sq (vm, dev, &cmd)) != VNET_DEV_OK)
	ena_log_err (dev, "tx_queue_stop[%u]: failed to destroy sq %u",
		     txq->queue_id, eq->sq_idx);
      eq->sq_created = 0;
    };

  if (eq->cq_created)
    {
      ena_admin_destroy_cq_cmd_t cmd = {
	.cq_idx = eq->cq_idx,
      };

      if ((rv = ena_admin_destroy_cq (vm, dev, &cmd)) != VNET_DEV_OK)
	ena_log_err (dev, "tx_queue_stop[%u]: failed to destroy cq %u",
		     txq->queue_id, eq->cq_idx);
      eq->cq_created = 0;
    };

  if (eq->sq_head != eq->sq_tail)
    ena_free_sq_buffer_indices (vm, eq->buffer_indices, txq->size);
}
