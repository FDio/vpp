/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <errno.h>
#include <fcntl.h>
#include <ibverbs.h>

VLIB_REGISTER_LOG_CLASS (ibv_log, static) = {
  .class_name = "ibverbs",
  .subclass_name = "queue",
};

vnet_dev_rv_t
ibv_rxq_irq_enable (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);

  return rdma_rxq_irq_enable (vm, &iq->irq);
}

void
ibv_rxq_irq_disable (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);

  rdma_rxq_irq_disable (vm, &iq->irq);
}

void
ibv_rxq_wq_destroy (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  struct ibv_wc wc[VLIB_FRAME_SIZE];
  int rv_ibv;

  if (iq->ibv_wq)
    {
      rv_ibv = ibv_destroy_wq (iq->ibv_wq);
      if (rv_ibv)
	log_err (dev, "rxq %u ibv_destroy_wq failed rv %d", rxq->queue_id, rv_ibv);
      iq->ibv_wq = 0;
    }

  while (iq->ibv_cq && ibv_poll_cq (iq->ibv_cq, ARRAY_LEN (wc), wc) > 0)
    ;

  for (u32 slot = 0; slot < rxq->size; slot++)
    {
      u32 *bufs = iq->buffers + slot * IBV_RXQ_MAX_CHAIN_SZ;
      u8 n_used = iq->n_used[slot];

      if (n_used < iq->n_ds)
	vlib_buffer_free (vm, bufs + n_used, iq->n_ds - n_used);
      iq->n_used[slot] = IBV_RXQ_MAX_CHAIN_SZ;
    }

  iq->head = 0;
  iq->tail = 0;
}

vnet_dev_rv_t
ibv_rxq_wq_create (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  ibv_dev_t *rd = vnet_dev_get_data (dev);
  ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  u32 n_ds = (rxq->port->max_rx_frame_size + iq->buf_sz - 1) / iq->buf_sz;
  struct ibv_wq_init_attr wqia = {
    .wq_type = IBV_WQT_RQ,
    .max_wr = rxq->size,
    .pd = rd->pd,
    .cq = iq->ibv_cq,
  };
  struct ibv_wq_attr wqa = {
    .attr_mask = IBV_WQ_ATTR_STATE,
    .wq_state = IBV_WQS_RDY,
  };
  int rv_ibv;

  n_ds = clib_clamp (n_ds, 1, clib_min (IBV_RXQ_MAX_CHAIN_SZ, rd->max_sge));
  iq->n_ds = n_ds;
  iq->single_buffer = n_ds == 1;
  wqia.max_sge = n_ds;

  for (u32 i = 0; i < IBV_RX_REFILL_BATCH_SZ; i++)
    {
      ibv_rx_refill_entry_t *re = iq->refill_entries + i;

      re->recv_wr = (struct ibv_recv_wr) {
	.next = i + 1 < IBV_RX_REFILL_BATCH_SZ ? &re[1].recv_wr : 0,
	.sg_list = re->sge,
	.num_sge = n_ds,
      };
      for (u32 j = 0; j < n_ds; j++)
	re->sge[j] = (struct ibv_sge) {
	  .length = iq->buf_sz,
	  .lkey = rd->lkey,
	};
    }

  for (u32 slot = 0; slot < rxq->size; slot++)
    iq->n_used[slot] = n_ds;
  iq->head = 0;
  iq->tail = 0;

  iq->ibv_wq = ibv_create_wq (rd->ctx, &wqia);
  if (iq->ibv_wq == 0)
    {
      log_err (dev, "rxq %u ibv_create_wq failed errno %d", rxq->queue_id, errno);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  rv_ibv = ibv_modify_wq (iq->ibv_wq, &wqa);
  if (rv_ibv)
    {
      log_err (dev, "rxq %u ibv_modify_wq rdy failed rv %d", rxq->queue_id, rv_ibv);
      ibv_rxq_wq_destroy (vm, rxq);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  return VNET_DEV_OK;
}

void
ibv_rxq_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  int rv_ibv;

  log_debug (dev, "ibv_rxq_free: queue %u", rxq->queue_id);

  ASSERT (rxq->started == 0);
  ibv_rxq_irq_disable (vm, rxq);
  if (iq->n_used)
    ibv_rxq_wq_destroy (vm, rxq);

  if (iq->ibv_cq)
    {
      rv_ibv = ibv_destroy_cq (iq->ibv_cq);
      if (rv_ibv)
	log_err (dev, "ibv_destroy_cq failed rv %d", rv_ibv);
      iq->ibv_cq = 0;
    }
  if (iq->irq.ibv_comp_ch)
    {
      rv_ibv = ibv_destroy_comp_channel (iq->irq.ibv_comp_ch);
      if (rv_ibv)
	log_err (dev, "ibv_destroy_comp_channel failed rv %d", rv_ibv);
      iq->irq.ibv_comp_ch = 0;
    }

  if (iq->buffers)
    clib_mem_free (iq->buffers);
  if (iq->n_used)
    clib_mem_free (iq->n_used);
  if (iq->refill_entries)
    clib_mem_free (iq->refill_entries);
  iq->buffers = 0;
  iq->n_used = 0;
  iq->refill_entries = 0;
}

vnet_dev_rv_t
ibv_rxq_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  ibv_dev_t *rd = vnet_dev_get_data (rxq->port->dev);
  ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  u32 n_bufs = rxq->size * IBV_RXQ_MAX_CHAIN_SZ;

  log_debug (dev, "ibv_rxq_alloc: queue %u", rxq->queue_id);

  iq->buf_sz = vnet_dev_get_rx_queue_buffer_data_size (vm, rxq);
  iq->buffers = clib_mem_alloc_aligned (sizeof (u32) * n_bufs, CLIB_CACHE_LINE_BYTES);
  iq->n_used = clib_mem_alloc_aligned (rxq->size, CLIB_CACHE_LINE_BYTES);
  iq->refill_entries = clib_mem_alloc_aligned (
    sizeof (iq->refill_entries[0]) * IBV_RX_REFILL_BATCH_SZ, CLIB_CACHE_LINE_BYTES);
  clib_memset (iq->n_used, IBV_RXQ_MAX_CHAIN_SZ, rxq->size);

  iq->irq.ibv_comp_ch = ibv_create_comp_channel (rd->ctx);
  if (iq->irq.ibv_comp_ch)
    {
      int flags = fcntl (iq->irq.ibv_comp_ch->fd, F_GETFL, 0);
      if (flags < 0 || fcntl (iq->irq.ibv_comp_ch->fd, F_SETFL, flags | O_NONBLOCK) < 0)
	{
	  log_warn (dev, "rxq %u completion channel setup failed, polling mode", rxq->queue_id);
	  ibv_destroy_comp_channel (iq->irq.ibv_comp_ch);
	  iq->irq.ibv_comp_ch = 0;
	}
    }
  else
    log_warn (dev, "rxq %u completion channel unavailable, polling mode", rxq->queue_id);

  iq->ibv_cq = ibv_create_cq (rd->ctx, rxq->size, 0, iq->irq.ibv_comp_ch, 0);
  if (iq->ibv_cq == 0)
    {
      log_err (dev, "ibv_create_cq failed errno %d", errno);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  iq->irq = (rdma_rxq_irq_t) {
    .rxq = rxq,
    .ibv_cq = iq->ibv_cq,
    .ibv_comp_ch = iq->irq.ibv_comp_ch,
    .driver_name = (u8 *) "ibverbs",
  };

  return VNET_DEV_OK;
}

void
ibv_txq_recover (vlib_main_t *vm, vnet_dev_tx_queue_t *txq, int status)
{
  vnet_dev_t *dev = txq->port->dev;
  ibv_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  struct ibv_wc wc[VLIB_FRAME_SIZE];
  u32 n = tq->tail - tq->head;
  int rv_ibv;

  log_err (dev, "txq %u completion error status %d, resetting queue", txq->queue_id, status);

  rdma_qp_stop (tq->ibv_qp);
  while (ibv_poll_cq (tq->ibv_cq, ARRAY_LEN (wc), wc) > 0)
    ;
  if (n)
    vlib_buffer_free_from_ring (vm, tq->buffers, tq->head & (txq->size - 1), txq->size, n);
  tq->head = 0;
  tq->tail = 0;

  rv_ibv = rdma_qp_start (tq->ibv_qp, txq->port->port_id, 0);
  if (rv_ibv)
    log_err (dev, "txq %u restart failed rv %d", txq->queue_id, rv_ibv);
}

void
ibv_txq_free (vlib_main_t *vm __clib_unused, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  ibv_txq_t *tq;

  log_debug (dev, "ibv_txq_free: queue %u", txq->queue_id);

  ASSERT (txq->started == 0);
  tq = vnet_dev_get_tx_queue_data (txq);

  if (tq->ibv_qp)
    {
      int rv_ibv = ibv_destroy_qp (tq->ibv_qp);
      if (rv_ibv)
	log_err (dev, "ibv_destroy_qp failed rv %d", rv_ibv);
      tq->ibv_qp = 0;
    }

  if (tq->ibv_cq)
    {
      int rv_ibv = ibv_destroy_cq (tq->ibv_cq);
      if (rv_ibv)
	log_err (dev, "ibv_destroy_cq failed rv %d", rv_ibv);
      tq->ibv_cq = 0;
    }

  if (tq->buffers)
    {
      clib_mem_free (tq->buffers);
      tq->buffers = 0;
    }
  if (tq->wr_template)
    {
      clib_mem_free (tq->wr_template);
      tq->wr_template = 0;
    }
  if (tq->sge_template)
    {
      clib_mem_free (tq->sge_template);
      tq->sge_template = 0;
    }

  tq->head = 0;
  tq->tail = 0;
}

vnet_dev_rv_t
ibv_txq_alloc (vlib_main_t *vm __clib_unused, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  ibv_dev_t *rd = vnet_dev_get_data (txq->port->dev);

  ibv_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  u8 ibv_port = txq->port->port_id;
  int rv_ibv;
  vnet_dev_rv_t rv = VNET_DEV_OK;
  u32 sz;

  log_debug (dev, "ibv_txq_alloc: queue %u", txq->queue_id);

  ASSERT (tq->buffers == 0);
  ASSERT (tq->wr_template == 0);
  ASSERT (tq->sge_template == 0);
  tq->head = 0;
  tq->tail = 0;

  sz = sizeof (tq->buffers[0]) * txq->size;
  tq->buffers = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
  if (tq->buffers == 0)
    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;

  sz = sizeof (tq->wr_template[0]) * VLIB_FRAME_SIZE;
  tq->wr_template = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
  if (tq->wr_template == 0)
    {
      rv = VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
      goto err;
    }

  sz = sizeof (tq->sge_template[0]) * VLIB_FRAME_SIZE * IBV_TXQ_MAX_SGE;
  tq->sge_template = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
  if (tq->sge_template == 0)
    {
      rv = VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
      goto err;
    }

  for (u32 i = 0; i < VLIB_FRAME_SIZE; i++)
    {
      tq->wr_template[i].next = (i + 1 < VLIB_FRAME_SIZE) ? &tq->wr_template[i + 1] : 0;
      tq->wr_template[i].sg_list = &tq->sge_template[i * IBV_TXQ_MAX_SGE];
      tq->wr_template[i].num_sge = 1;
      tq->wr_template[i].opcode = IBV_WR_SEND;
      for (u32 j = 0; j < IBV_TXQ_MAX_SGE; j++)
	tq->sge_template[i * IBV_TXQ_MAX_SGE + j].lkey = rd->lkey;
    }

  tq->ibv_cq = ibv_create_cq (rd->ctx, txq->size, 0, 0, 0);
  if (tq->ibv_cq == 0)
    {
      log_err (dev, "ibv_create_cq failed");
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }

  {
    struct ibv_qp_init_attr_ex qpia = {
      .send_cq = tq->ibv_cq,
      .recv_cq = tq->ibv_cq,
      .cap = {
	.max_send_wr = txq->size,
	.max_send_sge = rd->tx_max_sge,
      },
      .qp_type = IBV_QPT_RAW_PACKET,
      .comp_mask = IBV_QP_INIT_ATTR_PD,
      .pd = rd->pd,
    };

    if (rd->tx_tso)
      {
	qpia.comp_mask |= IBV_QP_INIT_ATTR_MAX_TSO_HEADER;
	qpia.max_tso_header = IBV_TSO_MAX_HDR_SZ;
      }

    tq->ibv_qp = ibv_create_qp_ex (rd->ctx, &qpia);
    if (tq->ibv_qp == 0)
      {
	log_err (dev, "ibv_create_qp_ex failed errno %d", errno);
	rv = VNET_DEV_ERR_INIT_FAILED;
	goto err;
      }
    tq->max_sge = clib_min (qpia.cap.max_send_sge, IBV_TXQ_MAX_SGE);
  }

  rv_ibv = ibv_modify_qp (tq->ibv_qp,
			  &(struct ibv_qp_attr) {
			    .qp_state = IBV_QPS_INIT,
			    .port_num = ibv_port,
			  },
			  IBV_QP_STATE | IBV_QP_PORT);
  if (rv_ibv)
    {
      log_err (dev, "ibv_modify_qp init failed rv %d", rv_ibv);
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }

  rv_ibv = ibv_modify_qp (tq->ibv_qp,
			  &(struct ibv_qp_attr) {
			    .qp_state = IBV_QPS_RTR,
			  },
			  IBV_QP_STATE);
  if (rv_ibv)
    {
      log_err (dev, "ibv_modify_qp rtr failed rv %d", rv_ibv);
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }

  rv_ibv = ibv_modify_qp (tq->ibv_qp,
			  &(struct ibv_qp_attr) {
			    .qp_state = IBV_QPS_RTS,
			  },
			  IBV_QP_STATE);
  if (rv_ibv)
    {
      log_err (dev, "ibv_modify_qp rts failed rv %d", rv_ibv);
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }

  return VNET_DEV_OK;

err:
  return rv;
}
