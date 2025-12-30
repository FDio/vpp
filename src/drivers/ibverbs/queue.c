/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vlib/file.h>
#include <errno.h>
#include <fcntl.h>
#include <ibverbs.h>

VLIB_REGISTER_LOG_CLASS (ibv_log, static) = {
  .class_name = "ibverbs",
  .subclass_name = "queue",
};

static clib_error_t *
ibv_cq_fd_read_ready (clib_file_t *uf)
{
  vnet_dev_rx_queue_t *rxq = uword_to_pointer (uf->private_data, vnet_dev_rx_queue_t *);
  vnet_dev_t *dev = rxq->port->dev;
  ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  struct ibv_cq *cq;
  void *cq_ctx;
  vlib_main_t *vm = vlib_get_main_by_index (rxq->rx_thread_index);
  u32 n_events = 0;

  while (ibv_get_cq_event (iq->ibv_comp_ch, &cq, &cq_ctx) == 0)
    {
      int rv_ibv;

      ibv_ack_cq_events (cq, 1);
      rv_ibv = ibv_req_notify_cq (cq, 0);
      if (rv_ibv)
	log_err (dev, "ibv_req_notify_cq failed rv %d", rv_ibv);
      n_events++;
    }

  if (errno != EAGAIN && errno != EWOULDBLOCK)
    log_err (dev, "ibv_get_cq_event failed errno %d", errno);

  if (n_events)
    vlib_node_set_interrupt_pending (vm, vnet_dev_get_port_rx_node_index (rxq->port));

  return 0;
}

static clib_error_t *
ibv_cq_fd_error_ready (clib_file_t *uf)
{
  vnet_dev_rx_queue_t *rxq = uword_to_pointer (uf->private_data, vnet_dev_rx_queue_t *);
  vnet_dev_t *dev = rxq->port->dev;

  log_err (dev, "rxq %u completion channel fd error", rxq->queue_id);
  return 0;
}

vnet_dev_rv_t
ibv_rxq_irq_enable (vlib_main_t *vm __clib_unused, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  clib_file_t template = {};
  u32 idx;
  int rv_ibv;

  if (iq->cq_file_added)
    return VNET_DEV_OK;

  if (iq->ibv_comp_ch == 0)
    return VNET_DEV_OK;

  rv_ibv = ibv_req_notify_cq (iq->ibv_cq, 0);
  if (rv_ibv)
    {
      log_err (dev, "ibv_req_notify_cq failed rv %d", rv_ibv);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  template.file_descriptor = iq->ibv_comp_ch->fd;
  template.read_function = ibv_cq_fd_read_ready;
  template.error_function = ibv_cq_fd_error_ready;
  template.private_data = pointer_to_uword (rxq);
  template.dont_close = 1;
  template.description =
    format (0, "ibverbs-rx-cqfd-%U-q%u%c", format_vnet_dev_addr, dev, rxq->queue_id, 0);
  idx = clib_file_add (&file_main, &template);
  clib_file_set_polling_thread (&file_main, idx, rxq->rx_thread_index);
  iq->cq_clib_file_index = idx;
  iq->cq_file_added = 1;
  return VNET_DEV_OK;
}

void
ibv_rxq_irq_disable (vlib_main_t *vm __clib_unused, vnet_dev_rx_queue_t *rxq)
{
  ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);

  if (iq->cq_file_added == 0)
    return;

  clib_file_del_by_index (&file_main, iq->cq_clib_file_index);
  iq->cq_file_added = 0;
  iq->cq_clib_file_index = 0;
}

void
ibv_rxq_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  struct ibv_flow **f;

  log_debug (dev, "ibv_rxq_free: queue %u", rxq->queue_id);

  ASSERT (rxq->started == 0);

  if (iq->flows)
    {
      vec_foreach (f, iq->flows)
	if (f[0])
	  {
	    int rv_ibv = ibv_destroy_flow (f[0]);
	    if (rv_ibv)
	      log_err (dev, "ibv_destroy_flow failed rv %d", rv_ibv);
	    else
	      log_debug (dev, "ibv_destroy_flow ok");
	  }
      vec_free (iq->flows);
      iq->flows = 0;
    }

  if (iq->refill_entries)
    clib_mem_free (iq->refill_entries);

  if (iq->second_bufs)
    clib_mem_free (iq->second_bufs);

  if (iq->n_tail_refills)
    clib_mem_free (iq->n_tail_refills);

  if (iq->ibv_qp)
    {
      int rv_ibv = ibv_destroy_qp (iq->ibv_qp);
      if (rv_ibv)
	log_err (dev, "ibv_destroy_qp failed rv %d", rv_ibv);
      else
	log_debug (dev, "ibv_destroy_qp ok");
    }

  ibv_rxq_irq_disable (vm, rxq);

  if (iq->ibv_cq)
    {
      int rv_ibv = ibv_destroy_cq (iq->ibv_cq);
      if (rv_ibv)
	log_err (dev, "ibv_destroy_cq failed rv %d", rv_ibv);
      else
	log_debug (dev, "ibv_destroy_cq ok");
    }
  if (iq->ibv_comp_ch)
    {
      int rv_ibv = ibv_destroy_comp_channel (iq->ibv_comp_ch);
      if (rv_ibv)
	log_err (dev, "ibv_destroy_comp_channel failed rv %d", rv_ibv);
      else
	log_debug (dev, "ibv_destroy_comp_channel ok");
      iq->ibv_comp_ch = 0;
    }

  if (iq->buffers)
    {
      u32 n = iq->tail - iq->head;
      if (n)
	{
	  u32 mask = rxq->size - 1;
	  if (iq->n_ds_per_wqe > 1 && iq->second_bufs)
	    {
	      u32 n_tail = iq->max_tails;
	      u32 slot = iq->head & mask;
	      u32 left = n;
	      while (left)
		{
		  u32 n_now = clib_min (left, rxq->size - slot);
		  for (u32 i = 0; i < n_now; i++)
		    {
		      u32 base = (slot + i) * n_tail;
		      vlib_buffer_free (vm, iq->second_bufs + base, n_tail);
		    }
		  left -= n_now;
		  slot = 0;
		}
	    }
	  vlib_buffer_free_from_ring (vm, iq->buffers, iq->head & mask, rxq->size, n);
	}
      clib_mem_free (iq->buffers);
    }
}

vnet_dev_rv_t
ibv_rxq_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  ibv_dev_t *rd = vnet_dev_get_data (rxq->port->dev);
  ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_rv_t rv = VNET_DEV_OK;
  u32 buf_sz = vnet_dev_get_rx_queue_buffer_data_size (vm, rxq);
  u32 n_tail;
  u32 max_chain_sz = (rxq->port->max_rx_frame_size + buf_sz - 1) / buf_sz;
  u8 ibv_port = (u8) rxq->port->port_id;
  int rv_ibv;

  log_debug (dev, "ibv_rxq_alloc: queue %u", rxq->queue_id);

  if (max_chain_sz == 0)
    max_chain_sz = 1;
  if (rd->max_sge && max_chain_sz > rd->max_sge)
    max_chain_sz = rd->max_sge;
  max_chain_sz = clib_min (max_chain_sz, (u32) IBV_RXQ_MAX_CHAIN_SZ);
  if (max_chain_sz == 0)
    max_chain_sz = 1;
  iq->buf_sz = buf_sz;
  iq->n_ds_per_wqe = (u8) max_chain_sz;
  iq->n_ds_per_wqe_max = (u8) max_chain_sz;
  n_tail = iq->n_ds_per_wqe - 1;
  iq->max_tails = (u8) n_tail;
  iq->n_left_to_post = 0;

  ASSERT (iq->buffers == 0);
  {
    u32 sz = sizeof (iq->buffers[0]) * rxq->size;
    iq->buffers = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
    if (iq->buffers == 0)
      return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
  }

  ASSERT (iq->refill_entries == 0);
  {
    ibv_rx_refill_entry_t *re;
    u32 n_wr = 1u << IBV_RX_REFILL_LOG2_BATCH_SZ;
    u32 sz = sizeof (iq->refill_entries[0]) * n_wr;

    iq->refill_entries = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
    if (iq->refill_entries == 0)
      {
	rv = VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
	goto err;
      }

    re = iq->refill_entries;
    for (u32 i = 0; i < n_wr; i++)
      {
	re[i] = (ibv_rx_refill_entry_t){
	  .recv_wr = {
	    .next = (i + 1 < n_wr) ? &re[i + 1].recv_wr : 0,
	    .sg_list = re[i].sge,
	    .num_sge = iq->n_ds_per_wqe,
	  },
	};
	for (u32 j = 0; j < iq->n_ds_per_wqe; j++)
	  {
	    u32 off = j * buf_sz;
	    re[i].sge[j].length = clib_min (buf_sz, rxq->port->max_rx_frame_size - off);
	    re[i].sge[j].lkey = rd->lkey;
	  }
      }
  }

  if (iq->n_ds_per_wqe > 1)
    {
      u32 sz = sizeof (iq->second_bufs[0]) * rxq->size * n_tail;
      iq->second_bufs = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
      if (iq->second_bufs == 0)
	{
	  rv = VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
	  goto err;
	}

      sz = sizeof (iq->n_tail_refills[0]) * rxq->size;
      iq->n_tail_refills = clib_mem_alloc_aligned (sz, 64);
      if (iq->n_tail_refills == 0)
	{
	  clib_mem_free (iq->second_bufs);
	  iq->second_bufs = 0;
	  rv = VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
	  goto err;
	}
      for (u32 i = 0; i < rxq->size; i++)
	iq->n_tail_refills[i] = n_tail;
    }

  iq->ibv_comp_ch = ibv_create_comp_channel (rd->ctx);
  if (iq->ibv_comp_ch)
    {
      int flags = fcntl (iq->ibv_comp_ch->fd, F_GETFL, 0);
      if (flags < 0 || fcntl (iq->ibv_comp_ch->fd, F_SETFL, flags | O_NONBLOCK) < 0)
	{
	  log_warn (dev, "rxq %u completion channel setup failed, polling mode", rxq->queue_id);
	  rv_ibv = ibv_destroy_comp_channel (iq->ibv_comp_ch);
	  if (rv_ibv)
	    log_err (dev, "ibv_destroy_comp_channel failed rv %d", rv_ibv);
	  iq->ibv_comp_ch = 0;
	}
    }
  else
    log_warn (dev, "rxq %u completion channel unavailable, polling mode", rxq->queue_id);

  iq->ibv_cq = ibv_create_cq (rd->ctx, rxq->size, 0, iq->ibv_comp_ch, 0);
  if (iq->ibv_cq == 0)
    {
      log_err (dev, "ibv_create_cq failed");
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }
  log_debug (dev, "ibv_create_cq ok cqe %u", rxq->size);

  {
    struct ibv_qp_init_attr qpia = {
      .send_cq = iq->ibv_cq,
      .recv_cq = iq->ibv_cq,
      .cap = {
	.max_send_wr = 1,
	.max_send_sge = 1,
	.max_recv_wr = rxq->size,
	.max_recv_sge = iq->n_ds_per_wqe,
      },
      .qp_type = IBV_QPT_RAW_PACKET,
    };
    iq->ibv_qp = ibv_create_qp (rd->pd, &qpia);
    if (iq->ibv_qp == 0 && iq->n_ds_per_wqe > 1)
      {
	qpia.cap.max_recv_sge = 1;
	iq->ibv_qp = ibv_create_qp (rd->pd, &qpia);
	if (iq->ibv_qp)
	  {
	    iq->n_ds_per_wqe = 1;
	    iq->n_ds_per_wqe_max = 1;
	    iq->max_tails = 0;
	  }
      }
  }
  if (iq->ibv_qp == 0)
    {
      log_err (dev, "ibv_create_qp failed errno %d n_ds_per_wqe %u", errno, iq->n_ds_per_wqe);
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }
  log_debug (dev, "ibv_create_qp ok");

  rv_ibv = ibv_modify_qp (iq->ibv_qp,
			  &(struct ibv_qp_attr){
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
  log_debug (dev, "ibv_modify_qp init ok");

  rv_ibv = ibv_modify_qp (iq->ibv_qp,
			  &(struct ibv_qp_attr){
			    .qp_state = IBV_QPS_RTR,
			  },
			  IBV_QP_STATE);
  if (rv_ibv)
    {
      log_err (dev, "ibv_modify_qp rtr failed rv %d", rv_ibv);
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }
  log_debug (dev, "ibv_modify_qp rtr ok");

  rv_ibv = ibv_modify_qp (iq->ibv_qp,
			  &(struct ibv_qp_attr){
			    .qp_state = IBV_QPS_RTS,
			  },
			  IBV_QP_STATE);
  if (rv_ibv)
    {
      log_err (dev, "ibv_modify_qp rts failed rv %d", rv_ibv);
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }
  log_debug (dev, "ibv_modify_qp rts ok");

  return rv;

err:
  ibv_rxq_free (vm, rxq);
  return rv;
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
      else
	log_debug (dev, "ibv_destroy_qp ok");
      tq->ibv_qp = 0;
    }

  if (tq->ibv_cq)
    {
      int rv_ibv = ibv_destroy_cq (tq->ibv_cq);
      if (rv_ibv)
	log_err (dev, "ibv_destroy_cq failed rv %d", rv_ibv);
      else
	log_debug (dev, "ibv_destroy_cq ok");
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
  u8 ibv_port = (u8) txq->port->port_id;
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

  sz = sizeof (tq->sge_template[0]) * VLIB_FRAME_SIZE * IBV_TXQ_MAX_CHAIN_SZ;
  tq->sge_template = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
  if (tq->sge_template == 0)
    {
      rv = VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
      goto err;
    }

  for (u32 i = 0; i < VLIB_FRAME_SIZE; i++)
    {
      tq->wr_template[i].next = (i + 1 < VLIB_FRAME_SIZE) ? &tq->wr_template[i + 1] : 0;
      tq->wr_template[i].sg_list = &tq->sge_template[i * IBV_TXQ_MAX_CHAIN_SZ];
      tq->wr_template[i].num_sge = 1;
      tq->wr_template[i].opcode = IBV_WR_SEND;
      for (u32 j = 0; j < IBV_TXQ_MAX_CHAIN_SZ; j++)
	tq->sge_template[i * IBV_TXQ_MAX_CHAIN_SZ + j].lkey = rd->lkey;
    }

  tq->ibv_cq = ibv_create_cq (rd->ctx, txq->size, 0, 0, 0);
  if (tq->ibv_cq == 0)
    {
      log_err (dev, "ibv_create_cq failed");
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }
  log_debug (dev, "ibv_create_cq ok cqe %u", txq->size);

  tq->ibv_qp = ibv_create_qp (
    rd->pd, &(struct ibv_qp_init_attr){
	     .send_cq = tq->ibv_cq,
	     .recv_cq = tq->ibv_cq,
	     .cap = {
	       .max_send_wr = txq->size,
	       .max_send_sge = IBV_TXQ_MAX_CHAIN_SZ,
	     },
	     .qp_type = IBV_QPT_RAW_PACKET,
	   });
  if (tq->ibv_qp == 0)
    {
      log_err (dev, "ibv_create_qp failed");
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }
  log_debug (dev, "ibv_create_qp ok");

  rv_ibv = ibv_modify_qp (tq->ibv_qp,
			  &(struct ibv_qp_attr){
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
  log_debug (dev, "ibv_modify_qp init ok");

  rv_ibv = ibv_modify_qp (tq->ibv_qp,
			  &(struct ibv_qp_attr){
			    .qp_state = IBV_QPS_RTR,
			  },
			  IBV_QP_STATE);
  if (rv_ibv)
    {
      log_err (dev, "ibv_modify_qp rtr failed rv %d", rv_ibv);
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }
  log_debug (dev, "ibv_modify_qp rtr ok");

  rv_ibv = ibv_modify_qp (tq->ibv_qp,
			  &(struct ibv_qp_attr){
			    .qp_state = IBV_QPS_RTS,
			  },
			  IBV_QP_STATE);
  if (rv_ibv)
    {
      log_err (dev, "ibv_modify_qp rts failed rv %d", rv_ibv);
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }
  log_debug (dev, "ibv_modify_qp rts ok");

  return VNET_DEV_OK;

err:
  ibv_txq_free (vm, txq);
  return rv;
}
