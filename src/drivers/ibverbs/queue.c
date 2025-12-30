/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <ibverbs.h>

VLIB_REGISTER_LOG_CLASS (ibv_log, static) = {
  .class_name = "ibverbs",
  .subclass_name = "queue",
};

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

  if (iq->n_used_per_chain)
    clib_mem_free (iq->n_used_per_chain);

  if (iq->ibv_qp)
    {
      int rv_ibv = ibv_destroy_qp (iq->ibv_qp);
      if (rv_ibv)
	log_err (dev, "ibv_destroy_qp failed rv %d", rv_ibv);
      else
	log_debug (dev, "ibv_destroy_qp ok");
    }

  if (iq->ibv_cq)
    {
      int rv_ibv = ibv_destroy_cq (iq->ibv_cq);
      if (rv_ibv)
	log_err (dev, "ibv_destroy_cq failed rv %d", rv_ibv);
      else
	log_debug (dev, "ibv_destroy_cq ok");
    }

  if (iq->buffers)
    {
      u32 n = iq->tail - iq->head;
      if (n)
	{
	  u32 mask = rxq->size - 1;
	  if (iq->n_ds_per_wqe > 1 && iq->second_bufs)
	    {
	      u32 n_tail = iq->n_ds_per_wqe - 1;
	      u32 slot = iq->head & mask;
	      u32 left = n;
	      while (left)
		{
		  u32 n_now = clib_min (left, rxq->size - slot);
		  for (u32 i = 0; i < n_now; i++)
		    {
		      u8 extras_alloc = iq->n_used_per_chain[slot + i];
		      u32 base = (slot + i) * n_tail;

		      if (extras_alloc)
			vlib_buffer_free (vm, iq->second_bufs + base,
					  extras_alloc);
		    }
		  left -= n_now;
		  slot = 0;
		}
	    }
	  vlib_buffer_free_from_ring (vm, iq->buffers, iq->head & mask,
				      rxq->size, n);
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
  u32 n_tail = iq->n_ds_per_wqe - 1;
  u32 max_chain_sz = (rxq->port->max_rx_frame_size / buf_sz) + 1;
  u8 ibv_port = (u8) rxq->port->port_id;
  int rv_ibv;

  log_debug (dev, "ibv_rxq_alloc: queue %u", rxq->queue_id);

  if (max_chain_sz == 0)
    max_chain_sz = 1;
  if (rd->max_sge && max_chain_sz > rd->max_sge)
    max_chain_sz = rd->max_sge;
  max_chain_sz = clib_min (max_chain_sz, (u32) RDMA_IBV_RXQ_MAX_CHAIN_SZ);
  if (max_chain_sz == 0)
    max_chain_sz = 1;
  iq->buf_sz = buf_sz;
  iq->n_ds_per_wqe = (u8) max_chain_sz;

  ASSERT (iq->buffers == 0);
  {
    u32 sz;

    sz = sizeof (iq->buffers[0]) * rxq->size;
    iq->buffers = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
    if (iq->buffers == 0)
      return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
    clib_memset (iq->buffers, 0, sz);
  }

  ASSERT (iq->refill_entries == 0);
  {
    ibv_rx_refill_entry_t *re;
    u32 n_wr;
    u32 i;
    u32 j;
    u32 sz;

    n_wr = 1u << RDMA_IBV_RX_REFILL_LOG2_BATCH_SZ;
    sz = sizeof (iq->refill_entries[0]) * n_wr;
    iq->refill_entries = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
    if (iq->refill_entries == 0)
      {
	rv = VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
	goto err;
      }

    re = iq->refill_entries;
    for (i = 0; i < n_wr; i++)
      {
	re[i] = (ibv_rx_refill_entry_t){
	  .recv_wr = {
	    .next = (i + 1 < n_wr) ? &re[i + 1].recv_wr : 0,
	    .sg_list = re[i].sge,
	    .num_sge = iq->n_ds_per_wqe,
	  },
	};
	for (j = 0; j < iq->n_ds_per_wqe; j++)
	  re[i].sge[j].length = buf_sz;
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
      clib_memset (iq->second_bufs, 0, sz);

      sz = sizeof (iq->n_used_per_chain[0]) * rxq->size;
      iq->n_used_per_chain =
	clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
      if (iq->n_used_per_chain == 0)
	{
	  clib_mem_free (iq->second_bufs);
	  iq->second_bufs = 0;
	  rv = VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
	  goto err;
	}
      for (u32 i = 0; i < rxq->size; i++)
	iq->n_used_per_chain[i] = 0;
      iq->n_total_additional_segs = 0;
    }

  iq->ibv_cq = ibv_create_cq (rd->ctx, rxq->size, 0, 0, 0);
  if (iq->ibv_cq == 0)
    {
      log_err (dev, "ibv_create_cq failed");
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }
  log_debug (dev, "ibv_create_cq ok cqe %u", rxq->size);

  iq->ibv_qp = ibv_create_qp (
    rd->pd, &(struct ibv_qp_init_attr){
	     .send_cq = iq->ibv_cq,
	     .recv_cq = iq->ibv_cq,
	     .cap = {
	       .max_recv_wr = rxq->size,
	       .max_recv_sge = iq->n_ds_per_wqe,
	     },
	     .qp_type = IBV_QPT_RAW_PACKET,
	   });
  if (iq->ibv_qp == 0)
    {
      log_err (dev, "ibv_create_qp failed");
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
      int rv_ibv;

      rv_ibv = ibv_destroy_qp (tq->ibv_qp);
      if (rv_ibv)
	log_err (dev, "ibv_destroy_qp failed rv %d", rv_ibv);
      else
	log_debug (dev, "ibv_destroy_qp ok");
      tq->ibv_qp = 0;
    }

  if (tq->ibv_cq)
    {
      int rv_ibv;

      rv_ibv = ibv_destroy_cq (tq->ibv_cq);
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
  tq->head = 0;
  tq->tail = 0;

  sz = sizeof (tq->buffers[0]) * txq->size;
  tq->buffers = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
  if (tq->buffers == 0)
    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
  clib_memset (tq->buffers, 0, sz);

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
	       .max_send_sge = 1,
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
