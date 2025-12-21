/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <dev_rdma/common.h>
#include <dev_rdma/ibv/ibv.h>

void
rdma_ibv_rxq_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  rdma_ibv_rxq_t *iq;
  u32 n;
  u32 mask;

  ASSERT (rxq->started == 0);
  iq = vnet_dev_get_rx_queue_data (rxq);

  if (iq->refill_entries)
    {
      clib_mem_free (iq->refill_entries);
      iq->refill_entries = 0;
    }

  if (iq->ibv_qp)
    {
      ibv_destroy_qp (iq->ibv_qp);
      iq->ibv_qp = 0;
    }

  if (iq->ibv_cq)
    {
      ibv_destroy_cq (iq->ibv_cq);
      iq->ibv_cq = 0;
    }

  if (iq->buffers)
    {
      n = iq->tail - iq->head;
      if (n)
	{
	  mask = rxq->size - 1;
	  vlib_buffer_free_from_ring (vm, iq->buffers, iq->head & mask,
				      rxq->size, n);
	}
      clib_mem_free (iq->buffers);
      iq->buffers = 0;
    }

  iq->head = 0;
  iq->tail = 0;
}

vnet_dev_rv_t
rdma_ibv_rxq_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  rdma_dev_t *rd;
  rdma_ibv_rxq_t *iq;
  struct ibv_qp_init_attr qpia = {};
  struct ibv_qp_attr qpa_init = {};
  struct ibv_qp_attr qpa_rtr = {};
  struct ibv_qp_attr qpa_rts = {};
  vnet_dev_rv_t rv = VNET_DEV_OK;
  rdma_ibv_rx_refill_entry_t *re;
  u32 sz;
  u32 n_wr;
  u32 i;
  u32 data_size;
  u8 ibv_port;

  rd = vnet_dev_get_data (rxq->port->dev);
  iq = vnet_dev_get_rx_queue_data (rxq);

  if (rd->pd == 0)
    {
      rd->pd = ibv_alloc_pd (rd->ctx);
      if (rd->pd == 0)
	return VNET_DEV_ERR_INIT_FAILED;
    }

  ASSERT (iq->buffers == 0);
  sz = sizeof (iq->buffers[0]) * rxq->size;
  iq->buffers = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
  if (iq->buffers == 0)
    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
  clib_memset (iq->buffers, 0, sz);

  ASSERT (iq->refill_entries == 0);
  n_wr = 1u << RDMA_IBV_RX_REFILL_LOG2_BATCH_SZ;
  sz = sizeof (iq->refill_entries[0]) * n_wr;
  iq->refill_entries = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
  if (iq->refill_entries == 0)
    {
      rv = VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
      goto err;
    }

  data_size = vnet_dev_get_rx_queue_buffer_data_size (vm, rxq);
  re = iq->refill_entries;
  for (i = 0; i < n_wr; i++)
    {
      re[i] = (rdma_ibv_rx_refill_entry_t){
	.sge = {
	  .length = data_size,
	},
	.recv_wr = {
	  .next = (i + 1 < n_wr) ? &re[i + 1].recv_wr : 0,
	  .sg_list = &re[i].sge,
	  .num_sge = 1,
	},
      };
    }

  iq->ibv_cq = ibv_create_cq (rd->ctx, rxq->size, 0, 0, 0);
  if (iq->ibv_cq == 0)
    {
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }

  qpia.send_cq = iq->ibv_cq;
  qpia.recv_cq = iq->ibv_cq;
  qpia.cap.max_recv_wr = rxq->size;
  qpia.cap.max_recv_sge = 1;
  qpia.cap.max_send_wr = 0;
  qpia.cap.max_send_sge = 0;
  qpia.qp_type = IBV_QPT_RAW_PACKET;

  iq->ibv_qp = ibv_create_qp (rd->pd, &qpia);
  if (iq->ibv_qp == 0)
    {
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }

  ibv_port = (u8) rxq->port->port_id;
  qpa_init.qp_state = IBV_QPS_INIT;
  qpa_init.port_num = ibv_port;
  if (ibv_modify_qp (iq->ibv_qp, &qpa_init, IBV_QP_STATE | IBV_QP_PORT))
    {
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }

  qpa_rtr.qp_state = IBV_QPS_RTR;
  if (ibv_modify_qp (iq->ibv_qp, &qpa_rtr, IBV_QP_STATE))
    {
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }

  qpa_rts.qp_state = IBV_QPS_RTS;
  if (ibv_modify_qp (iq->ibv_qp, &qpa_rts, IBV_QP_STATE))
    {
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }

  return rv;

err:
  rdma_ibv_rxq_free (vm, rxq);
  return rv;
}

void
rdma_ibv_txq_free (vlib_main_t *vm __clib_unused, vnet_dev_tx_queue_t *txq)
{
  rdma_ibv_txq_t *tq;

  ASSERT (txq->started == 0);
  tq = vnet_dev_get_tx_queue_data (txq);

  if (tq->ibv_qp)
    {
      ibv_destroy_qp (tq->ibv_qp);
      tq->ibv_qp = 0;
    }

  if (tq->ibv_cq)
    {
      ibv_destroy_cq (tq->ibv_cq);
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
rdma_ibv_txq_alloc (vlib_main_t *vm __clib_unused, vnet_dev_tx_queue_t *txq)
{
  rdma_dev_t *rd;
  rdma_ibv_txq_t *tq;
  vnet_dev_rv_t rv = VNET_DEV_OK;
  struct ibv_qp_init_attr qpia = {};
  struct ibv_qp_attr qpa_init = {};
  struct ibv_qp_attr qpa_rtr = {};
  struct ibv_qp_attr qpa_rts = {};
  u32 sz;
  u8 ibv_port;

  rd = vnet_dev_get_data (txq->port->dev);
  tq = vnet_dev_get_tx_queue_data (txq);
  ASSERT (tq->buffers == 0);
  tq->head = 0;
  tq->tail = 0;

  if (rd->pd == 0)
    {
      rd->pd = ibv_alloc_pd (rd->ctx);
      if (rd->pd == 0)
	return VNET_DEV_ERR_INIT_FAILED;
    }

  sz = sizeof (tq->buffers[0]) * txq->size;
  tq->buffers = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
  if (tq->buffers == 0)
    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
  clib_memset (tq->buffers, 0, sz);

  tq->ibv_cq = ibv_create_cq (rd->ctx, txq->size, 0, 0, 0);
  if (tq->ibv_cq == 0)
    {
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }

  qpia.send_cq = tq->ibv_cq;
  qpia.recv_cq = tq->ibv_cq;
  qpia.cap.max_send_wr = txq->size;
  qpia.cap.max_send_sge = 1;
  qpia.qp_type = IBV_QPT_RAW_PACKET;

  tq->ibv_qp = ibv_create_qp (rd->pd, &qpia);
  if (tq->ibv_qp == 0)
    {
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }

  ibv_port = (u8) txq->port->port_id;
  qpa_init.qp_state = IBV_QPS_INIT;
  qpa_init.port_num = ibv_port;
  if (ibv_modify_qp (tq->ibv_qp, &qpa_init, IBV_QP_STATE | IBV_QP_PORT))
    {
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }

  qpa_rtr.qp_state = IBV_QPS_RTR;
  if (ibv_modify_qp (tq->ibv_qp, &qpa_rtr, IBV_QP_STATE))
    {
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }

  qpa_rts.qp_state = IBV_QPS_RTS;
  if (ibv_modify_qp (tq->ibv_qp, &qpa_rts, IBV_QP_STATE))
    {
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }

  return VNET_DEV_OK;

err:
  rdma_ibv_txq_free (vm, txq);
  return rv;
}
