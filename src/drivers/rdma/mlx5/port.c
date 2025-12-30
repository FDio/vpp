/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <common.h>
#include <mlx5.h>
#include <common/common.h>
#include <errno.h>

static u8 mlx5_rss_hash_key[] = {
  0x2c, 0xc6, 0x81, 0xd1, 0x5b, 0xdb, 0xf4, 0xf7, 0xfc, 0xa2, 0x83, 0x19, 0xdb, 0x1a,
  0x3e, 0x94, 0x6b, 0x9e, 0x38, 0xd9, 0x2c, 0x9c, 0x03, 0xd1, 0xad, 0x99, 0x44, 0xa7,
  0xd9, 0x56, 0x3d, 0x59, 0x06, 0x3c, 0x25, 0xf3, 0xfc, 0x1f, 0xdc, 0x2a,
};

VLIB_REGISTER_LOG_CLASS (mlx5_log, static) = {
  .class_name = "mlx5",
  .subclass_name = "port",
};

vnet_dev_rv_t
mlx5_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  return mlx5_port_init_counters (vm, port);
}

static void
mlx5_port_collect_addrs (vnet_dev_port_t *port, vnet_dev_port_cfg_change_req_t *req,
			 vnet_dev_hw_addr_t **addrs)
{
  rdma_port_collect_addrs (port, req, addrs);
}

static void
mlx5_port_rss_disable (vnet_dev_port_t *port)
{
  mlx5_port_t *mp = vnet_dev_get_port_data (port);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
      mq->use_rss = 0;
    }

  rdma_rxq_destroy_flows (&mp->flows);
  vec_free (mp->ucast_flows);
  mp->ucast_flows = 0;
  mp->promisc_flow_index = RDMA_RX_FLOW_INDEX_INVALID;
  mp->mcast_flow_index = RDMA_RX_FLOW_INDEX_INVALID;
  if (mp->rss_qp)
    {
      ibv_destroy_qp (mp->rss_qp);
      mp->rss_qp = 0;
    }
  if (mp->rwq_ind_tbl)
    {
      ibv_destroy_rwq_ind_table (mp->rwq_ind_tbl);
      mp->rwq_ind_tbl = 0;
    }
  mp->rss_enabled = 0;
}

static vnet_dev_rv_t
mlx5_port_rss_enable (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  mlx5_dev_t *rd = vnet_dev_get_data (dev);
  mlx5_port_t *mp = vnet_dev_get_port_data (port);
  struct ibv_wq **wqs = 0;
  struct ibv_wq **ind_tbl = 0;
  struct ibv_rwq_ind_table_init_attr rwqia = {};
  struct ibv_qp_init_attr_ex qpia = {};
  u64 rx_hash_fields = 0;
  u32 n_rxq = 0;
  u32 n_ind;
  u32 max_ind;
  u32 i;

  if (rd->rss == 0 || mp->striding_rq == 0)
    return VNET_DEV_OK;

  mlx5_port_rss_disable (port);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
      if (mq->ibv_wq == 0)
	return VNET_DEV_OK;
      vec_add1 (wqs, mq->ibv_wq);
    }

  n_rxq = vec_len (wqs);
  if (n_rxq < 2)
    goto done;

  max_ind = rd->rss_max_ind_tbl_size;
  n_ind = 1u << max_log2 (n_rxq);
  if (n_ind > max_ind)
    n_ind = 1u << min_log2 (max_ind);
  if (n_ind < 2)
    goto done;

  vec_validate (ind_tbl, n_ind - 1);
  for (i = 0; i < n_ind; i++)
    ind_tbl[i] = wqs[i % n_rxq];

  rwqia.log_ind_tbl_size = min_log2 (n_ind);
  rwqia.ind_tbl = ind_tbl;
  mp->rwq_ind_tbl = ibv_create_rwq_ind_table (rd->ctx, &rwqia);
  if (mp->rwq_ind_tbl == 0)
    {
      log_err (dev, "ibv_create_rwq_ind_table failed");
      vec_free (ind_tbl);
      vec_free (wqs);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  qpia.qp_type = IBV_QPT_RAW_PACKET;
  qpia.comp_mask = IBV_QP_INIT_ATTR_PD | IBV_QP_INIT_ATTR_IND_TABLE | IBV_QP_INIT_ATTR_RX_HASH;
  qpia.pd = rd->pd;
  qpia.rwq_ind_tbl = mp->rwq_ind_tbl;
  if (!(rd->rss_hash_function & IBV_RX_HASH_FUNC_TOEPLITZ))
    {
      log_err (dev, "toeplitz hash function is not supported");
      mlx5_port_rss_disable (port);
      vec_free (ind_tbl);
      vec_free (wqs);
      return VNET_DEV_ERR_UNSUPPORTED_DEVICE;
    }
  if ((rd->rss_hash_fields_mask & (IBV_RX_HASH_SRC_IPV4 | IBV_RX_HASH_DST_IPV4)) ==
      (IBV_RX_HASH_SRC_IPV4 | IBV_RX_HASH_DST_IPV4))
    rx_hash_fields = IBV_RX_HASH_SRC_IPV4 | IBV_RX_HASH_DST_IPV4;
  else if ((rd->rss_hash_fields_mask & (IBV_RX_HASH_SRC_IPV6 | IBV_RX_HASH_DST_IPV6)) ==
	   (IBV_RX_HASH_SRC_IPV6 | IBV_RX_HASH_DST_IPV6))
    rx_hash_fields = IBV_RX_HASH_SRC_IPV6 | IBV_RX_HASH_DST_IPV6;
  if (rx_hash_fields == 0)
    {
      log_err (dev, "cannot find a usable rx hash field profile");
      mlx5_port_rss_disable (port);
      vec_free (ind_tbl);
      vec_free (wqs);
      return VNET_DEV_ERR_UNSUPPORTED_DEVICE;
    }
  STATIC_ASSERT_SIZEOF (mlx5_rss_hash_key, 40);
  qpia.rx_hash_conf.rx_hash_key_len = sizeof (mlx5_rss_hash_key);
  qpia.rx_hash_conf.rx_hash_key = mlx5_rss_hash_key;
  qpia.rx_hash_conf.rx_hash_function = IBV_RX_HASH_FUNC_TOEPLITZ;
  qpia.rx_hash_conf.rx_hash_fields_mask = rx_hash_fields;
  mp->rss_qp = ibv_create_qp_ex (rd->ctx, &qpia);
  if (mp->rss_qp == 0)
    {
      log_err (dev, "ibv_create_qp_ex failed errno %d", errno);
      mlx5_port_rss_disable (port);
      vec_free (ind_tbl);
      vec_free (wqs);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
      rdma_rxq_destroy_flows (&mq->flows);
      vec_reset_length (mq->ucast_flows);
      mq->promisc_flow_index = RDMA_RX_FLOW_INDEX_INVALID;
      mq->mcast_flow_index = RDMA_RX_FLOW_INDEX_INVALID;
      mq->use_rss = 1;
    }
  mp->rss_enabled = 1;

done:
  vec_free (ind_tbl);
  vec_free (wqs);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
mlx5_port_program_flows (vnet_dev_port_t *port, vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_t *dev = port->dev;
  mlx5_port_t *mp = vnet_dev_get_port_data (port);
  vnet_dev_hw_addr_t *addrs = 0;
  vnet_dev_rv_t rv = VNET_DEV_OK;
  u8 promisc;
  u8 ibv_port;

  log_debug (dev, "mlx5_port_program_flows: port %u", port->port_id);

  promisc = port->promisc;
  if (req && req->type == VNET_DEV_PORT_CFG_PROMISC_MODE)
    promisc = req->promisc;

  if (promisc == 0)
    mlx5_port_collect_addrs (port, req, &addrs);

  ibv_port = (u8) port->port_id;
  if (mp->rss_enabled)
    {
      rv =
	rdma_program_flow_state (mp->rss_qp, &mp->flows, &mp->ucast_flows, &mp->promisc_flow_index,
				 &mp->mcast_flow_index, addrs, promisc, ibv_port);
      goto done;
    }

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      struct ibv_qp *qp;
      rdma_rx_flow_t ***flows;
      mlx5_rxq_t *mq;

      mq = vnet_dev_get_rx_queue_data (rxq);
      qp = mq->ibv_qp;
      flows = &mq->flows;
      rv = rdma_program_flow_state (qp, flows, &mq->ucast_flows, &mq->promisc_flow_index,
				    &mq->mcast_flow_index, addrs, promisc, ibv_port);
      if (rv != VNET_DEV_OK)
	goto done;
    }

done:
  vec_free (addrs);
  return rv;
}

vnet_dev_rv_t
mlx5_port_apply_flows (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;

  log_debug (dev, "mlx5_port_apply_flows: port %u", port->port_id);

  return mlx5_port_program_flows (port, 0);
}

static vnet_dev_rv_t
mlx5_qp_start (vnet_dev_t *dev, struct ibv_qp *qp, u8 ibv_port)
{
  rdma_qp_stage_t failed_stage;
  int rv_ibv;

  log_debug (dev, "mlx5_qp_start: port %u", ibv_port);

  rv_ibv = rdma_qp_start (qp, ibv_port, &failed_stage);
  if (rv_ibv)
    {
      if (failed_stage == RDMA_QP_STAGE_RESET)
	log_err (dev, "ibv_modify_qp reset failed rv %d", rv_ibv);
      else if (failed_stage == RDMA_QP_STAGE_INIT)
	log_err (dev, "ibv_modify_qp init failed rv %d", rv_ibv);
      else if (failed_stage == RDMA_QP_STAGE_RTR)
	log_err (dev, "ibv_modify_qp rtr failed rv %d", rv_ibv);
      else if (failed_stage == RDMA_QP_STAGE_RTS)
	log_err (dev, "ibv_modify_qp rts failed rv %d", rv_ibv);
      else
	log_err (dev, "mlx5_qp_start failed rv %d", rv_ibv);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  return VNET_DEV_OK;
}

static vnet_dev_rv_t
mlx5_port_cfg_rxq_int_mode_change (vlib_main_t *vm, vnet_dev_port_t *port, u16 qid, u8 enable,
				   u8 all)
{
  return rdma_port_cfg_rxq_intr_mode_change (vm, port, qid, enable, all, mlx5_rxq_irq_enable,
					     mlx5_rxq_irq_disable);
}

static void
mlx5_qp_stop (vnet_dev_t *dev, struct ibv_qp *qp)
{
  int rv_ibv;

  log_debug (dev, "mlx5_qp_stop");

  if (qp == 0)
    return;

  rv_ibv = rdma_qp_stop (qp);
  if (rv_ibv)
    log_err (dev, "ibv_modify_qp reset failed rv %d", rv_ibv);
  else
    log_debug (dev, "ibv_modify_qp reset ok");
}

vnet_dev_rv_t
mlx5_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  mlx5_port_t *mp = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv;
  u8 ibv_port;

  log_debug (dev, "mlx5_port_start: port %u", port->port_id);

  ibv_port = (u8) port->port_id;
  rv = mlx5_port_rss_enable (port);
  if (rv != VNET_DEV_OK)
    return rv;

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
      u32 i;

      if (!mp->striding_rq)
	{
	  u32 buf_sz = vnet_dev_get_rx_queue_buffer_data_size (vm, rxq);
	  u32 max_chain_sz = (port->max_rx_frame_size / buf_sz) + 1;
	  u32 max_ds = mq->n_ds_per_wqe;

	  if (max_chain_sz == 0)
	    max_chain_sz = 1;
	  max_chain_sz = clib_min (max_chain_sz, (u32) RDMA_RXQ_LEGACY_MODE_MAX_CHAIN_SZ);
	  if (max_chain_sz > max_ds)
	    max_chain_sz = max_ds;
	  mq->n_ds_per_wqe = (u8) max_chain_sz;
	  rv = mlx5_qp_start (dev, mq->ibv_qp, ibv_port);
	  if (rv != VNET_DEV_OK)
	    return rv;
	}
      if (rxq->interrupt_mode)
	{
	  rv = mlx5_rxq_irq_enable (vm, rxq);
	  if (rv != VNET_DEV_OK)
	    return rv;
	}
      mq->head = 0;
      mq->tail = 0;
      mq->striding_wqe_tail = 0;
      mq->dv_cq_idx = 0;
      mq->n_mini_cqes = 0;
      mq->n_mini_cqes_left = 0;
      if (mq->dv_cq_cqes)
	for (i = 0; i < mq->dv_cq_size; i++)
	  mq->dv_cq_cqes[i].op_own = 0xff;
      if (mq->dv_sq_dbrec)
	__atomic_store_n (&mq->dv_sq_dbrec[MLX5_RCV_DBR], 0, __ATOMIC_RELEASE);
      if (mq->dv_cq_dbrec)
	__atomic_store_n (&mq->dv_cq_dbrec[0], 0, __ATOMIC_RELEASE);
    }

  foreach_vnet_dev_port_tx_queue (txq, port)
    {
      mlx5_txq_t *tq;
      u32 i;

      tq = vnet_dev_get_tx_queue_data (txq);
      rv = mlx5_qp_start (dev, tq->ibv_qp, ibv_port);
      if (rv != VNET_DEV_OK)
	return rv;
      tq->head = 0;
      tq->tail = 0;
      tq->dv_cq_idx = 0;
      if (tq->dv_cq_cqes)
	for (i = 0; i < tq->dv_cq_size; i++)
	  tq->dv_cq_cqes[i].op_own = 0xff;
      if (tq->dv_sq_dbrec)
	__atomic_store_n (&tq->dv_sq_dbrec[MLX5_SND_DBR], 0, __ATOMIC_RELEASE);
      if (tq->dv_cq_dbrec)
	__atomic_store_n (&tq->dv_cq_dbrec[0], 0, __ATOMIC_RELEASE);
    }

  rv = mlx5_port_apply_flows (vm, port);
  if (rv != VNET_DEV_OK)
    return rv;

  vnet_dev_poll_port_add (vm, port, 1, mlx5_port_counter_poll);
  return VNET_DEV_OK;
}

void
mlx5_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  mlx5_port_t *mp = vnet_dev_get_port_data (port);

  log_debug (dev, "mlx5_port_stop: port %u", port->port_id);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      mlx5_rxq_t *mq;

      mq = vnet_dev_get_rx_queue_data (rxq);
      mlx5_rxq_irq_disable (vm, rxq);
      if (!mp->striding_rq)
	mlx5_qp_stop (dev, mq->ibv_qp);
      if (mq->buffers)
	{
	  u32 n;
	  u32 mask;

	  n = (u16) (mq->tail - mq->head);
	  if (n)
	    {
	      mask = rxq->size - 1;
	      if (mq->n_ds_per_wqe > 1 && mq->second_bufs && mq->n_used_per_chain)
		{
		  u32 extras_per = mq->n_ds_per_wqe - 1;
		  u32 slot = mq->head & mask;
		  u32 left = n;
		  u32 n_now;
		  u32 i;
		  u32 base;

		  while (left)
		    {
		      n_now = clib_min (left, rxq->size - slot);
		      for (i = 0; i < n_now; i++)
			{
			  u8 extras_alloc = mq->n_used_per_chain[slot + i];

			  base = (slot + i) * extras_per;
			  if (extras_alloc)
			    vlib_buffer_free (vm, mq->second_bufs + base, extras_alloc);
			  mq->n_used_per_chain[slot + i] = 0;
			}
		      left -= n_now;
		      slot = 0;
		    }
		  mq->n_total_additional_segs = 0;
		}
	      vlib_buffer_free_from_ring (vm, mq->buffers, mq->head & mask, rxq->size, n);
	    }
	}
      mq->head = 0;
      mq->tail = 0;
      mq->striding_wqe_tail = 0;
      mq->dv_cq_idx = 0;
      mq->use_rss = 0;
    }

  foreach_vnet_dev_port_tx_queue (txq, port)
    {
      mlx5_txq_t *tq;

      tq = vnet_dev_get_tx_queue_data (txq);
      mlx5_qp_stop (dev, tq->ibv_qp);
      if (tq->buffers)
	{
	  u32 n;
	  u32 mask;

	  n = (u16) (tq->tail - tq->head);
	  if (n)
	    {
	      mask = txq->size - 1;
	      vlib_buffer_free_from_ring (vm, tq->buffers, tq->head & mask, txq->size, n);
	    }
	}
      tq->head = 0;
      tq->tail = 0;
      tq->dv_cq_idx = 0;
    }

  vnet_dev_poll_port_remove (vm, port, mlx5_port_counter_poll);
  mlx5_port_rss_disable (port);
}

vnet_dev_rv_t
mlx5_port_cfg_change_validate (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port,
			       vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_t *dev = port->dev;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  log_debug (dev, "mlx5_port_cfg_change_validate: port %u type %u", port->port_id, req->type);

  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE:
      if (port->started)
	rv = VNET_DEV_ERR_PORT_STARTED;
      break;

    case VNET_DEV_PORT_CFG_PROMISC_MODE:
    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_ENABLE:
    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_DISABLE:
      break;

    default:
      rv = VNET_DEV_ERR_NOT_SUPPORTED;
    };

  return rv;
}

vnet_dev_rv_t
mlx5_port_cfg_change (vlib_main_t *vm, vnet_dev_port_t *port, vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_t *dev = port->dev;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  log_debug (dev, "mlx5_port_cfg_change: port %u type %u", port->port_id, req->type);

  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE:
      break;

    case VNET_DEV_PORT_CFG_PROMISC_MODE:
    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
      if (port->started)
	rv = mlx5_port_program_flows (port, req);
      break;

    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_ENABLE:
      rv = mlx5_port_cfg_rxq_int_mode_change (vm, port, req->queue_id, 1, req->all_queues);
      break;

    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_DISABLE:
      rv = mlx5_port_cfg_rxq_int_mode_change (vm, port, req->queue_id, 0, req->all_queues);
      break;

    default:
      rv = VNET_DEV_ERR_NOT_SUPPORTED;
    };

  return rv;
}
