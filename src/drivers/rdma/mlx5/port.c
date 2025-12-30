/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <common.h>
#include <mlx5.h>
#include <common/common.h>
#include <errno.h>

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
mlx5_port_rss_cleanup (vnet_dev_port_t *port)
{
  mlx5_port_t *mp = vnet_dev_get_port_data (port);
  vnet_dev_t *dev = port->dev;
  int rv_ibv;

  rdma_rxq_destroy_flows (&mp->flow_state.flows);
  vec_free (mp->flow_state.ucast_flows);
  mp->flow_state.ucast_flows = 0;
  mp->flow_state.promisc_flow_index = RDMA_RX_FLOW_INDEX_INVALID;
  mp->flow_state.mcast_flow_index = RDMA_RX_FLOW_INDEX_INVALID;
  if (mp->rss_qp)
    {
      rv_ibv = rdma_qp_stop (mp->rss_qp);
      if (rv_ibv && rv_ibv != 95)
	log_err (dev, "rss qp reset failed rv %d", rv_ibv);
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
  rdma_qp_stage_t failed_stage = RDMA_QP_STAGE_NONE;
  int rv_ibv;
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
    return VNET_DEV_ERR_UNSUPPORTED_DEVICE;

  mlx5_port_rss_cleanup (port);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
      if (mq->ibv_wq == 0)
	return VNET_DEV_OK;
      vec_add1 (wqs, mq->ibv_wq);
    }

  n_rxq = vec_len (wqs);
  if (n_rxq == 0)
    goto done;

  max_ind = rd->rss_max_ind_tbl_size;
  n_ind = 1u << max_log2 (n_rxq);
  if (n_ind > max_ind)
    n_ind = 1u << min_log2 (max_ind);
  if (n_ind == 0)
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
      mlx5_port_rss_cleanup (port);
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
      mlx5_port_rss_cleanup (port);
      vec_free (ind_tbl);
      vec_free (wqs);
      return VNET_DEV_ERR_UNSUPPORTED_DEVICE;
    }
  qpia.rx_hash_conf.rx_hash_key_len = port->rss_key.length;
  qpia.rx_hash_conf.rx_hash_key = port->rss_key.key;
  qpia.rx_hash_conf.rx_hash_function = IBV_RX_HASH_FUNC_TOEPLITZ;
  qpia.rx_hash_conf.rx_hash_fields_mask = rx_hash_fields;
  mp->rss_qp = ibv_create_qp_ex (rd->ctx, &qpia);
  if (mp->rss_qp == 0)
    {
      log_err (dev, "ibv_create_qp_ex failed errno %d", errno);
      mlx5_port_rss_cleanup (port);
      vec_free (ind_tbl);
      vec_free (wqs);
      return VNET_DEV_ERR_INIT_FAILED;
    }
  rv_ibv = rdma_qp_start (mp->rss_qp, port->port_id, &failed_stage);
  if (rv_ibv)
    {
      if (rv_ibv == 95 && failed_stage == RDMA_QP_STAGE_RESET)
	log_debug (dev, "rss qp start skipped rv %d stage %u", rv_ibv, failed_stage);
      else
	{
	  log_err (dev, "rss qp start failed rv %d stage %u", rv_ibv, failed_stage);
	  mlx5_port_rss_cleanup (port);
	  vec_free (ind_tbl);
	  vec_free (wqs);
	  return VNET_DEV_ERR_INIT_FAILED;
	}
    }

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
      rdma_rxq_destroy_flows (&mq->flows);
      vec_reset_length (mq->ucast_flows);
      mq->promisc_flow_index = RDMA_RX_FLOW_INDEX_INVALID;
      mq->mcast_flow_index = RDMA_RX_FLOW_INDEX_INVALID;
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
  vnet_dev_rv_t rv = VNET_DEV_OK;
  u8 promisc;
  u8 ibv_port;

  log_debug (dev, "mlx5_port_program_flows: port %u", port->port_id);

  promisc = port->promisc;
  if (req && req->type == VNET_DEV_PORT_CFG_PROMISC_MODE)
    promisc = req->promisc;

  ibv_port = port->port_id;
  rv = rdma_program_flow_state (mp->rss_qp, &mp->flow_state, port, req, promisc, ibv_port);
  return rv;
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
mlx5_port_poll_state (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  mlx5_dev_t *rd = vnet_dev_get_data (dev);
  struct ibv_port_attr port_attr = {};
  vnet_dev_port_state_changes_t changes = {};
  u8 ibv_port = port->port_id;
  u8 link_up;
  u32 width_lanes;
  u32 speed_lane;
  u32 speed;
  int rv_ibv;

  rv_ibv = ibv_query_port (rd->ctx, ibv_port, &port_attr);
  if (rv_ibv)
    {
      log_err (dev, "ibv_query_port failed port %u rv %d", ibv_port, rv_ibv);
      return;
    }

  link_up = port_attr.state == IBV_PORT_ACTIVE;
  width_lanes = rdma_port_width_lanes (port_attr.active_width);
  speed_lane = port_attr.active_speed ? mlx5_port_speed (port_attr.active_speed) : 0;
  speed = speed_lane ? (width_lanes ? speed_lane * width_lanes : speed_lane) : 0;

  if (port->link_up != link_up)
    {
      changes.change.link_state = 1;
      changes.link_state = link_up;
    }

  if (port->speed != speed)
    {
      changes.change.link_speed = 1;
      changes.link_speed = speed;
    }

  if (changes.change.any)
    vnet_dev_port_state_change (vm, port, changes);
}

static void
mlx5_port_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  mlx5_port_poll_state (vm, port);
  mlx5_port_counter_poll (vm, port);
}

vnet_dev_rv_t
mlx5_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  mlx5_port_t *mp = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv;
  u8 ibv_port;

  log_debug (dev, "mlx5_port_start: port %u", port->port_id);

  rv = mlx5_port_init_counters (vm, port);
  if (rv != VNET_DEV_OK)
    return rv;

  ibv_port = port->port_id;
  rv = mlx5_port_rss_enable (port);
  if (rv != VNET_DEV_OK)
    return rv;
  if (mp->rss_enabled == 0)
    return VNET_DEV_ERR_UNSUPPORTED_DEVICE;

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
      u32 i;
      u32 buf_sz;
      u32 max_chain_sz;
      u32 max_ds;

      if (!mp->striding_rq)
	{
	  buf_sz = vnet_dev_get_rx_queue_buffer_data_size (vm, rxq);
	  max_chain_sz = (port->max_rx_frame_size / buf_sz) + 1;
	  max_ds = mq->n_ds_per_wqe;

	  if (max_chain_sz == 0)
	    max_chain_sz = 1;
	  max_chain_sz = clib_min (max_chain_sz, (u32) RDMA_RXQ_LEGACY_MODE_MAX_CHAIN_SZ);
	  if (max_chain_sz > max_ds)
	    max_chain_sz = max_ds;
	  mq->n_ds_per_wqe = (u8) max_chain_sz;
	}
      if (mq->ibv_wq == 0)
	{
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
      mlx5_txq_t *tq = vnet_dev_get_tx_queue_data (txq);

      rv = mlx5_qp_start (dev, tq->ibv_qp, ibv_port);
      if (rv != VNET_DEV_OK)
	return rv;
      tq->sq_head = 0;
      tq->sq_tail = 0;
      tq->pkt_head = 0;
      tq->pkt_tail = 0;
      tq->dv_cq_idx = 0;
      if (tq->wqebb_n_pkts)
	clib_memset (tq->wqebb_n_pkts, 0, txq->size);
      if (tq->dv_cq_cqes)
	for (u32 i = 0; i < tq->dv_cq_size; i++)
	  tq->dv_cq_cqes[i].op_own = 0xff;
      if (tq->dv_sq_dbrec)
	__atomic_store_n (&tq->dv_sq_dbrec[MLX5_SND_DBR], 0, __ATOMIC_RELEASE);
      if (tq->dv_cq_dbrec)
	__atomic_store_n (&tq->dv_cq_dbrec[0], 0, __ATOMIC_RELEASE);
    }

  rv = mlx5_port_program_flows (port, 0);
  if (rv != VNET_DEV_OK)
    return rv;

  mlx5_port_poll_state (vm, port);
  vnet_dev_poll_port_add (vm, port, 1, mlx5_port_poll);
  return VNET_DEV_OK;
}

void
mlx5_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;

  log_debug (dev, "mlx5_port_stop: port %u", port->port_id);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    mlx5_rxq_stop (vm, rxq);

  foreach_vnet_dev_port_tx_queue (txq, port)
    mlx5_txq_stop (vm, txq);

  vnet_dev_poll_port_remove (vm, port, mlx5_port_poll);
  mlx5_port_rss_cleanup (port);

  vnet_dev_port_state_change (vm, port,
			      (vnet_dev_port_state_changes_t){
				.change.link_state = 1,
				.change.link_speed = 1,
				.link_speed = 0,
				.link_state = 0,
			      });
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
  mlx5_port_t *mp = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv = VNET_DEV_OK;
  u8 ibv_port = port->port_id;

  log_debug (dev, "mlx5_port_cfg_change: port %u type %u", port->port_id, req->type);

  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE:
      break;

    case VNET_DEV_PORT_CFG_PROMISC_MODE:
      if (port->started)
	rv =
	  rdma_flow_state_set_promisc (mp->rss_qp, &mp->flow_state, port, ibv_port, req->promisc);

    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
      if (port->started)
	rv = rdma_flow_state_set_primary_mac (
	  mp->rss_qp, &mp->flow_state, port->primary_hw_addr.eth_mac, req->addr.eth_mac, ibv_port);
      break;

    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
      if (port->started)
	rv = rdma_flow_state_add_secondary_mac (mp->rss_qp, &mp->flow_state, req->addr.eth_mac,
						ibv_port);
      break;

    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
      if (port->started)
	rv = rdma_flow_state_del_secondary_mac (mp->rss_qp, &mp->flow_state, req->addr.eth_mac,
						ibv_port);
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
