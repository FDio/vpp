/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <common.h>
#include <mlx5.h>

VLIB_REGISTER_LOG_CLASS (mlx5_log, static) = {
  .class_name = "mlx5",
  .subclass_name = "port",
};

static vnet_dev_rv_t
mlx5_rxq_program_promisc (vnet_dev_t *dev, struct ibv_qp *qp, struct ibv_flow ***flows, u8 ibv_port)
{
  u8 zero[6] = {};

  log_debug (dev, "mlx5_rxq_program_promisc: port %u", ibv_port);

  return mlx5_rxq_add_flow (dev, qp, flows, ibv_port, zero, zero, 0, 0);
}

static vnet_dev_rv_t
mlx5_rxq_program_ucast (vnet_dev_t *dev, struct ibv_qp *qp, struct ibv_flow ***flows, u8 ibv_port,
			vnet_dev_hw_addr_t *addrs, u32 n_addrs)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;
  u8 ucast_mask[6] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  };
  u8 mcast[6] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  u8 mcast_mask[6] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
  };

  log_debug (dev, "mlx5_rxq_program_ucast: port %u addrs %u", ibv_port, n_addrs);

  {
    u32 i;

    for (i = 0; i < n_addrs; i++)
      {
	rv = mlx5_rxq_add_flow (dev, qp, flows, ibv_port, addrs[i].eth_mac, ucast_mask, 0, 0);
	if (rv != VNET_DEV_OK)
	  return rv;
      }
  }

  return mlx5_rxq_add_flow (dev, qp, flows, ibv_port, mcast, mcast_mask, 0,
			    IBV_FLOW_ATTR_FLAGS_DONT_TRAP);
}

static void
mlx5_port_collect_addrs (vnet_dev_port_t *port, vnet_dev_port_cfg_change_req_t *req,
			 vnet_dev_hw_addr_t **addrs)
{
  vnet_dev_t *dev = port->dev;
  vnet_dev_hw_addr_t addr;
  vnet_dev_hw_addr_t *a;

  log_debug (dev, "mlx5_port_collect_addrs: port %u", port->port_id);

  addr = port->primary_hw_addr;
  if (req && req->type == VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR)
    addr = req->addr;

  vec_add1 (*addrs, addr);

  pool_foreach (a, port->secondary_hw_addr)
    {
      if (req && req->type == VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR)
	{
	  if (clib_memcmp (a, &req->addr, sizeof (*a)) == 0)
	    continue;
	}
      vec_add1 (*addrs, *a);
    }

  if (req && req->type == VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR)
    vec_add1 (*addrs, req->addr);
}

static vnet_dev_rv_t
mlx5_port_program_flows (vnet_dev_port_t *port, vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_t *dev = port->dev;
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

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      struct ibv_qp *qp;
      struct ibv_flow ***flows;
      mlx5_rxq_t *mq;

      mq = vnet_dev_get_rx_queue_data (rxq);
      qp = mq->ibv_qp;
      flows = &mq->flows;

      mlx5_rxq_destroy_flows (dev, flows);
      if (promisc)
	rv = mlx5_rxq_program_promisc (dev, qp, flows, ibv_port);
      else
	rv = mlx5_rxq_program_ucast (dev, qp, flows, ibv_port, addrs, vec_len (addrs));

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
  struct ibv_qp_attr qpa = {};
  int rv_ibv;

  log_debug (dev, "mlx5_qp_start: port %u", ibv_port);

  if (qp == 0)
    return VNET_DEV_ERR_INIT_FAILED;

  qpa.qp_state = IBV_QPS_RESET;
  rv_ibv = ibv_modify_qp (qp, &qpa, IBV_QP_STATE);
  if (rv_ibv)
    {
      log_err (dev, "ibv_modify_qp reset failed rv %d", rv_ibv);
      return VNET_DEV_ERR_INIT_FAILED;
    }
  log_debug (dev, "ibv_modify_qp reset ok");

  qpa.qp_state = IBV_QPS_INIT;
  qpa.port_num = ibv_port;
  rv_ibv = ibv_modify_qp (qp, &qpa, IBV_QP_STATE | IBV_QP_PORT);
  if (rv_ibv)
    {
      log_err (dev, "ibv_modify_qp init failed rv %d", rv_ibv);
      return VNET_DEV_ERR_INIT_FAILED;
    }
  log_debug (dev, "ibv_modify_qp init ok");

  qpa.qp_state = IBV_QPS_RTR;
  rv_ibv = ibv_modify_qp (qp, &qpa, IBV_QP_STATE);
  if (rv_ibv)
    {
      log_err (dev, "ibv_modify_qp rtr failed rv %d", rv_ibv);
      return VNET_DEV_ERR_INIT_FAILED;
    }
  log_debug (dev, "ibv_modify_qp rtr ok");

  qpa.qp_state = IBV_QPS_RTS;
  rv_ibv = ibv_modify_qp (qp, &qpa, IBV_QP_STATE);
  if (rv_ibv)
    {
      log_err (dev, "ibv_modify_qp rts failed rv %d", rv_ibv);
      return VNET_DEV_ERR_INIT_FAILED;
    }
  log_debug (dev, "ibv_modify_qp rts ok");

  return VNET_DEV_OK;
}

static void
mlx5_qp_stop (vnet_dev_t *dev, struct ibv_qp *qp)
{
  log_debug (dev, "mlx5_qp_stop");

  if (qp == 0)
    return;

  {
    int rv_ibv;

    rv_ibv = ibv_modify_qp (qp,
			    &(struct ibv_qp_attr){
			      .qp_state = IBV_QPS_RESET,
			    },
			    IBV_QP_STATE);
    if (rv_ibv)
      log_err (dev, "ibv_modify_qp reset failed rv %d", rv_ibv);
    else
      log_debug (dev, "ibv_modify_qp reset ok");
  }
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
      break;

    default:
      rv = VNET_DEV_ERR_NOT_SUPPORTED;
    };

  return rv;
}

vnet_dev_rv_t
mlx5_port_cfg_change (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port,
		      vnet_dev_port_cfg_change_req_t *req)
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

    default:
      rv = VNET_DEV_ERR_NOT_SUPPORTED;
    };

  return rv;
}
