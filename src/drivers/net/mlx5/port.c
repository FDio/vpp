/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <common.h>
#include <mlx5.h>
#include <vnet/devices/netlink.h>
#include <rdma/common.h>
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

static rdma_rss_caps_t
mlx5_rss_caps (vnet_dev_port_t *port)
{
  mlx5_dev_t *rd = vnet_dev_get_data (port->dev);

  return (rdma_rss_caps_t) {
    .ctx = rd->ctx,
    .pd = rd->pd,
    .max_ind_tbl_size = rd->rss_max_ind_tbl_size,
    .hash_function = rd->rss_hash_function,
    .hash_fields_mask = rd->rss_hash_fields_mask,
  };
}

static void
mlx5_port_rss_disable (vnet_dev_port_t *port)
{
  mlx5_port_t *mp = vnet_dev_get_port_data (port);

  rdma_rss_disable (&mp->rss);
}

static vnet_dev_rv_t
mlx5_port_rss_enable (vnet_dev_port_t *port, const vnet_dev_rss_config_t *cfg)
{
  mlx5_port_t *mp = vnet_dev_get_port_data (port);
  rdma_rss_caps_t caps = mlx5_rss_caps (port);
  struct ibv_wq **wqs = 0;
  vnet_dev_rv_t rv;

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
      vec_validate (wqs, rxq->queue_id);
      wqs[rxq->queue_id] = mq->ibv_wq;
    }

  rv = rdma_rss_enable (&mp->rss, &caps, wqs, cfg);
  if (rv != VNET_DEV_OK)
    log_err (port->dev, "rss setup failed: %U (errno %d)", format_vnet_dev_rv, rv, errno);
  vec_free (wqs);
  return rv;
}

static vnet_dev_rv_t
mlx5_port_program_flows (vnet_dev_port_t *port, vnet_dev_port_cfg_change_req_t *req)
{
  mlx5_port_t *mp = vnet_dev_get_port_data (port);

  return rdma_rss_program_flows (&mp->rss, port, req);
}

vnet_dev_rv_t
mlx5_port_apply_flows (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port)
{
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
}

static void
mlx5_port_poll_state (vlib_main_t *vm, vnet_dev_port_t *port)
{
  mlx5_dev_t *rd = vnet_dev_get_data (port->dev);

  rdma_port_poll_state (vm, port, rd->ctx);
}

static vnet_dev_rv_t
mlx5_port_set_netdev_mtu (vnet_dev_port_t *port, u32 max_rx_frame_size)
{
  mlx5_port_t *mp = vnet_dev_get_port_data (port);
  clib_error_t *err = 0;
  vnet_dev_rv_t rv;

  rv = rdma_netdev_set_mtu (mp->netdev_ifindex, max_rx_frame_size, &err);
  if (rv != VNET_DEV_OK)
    {
      log_err (port->dev, "failed to set kernel netdev mtu: %U", format_clib_error, err);
      clib_error_free (err);
    }
  return rv;
}

static void
mlx5_port_rx_error_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  vnet_dev_rv_t rv = VNET_DEV_OK;
  u8 rx_error = 0;

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
      rx_error |= __atomic_load_n (&mq->rx_error, __ATOMIC_RELAXED);
    }

  if (PREDICT_TRUE (rx_error == 0))
    return;

  vlib_worker_thread_barrier_sync (vm);

  mlx5_port_rss_disable (port);
  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);

      if (mq->rx_error)
	log_err (dev, "rxq %u completion error syndrome 0x%x, resetting rx queues", rxq->queue_id,
		 mq->rx_error_syndrome);
      mq->rx_error = 0;
      mlx5_rxq_wq_destroy (vm, rxq);
      if (rv == VNET_DEV_OK)
	rv = mlx5_rxq_wq_create (vm, rxq);
    }
  if (rv == VNET_DEV_OK)
    rv = mlx5_port_rss_enable (port, &port->rss_config);
  if (rv == VNET_DEV_OK)
    rv = mlx5_port_apply_flows (vm, port);

  vlib_worker_thread_barrier_release (vm);

  if (rv != VNET_DEV_OK)
    log_err (dev, "rx queue recovery failed: %U", format_vnet_dev_rv, rv);
}

vnet_dev_rv_t
mlx5_port_get_module_eeprom (vlib_main_t *vm, vnet_dev_port_t *port, void *p)
{
  mlx5_port_t *mp = vnet_dev_get_port_data (port);

  return rdma_netdev_module_eeprom_read (mp->netdev_ifindex, p);
}

vnet_dev_rv_t
mlx5_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  vnet_dev_rv_t rv;
  u8 striding = 0;

  log_debug (dev, "mlx5_port_start: port %u", port->port_id);

  rv = mlx5_port_set_netdev_mtu (port, port->max_rx_frame_size);
  if (rv != VNET_DEV_OK)
    return rv;

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      rv = mlx5_rxq_wq_create (vm, rxq);
      if (rv != VNET_DEV_OK)
	return rv;
      striding = ((mlx5_rxq_t *) vnet_dev_get_rx_queue_data (rxq))->striding;

      if (rxq->interrupt_mode)
	{
	  rv = mlx5_rxq_irq_enable (vm, rxq);
	  if (rv != VNET_DEV_OK)
	    return rv;
	}
    }

  vnet_dev_port_set_rx_node (vm, port, striding ? &mlx5_rx_node_striding : &mlx5_rx_node_legacy);

  rv = mlx5_port_rss_enable (port, &port->rss_config);
  if (rv != VNET_DEV_OK)
    return rv;

  foreach_vnet_dev_port_tx_queue (txq, port)
    {
      mlx5_txq_t *tq = vnet_dev_get_tx_queue_data (txq);

      rv = mlx5_qp_start (dev, tq->ibv_qp, port->port_id);
      if (rv != VNET_DEV_OK)
	return rv;
      tq->head = 0;
      tq->tail = 0;
    }

  rv = mlx5_port_apply_flows (vm, port);
  if (rv != VNET_DEV_OK)
    return rv;

  vnet_dev_poll_port_add (vm, port, 1, mlx5_port_counter_poll);
  vnet_dev_poll_port_add (vm, port, 1, mlx5_port_poll_state);
  vnet_dev_poll_port_add (vm, port, 0.1, mlx5_port_rx_error_poll);
  return VNET_DEV_OK;
}

void
mlx5_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;

  log_debug (dev, "mlx5_port_stop: port %u", port->port_id);

  vnet_dev_poll_port_remove (vm, port, mlx5_port_counter_poll);
  vnet_dev_poll_port_remove (vm, port, mlx5_port_poll_state);
  vnet_dev_poll_port_remove (vm, port, mlx5_port_rx_error_poll);

  mlx5_port_rss_disable (port);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      mlx5_rxq_irq_disable (vm, rxq);
      mlx5_rxq_wq_destroy (vm, rxq);
    }

  foreach_vnet_dev_port_tx_queue (txq, port)
    {
      mlx5_txq_t *tq = vnet_dev_get_tx_queue_data (txq);

      mlx5_qp_stop (dev, tq->ibv_qp);
      mlx5_txq_cq_sync (txq);
      mlx5_txq_free_bufs (vm, tq, tq->buf_tail);
      tq->head = 0;
      tq->tail = 0;
      tq->buf_head = tq->buf_tail = 0;
      __atomic_store_n (&tq->dv_sq_dbrec[MLX5_SND_DBR], 0, __ATOMIC_RELEASE);
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
      else if (req->max_rx_frame_size > port->attr.max_supported_rx_frame_size ||
	       req->max_rx_frame_size <= RDMA_NETDEV_MTU_OVERHEAD)
	rv = VNET_DEV_ERR_INVALID_VALUE;
      break;

    case VNET_DEV_PORT_CFG_SET_RSS_CONFIG:
      {
	rdma_rss_caps_t caps = mlx5_rss_caps (port);
	rv = rdma_rss_cfg_validate (&caps, &req->rss_config);
      }
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

    case VNET_DEV_PORT_CFG_SET_RSS_CONFIG:
      if (port->started)
	{
	  vnet_dev_rss_config_t cfg = port->rss_config;

	  rdma_rss_cfg_merge (&cfg, &req->rss_config);
	  mlx5_port_rss_disable (port);
	  rv = mlx5_port_rss_enable (port, &cfg);
	  if (rv == VNET_DEV_OK)
	    rv = mlx5_port_program_flows (port, 0);
	}
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
