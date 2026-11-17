/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <ibverbs.h>
#include <rdma/common.h>
#include <vlib/file.h>
#include <vnet/dev/counters.h>
#include <errno.h>
#include <fcntl.h>

VLIB_REGISTER_LOG_CLASS (ibv_log, static) = {
  .class_name = "ibverbs",
  .subclass_name = "port",
};

static rdma_rss_caps_t
ibv_rss_caps (vnet_dev_port_t *port)
{
  ibv_dev_t *rd = vnet_dev_get_data (port->dev);

  return (rdma_rss_caps_t) {
    .ctx = rd->ctx,
    .pd = rd->pd,
    .max_ind_tbl_size = rd->rss_max_ind_tbl_size,
    .hash_function = rd->rss_hash_function,
    .hash_fields_mask = rd->rss_hash_fields_mask,
  };
}

static vnet_dev_rv_t
ibv_port_rss_enable (vnet_dev_port_t *port, const vnet_dev_rss_config_t *cfg)
{
  ibv_port_t *ip = vnet_dev_get_port_data (port);
  rdma_rss_caps_t caps = ibv_rss_caps (port);
  struct ibv_wq **wqs = 0;
  vnet_dev_rv_t rv;

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
      vec_validate (wqs, rxq->queue_id);
      wqs[rxq->queue_id] = iq->ibv_wq;
    }

  rv = rdma_rss_enable (&ip->rss, &caps, wqs, cfg);
  if (rv != VNET_DEV_OK)
    log_err (port->dev, "rss setup failed: %U (errno %d)", format_vnet_dev_rv, rv, errno);
  vec_free (wqs);
  return rv;
}

static vnet_dev_rv_t
ibv_port_program_flows (vnet_dev_port_t *port, vnet_dev_port_cfg_change_req_t *req)
{
  ibv_port_t *ip = vnet_dev_get_port_data (port);

  return rdma_rss_program_flows (&ip->rss, port, req);
}

vnet_dev_rv_t
ibv_port_apply_flows (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port)
{
  return ibv_port_program_flows (port, 0);
}

static vnet_dev_rv_t
ibv_port_cfg_rxq_int_mode_change (vlib_main_t *vm, vnet_dev_port_t *port, u16 qid, u8 enable,
				  u8 all)
{
  return rdma_port_cfg_rxq_intr_mode_change (vm, port, qid, enable, all, ibv_rxq_irq_enable,
					     ibv_rxq_irq_disable);
}

static vnet_dev_rv_t
ibv_drv_qp_start (vnet_dev_t *dev, struct ibv_qp *qp, u8 ibv_port)
{
  rdma_qp_stage_t failed_stage;
  int rv_ibv;

  log_debug (dev, "ibv_qp_start: port %u", ibv_port);

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
	log_err (dev, "ibv_qp_start failed rv %d", rv_ibv);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  return VNET_DEV_OK;
}

static void
ibv_drv_qp_stop (vnet_dev_t *dev, struct ibv_qp *qp)
{
  int rv_ibv;

  log_debug (dev, "ibv_qp_stop");

  if (qp == 0)
    return;

  rv_ibv = rdma_qp_stop (qp);
  if (rv_ibv)
    log_err (dev, "ibv_modify_qp reset failed rv %d", rv_ibv);
}

static void
ibv_port_poll_state (vlib_main_t *vm, vnet_dev_port_t *port)
{
  ibv_dev_t *rd = vnet_dev_get_data (port->dev);

  rdma_port_poll_state (vm, port, rd->ctx);
}

static clib_error_t *
ibv_async_fd_read_ready (clib_file_t *uf)
{
  vnet_dev_t *dev = uword_to_pointer (uf->private_data, vnet_dev_t *);
  ibv_dev_t *rd = vnet_dev_get_data (dev);
  struct ibv_async_event ae;

  while (ibv_get_async_event (rd->ctx, &ae) == 0)
    {
      u8 ibv_port = 0;

      switch (ae.event_type)
	{
	case IBV_EVENT_PORT_ACTIVE:
	case IBV_EVENT_PORT_ERR:
#ifdef IBV_EVENT_GID_CHANGE
	case IBV_EVENT_GID_CHANGE:
#endif
	case IBV_EVENT_LID_CHANGE:
	case IBV_EVENT_PKEY_CHANGE:
	case IBV_EVENT_SM_CHANGE:
	  ibv_port = ae.element.port_num;
	  break;
	default:
	  break;
	}

      if (ibv_port)
	{
	  vnet_dev_port_t *port = vnet_dev_get_port_by_id (dev, ibv_port);
	  if (port && port->started)
	    vnet_dev_process_call_port_op_no_wait (vlib_get_main (), port, ibv_port_poll_state);
	}

      ibv_ack_async_event (&ae);
    }

  if (errno != EAGAIN && errno != EWOULDBLOCK)
    log_err (dev, "ibv_get_async_event failed errno %d", errno);

  return 0;
}

static clib_error_t *
ibv_async_fd_error_ready (clib_file_t *uf)
{
  vnet_dev_t *dev = uword_to_pointer (uf->private_data, vnet_dev_t *);

  log_err (dev, "async event fd error");
  return 0;
}

static void
ibv_async_events_enable (vnet_dev_t *dev)
{
  ibv_dev_t *rd = vnet_dev_get_data (dev);
  clib_file_t template = {};
  int flags;
  u32 idx;

  if (rd->async_event_file_added)
    return;

  flags = fcntl (rd->ctx->async_fd, F_GETFL, 0);
  if (flags < 0 || fcntl (rd->ctx->async_fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
      log_warn (dev, "async event fd setup failed, polling only");
      return;
    }

  template.file_descriptor = rd->ctx->async_fd;
  template.read_function = ibv_async_fd_read_ready;
  template.error_function = ibv_async_fd_error_ready;
  template.private_data = pointer_to_uword (dev);
  template.dont_close = 1;
  template.description = format (0, "ibverbs-asyncfd-%U%c", format_vnet_dev_addr, dev, 0);
  idx = clib_file_add (&file_main, &template);
  rd->async_clib_file_index = idx;
  rd->async_event_file_added = 1;
}

static void
ibv_async_events_disable (vnet_dev_t *dev, vnet_dev_port_t *stopping_port)
{
  ibv_dev_t *rd = vnet_dev_get_data (dev);
  int keep = 0;

  if (rd->async_event_file_added == 0)
    return;

  foreach_vnet_dev_port (p, dev)
    if (p != stopping_port && p->started)
      {
	keep = 1;
	break;
      }

  if (keep)
    return;

  clib_file_del_by_index (&file_main, rd->async_clib_file_index);
  rd->async_event_file_added = 0;
  rd->async_clib_file_index = 0;
}

static void
ibv_port_rx_error_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  ibv_port_t *ip = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv = VNET_DEV_OK;
  u8 rx_error = 0;

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
      rx_error |= __atomic_load_n (&iq->rx_error, __ATOMIC_RELAXED);
    }

  if (PREDICT_TRUE (rx_error == 0))
    return;

  vlib_worker_thread_barrier_sync (vm);

  rdma_rss_disable (&ip->rss);
  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);

      if (iq->rx_error)
	log_err (dev, "rxq %u completion error status %u, resetting rx queues", rxq->queue_id,
		 iq->rx_error_status);
      iq->rx_error = 0;
      ibv_rxq_wq_destroy (vm, rxq);
      if (rv == VNET_DEV_OK)
	rv = ibv_rxq_wq_create (vm, rxq);
    }
  if (rv == VNET_DEV_OK)
    rv = ibv_port_rss_enable (port, &port->rss_config);
  if (rv == VNET_DEV_OK)
    rv = ibv_port_program_flows (port, 0);

  vlib_worker_thread_barrier_release (vm);

  if (rv != VNET_DEV_OK)
    log_err (dev, "rx queue recovery failed: %U", format_vnet_dev_rv, rv);
}

static vnet_dev_rv_t
ibv_port_set_netdev_mtu (vnet_dev_port_t *port, u32 max_rx_frame_size)
{
  ibv_port_t *ip = vnet_dev_get_port_data (port);
  clib_error_t *err = 0;
  vnet_dev_rv_t rv;

  if (ip->netdev_ifindex == 0)
    return VNET_DEV_OK;

  rv = rdma_netdev_set_mtu (ip->netdev_ifindex, max_rx_frame_size, &err);
  if (rv != VNET_DEV_OK)
    {
      log_err (port->dev, "failed to set kernel netdev mtu: %U", format_clib_error, err);
      clib_error_free (err);
    }
  return rv;
}

vnet_dev_rv_t
ibv_port_get_module_eeprom (vlib_main_t *vm, vnet_dev_port_t *port, void *p)
{
  ibv_port_t *ip = vnet_dev_get_port_data (port);

  return rdma_netdev_module_eeprom_read (ip->netdev_ifindex, p);
}

vnet_dev_rv_t
ibv_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  vnet_dev_rv_t rv;

  log_debug (dev, "ibv_port_start: port %u", port->port_id);

  rv = ibv_port_set_netdev_mtu (port, port->max_rx_frame_size);
  if (rv != VNET_DEV_OK)
    return rv;

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      rv = ibv_rxq_wq_create (vm, rxq);
      if (rv != VNET_DEV_OK)
	return rv;
      if (rxq->interrupt_mode)
	{
	  rv = ibv_rxq_irq_enable (vm, rxq);
	  if (rv != VNET_DEV_OK)
	    return rv;
	}
    }

  rv = ibv_port_rss_enable (port, &port->rss_config);
  if (rv != VNET_DEV_OK)
    return rv;

  foreach_vnet_dev_port_tx_queue (txq, port)
    {
      ibv_txq_t *tq = vnet_dev_get_tx_queue_data (txq);

      rv = ibv_drv_qp_start (dev, tq->ibv_qp, port->port_id);
      if (rv != VNET_DEV_OK)
	return rv;
      tq->head = 0;
      tq->tail = 0;
    }

  rv = ibv_port_program_flows (port, 0);
  if (rv != VNET_DEV_OK)
    return rv;

  ibv_async_events_enable (dev);
  vnet_dev_poll_port_add (vm, port, 1, ibv_port_poll_state);
  vnet_dev_poll_port_add (vm, port, 0.1, ibv_port_rx_error_poll);

  return VNET_DEV_OK;
}

void
ibv_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  ibv_port_t *ip = vnet_dev_get_port_data (port);

  log_debug (dev, "ibv_port_stop: port %u", port->port_id);

  vnet_dev_poll_port_remove (vm, port, ibv_port_poll_state);
  vnet_dev_poll_port_remove (vm, port, ibv_port_rx_error_poll);

  rdma_rss_disable (&ip->rss);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);

      ibv_rxq_irq_disable (vm, rxq);
      ibv_rxq_wq_destroy (vm, rxq);
      iq->rx_error = 0;
    }

  foreach_vnet_dev_port_tx_queue (txq, port)
    {
      ibv_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
      u32 n = tq->tail - tq->head;
      struct ibv_wc wc[VLIB_FRAME_SIZE];

      ibv_drv_qp_stop (dev, tq->ibv_qp);
      while (ibv_poll_cq (tq->ibv_cq, ARRAY_LEN (wc), wc) > 0)
	;
      if (n)
	vlib_buffer_free_from_ring (vm, tq->buffers, tq->head & (txq->size - 1), txq->size, n);
      tq->head = 0;
      tq->tail = 0;
    }

  ibv_async_events_disable (dev, port);
}

vnet_dev_rv_t
ibv_port_cfg_change_validate (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port,
			      vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_t *dev = port->dev;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  log_debug (dev, "ibv_port_cfg_change_validate: port %u type %u", port->port_id, req->type);

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
	rdma_rss_caps_t caps = ibv_rss_caps (port);
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
ibv_port_cfg_change (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port,
		     vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_t *dev = port->dev;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  log_debug (dev, "ibv_port_cfg_change: port %u type %u", port->port_id, req->type);

  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE:
      break;

    case VNET_DEV_PORT_CFG_SET_RSS_CONFIG:
      if (port->started)
	{
	  ibv_port_t *ip = vnet_dev_get_port_data (port);
	  vnet_dev_rss_config_t cfg = port->rss_config;

	  rdma_rss_cfg_merge (&cfg, &req->rss_config);
	  rdma_rss_disable (&ip->rss);
	  rv = ibv_port_rss_enable (port, &cfg);
	  if (rv == VNET_DEV_OK)
	    rv = ibv_port_program_flows (port, 0);
	}
      break;

    case VNET_DEV_PORT_CFG_PROMISC_MODE:
    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
      if (port->started)
	rv = ibv_port_program_flows (port, req);
      break;

    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_ENABLE:
      rv = ibv_port_cfg_rxq_int_mode_change (vm, port, req->queue_id, 1, req->all_queues);
      break;

    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_DISABLE:
      rv = ibv_port_cfg_rxq_int_mode_change (vm, port, req->queue_id, 0, req->all_queues);
      break;

    default:
      rv = VNET_DEV_ERR_NOT_SUPPORTED;
    };

  return rv;
}
