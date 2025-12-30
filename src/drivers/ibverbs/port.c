/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <ibverbs.h>
#include <vlib/file.h>
#include <errno.h>
#include <fcntl.h>

VLIB_REGISTER_LOG_CLASS (ibv_log, static) = {
  .class_name = "ibverbs",
  .subclass_name = "port",
};

static vnet_dev_rv_t
ibv_rxq_program_promisc (vnet_dev_t *dev, struct ibv_qp *qp, struct ibv_flow ***flows, u8 ibv_port)
{
  u8 zero[6] = {};

  log_debug (dev, "ibv_rxq_program_promisc: port %u", ibv_port);

  return ibv_rxq_add_flow (dev, qp, flows, ibv_port, zero, zero, 0, 0);
}

static vnet_dev_rv_t
ibv_rxq_program_ucast (vnet_dev_t *dev, struct ibv_qp *qp, struct ibv_flow ***flows, u8 ibv_port,
		       vnet_dev_hw_addr_t *addrs, u32 n_addrs)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;
  u8 mcast[6] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };
  u8 ucast_mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  u8 mcast_mask[6] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };

  log_debug (dev, "ibv_rxq_program_ucast: port %u addrs %u", ibv_port, n_addrs);

  for (u32 i = 0; i < n_addrs; i++)
    {
      rv = ibv_rxq_add_flow (dev, qp, flows, ibv_port, addrs[i].eth_mac, ucast_mask, 0, 0);
      if (rv != VNET_DEV_OK)
	return rv;
    }

  return ibv_rxq_add_flow (dev, qp, flows, ibv_port, mcast, mcast_mask, 0,
			   IBV_FLOW_ATTR_FLAGS_DONT_TRAP);
}

static void
ibv_port_collect_addrs (vnet_dev_port_t *port, vnet_dev_port_cfg_change_req_t *req,
			vnet_dev_hw_addr_t **addrs)
{
  vnet_dev_t *dev = port->dev;
  vnet_dev_hw_addr_t addr = port->primary_hw_addr;
  vnet_dev_hw_addr_t *a;

  log_debug (dev, "ibv_port_collect_addrs: port %u", port->port_id);

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
ibv_port_program_flows (vnet_dev_port_t *port, vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_t *dev = port->dev;
  vnet_dev_hw_addr_t *addrs = 0;
  vnet_dev_rv_t rv = VNET_DEV_OK;
  u8 promisc;
  u8 ibv_port;

  log_debug (dev, "ibv_port_program_flows: port %u", port->port_id);

  promisc = port->promisc;
  if (req && req->type == VNET_DEV_PORT_CFG_PROMISC_MODE)
    promisc = req->promisc;

  if (promisc == 0)
    ibv_port_collect_addrs (port, req, &addrs);

  ibv_port = (u8) port->port_id;

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      struct ibv_qp *qp;
      struct ibv_flow ***flows;
      ibv_rxq_t *iq;

      iq = vnet_dev_get_rx_queue_data (rxq);
      qp = iq->ibv_qp;
      flows = &iq->flows;

      ibv_rxq_destroy_flows (dev, flows);
      if (promisc)
	rv = ibv_rxq_program_promisc (dev, qp, flows, ibv_port);
      else
	rv = ibv_rxq_program_ucast (dev, qp, flows, ibv_port, addrs, vec_len (addrs));

      if (rv != VNET_DEV_OK)
	goto done;
    }

done:
  vec_free (addrs);
  return rv;
}

static vnet_dev_rv_t
ibv_port_cfg_rxq_int_mode_change (vlib_main_t *vm, vnet_dev_port_t *port, u16 qid, u8 enable,
				  u8 all)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;

  if (port->started == 0)
    return rv;

  if (all)
    {
      foreach_vnet_dev_port_rx_queue (rxq, port)
	{
	  if (rxq->started == 0)
	    continue;
	  if (enable)
	    rv = ibv_rxq_irq_enable (vm, rxq);
	  else
	    ibv_rxq_irq_disable (vm, rxq);
	  if (rv != VNET_DEV_OK)
	    return rv;
	}
    }
  else
    {
      vnet_dev_rx_queue_t *rxq = vnet_dev_get_port_rx_queue_by_id (port, qid);
      if (rxq == 0)
	return VNET_DEV_ERR_BUG;
      if (rxq->started == 0)
	return rv;
      if (enable)
	rv = ibv_rxq_irq_enable (vm, rxq);
      else
	ibv_rxq_irq_disable (vm, rxq);
    }

  return rv;
}

static vnet_dev_rv_t
ibv_qp_start (vnet_dev_t *dev, struct ibv_qp *qp, u8 ibv_port)
{
  struct ibv_qp_attr qpa = {};
  int rv_ibv;

  log_debug (dev, "ibv_qp_start: port %u", ibv_port);

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
ibv_qp_stop (vnet_dev_t *dev, struct ibv_qp *qp)
{
  log_debug (dev, "ibv_qp_stop");

  if (qp == 0)
    return;

  {
    int rv_ibv = ibv_modify_qp (qp,
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

static void
ibv_port_poll_state (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  ibv_dev_t *rd = vnet_dev_get_data (dev);
  struct ibv_port_attr port_attr = {};
  vnet_dev_port_state_changes_t changes = {};
  u8 ibv_port = (u8) port->port_id;
  u8 link_up;
  u32 speed;
  int rv_ibv;

  rv_ibv = ibv_query_port (rd->ctx, ibv_port, &port_attr);
  if (rv_ibv)
    {
      log_err (dev, "ibv_query_port failed port %u rv %d", ibv_port, rv_ibv);
      return;
    }

  link_up = port_attr.state == IBV_PORT_ACTIVE;
  speed = port_attr.active_speed ? ibv_port_speed (port_attr.active_speed) : 0;

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
	  if (port)
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

vnet_dev_rv_t
ibv_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  vnet_dev_rv_t rv;
  u8 ibv_port;

  log_debug (dev, "ibv_port_start: port %u", port->port_id);

  ibv_port = (u8) port->port_id;

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
      u32 buf_sz = vnet_dev_get_rx_queue_buffer_data_size (vm, rxq);
      u32 max_chain_sz = (port->max_rx_frame_size + buf_sz - 1) / buf_sz;
      u32 max_ds = iq->n_ds_per_wqe_max;
      u32 n_tail;
      u32 n_wr = 1u << IBV_RX_REFILL_LOG2_BATCH_SZ;
      u32 sz;

      if (max_chain_sz == 0)
	max_chain_sz = 1;
      max_chain_sz = clib_min (max_chain_sz, (u32) IBV_RXQ_MAX_CHAIN_SZ);
      if (max_chain_sz > max_ds)
	max_chain_sz = max_ds;
      n_tail = max_chain_sz - 1;
      if (n_tail != iq->max_tails)
	{
	  if (iq->second_bufs)
	    {
	      clib_mem_free (iq->second_bufs);
	      iq->second_bufs = 0;
	    }
	  if (iq->n_tail_refills)
	    {
	      clib_mem_free (iq->n_tail_refills);
	      iq->n_tail_refills = 0;
	    }
	  if (n_tail)
	    {
	      sz = sizeof (iq->second_bufs[0]) * rxq->size * n_tail;
	      iq->second_bufs = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
	      if (iq->second_bufs == 0)
		return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
	      sz = sizeof (iq->n_tail_refills[0]) * rxq->size;
	      iq->n_tail_refills = clib_mem_alloc_aligned (sz, 64);
	      if (iq->n_tail_refills == 0)
		{
		  clib_mem_free (iq->second_bufs);
		  iq->second_bufs = 0;
		  return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
		}
	      for (u32 i = 0; i < rxq->size; i++)
		iq->n_tail_refills[i] = n_tail;
	    }
	}
      iq->n_ds_per_wqe = (u8) max_chain_sz;
      iq->max_tails = (u8) n_tail;
      iq->n_left_to_post = 0;
      for (u32 i = 0; i < n_wr; i++)
	{
	  iq->refill_entries[i].recv_wr.num_sge = iq->n_ds_per_wqe;
	  for (u32 j = 0; j < iq->n_ds_per_wqe; j++)
	    {
	      u32 off = j * buf_sz;
	      iq->refill_entries[i].sge[j].length =
		clib_min (buf_sz, port->max_rx_frame_size - off);
	    }
	}
      rv = ibv_qp_start (dev, iq->ibv_qp, ibv_port);
      if (rv != VNET_DEV_OK)
	return rv;
      if (rxq->interrupt_mode)
	{
	  rv = ibv_rxq_irq_enable (vm, rxq);
	  if (rv != VNET_DEV_OK)
	    return rv;
	}
      iq->head = 0;
      iq->tail = 0;
    }

  foreach_vnet_dev_port_tx_queue (txq, port)
    {
      ibv_txq_t *tq;

      tq = vnet_dev_get_tx_queue_data (txq);
      rv = ibv_qp_start (dev, tq->ibv_qp, ibv_port);
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

  return VNET_DEV_OK;
}

void
ibv_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;

  log_debug (dev, "ibv_port_stop: port %u", port->port_id);

  vnet_dev_poll_port_remove (vm, port, ibv_port_poll_state);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
      ibv_rxq_irq_disable (vm, rxq);
      ibv_qp_stop (dev, iq->ibv_qp);

      if (iq->buffers)
	{
	  u32 n = iq->tail - iq->head;

	  if (n)
	    {
	      u32 mask = rxq->size - 1;
	      if (iq->n_ds_per_wqe > 1 && iq->second_bufs)
		{
		  u32 extras_per = iq->n_ds_per_wqe - 1;
		  u32 slot = iq->head & mask;
		  u32 left = n;
		  while (left)
		    {
		      u32 n_now = clib_min (left, rxq->size - slot);
		      for (u32 i = 0; i < n_now; i++)
			{
			  u32 base = (slot + i) * extras_per;
			  vlib_buffer_free (vm, iq->second_bufs + base, extras_per);
			}
		      left -= n_now;
		      slot = 0;
		    }
		}
	      vlib_buffer_free_from_ring (vm, iq->buffers, iq->head & mask, rxq->size, n);
	    }
	}
      iq->head = 0;
      iq->tail = 0;
    }

  foreach_vnet_dev_port_tx_queue (txq, port)
    {
      ibv_txq_t *tq;

      tq = vnet_dev_get_tx_queue_data (txq);
      ibv_qp_stop (dev, tq->ibv_qp);
      if (tq->buffers)
	{
	  u32 n;
	  u32 mask;

	  n = tq->tail - tq->head;
	  if (n)
	    {
	      mask = txq->size - 1;
	      vlib_buffer_free_from_ring (vm, tq->buffers, tq->head & mask, txq->size, n);
	    }
	}
      tq->head = 0;
      tq->tail = 0;
    }

  ibv_async_events_disable (dev, port);

  vnet_dev_port_state_change (vm, port,
			      (vnet_dev_port_state_changes_t){
				.change.link_state = 1,
				.change.link_speed = 1,
				.link_speed = 0,
				.link_state = 0,
			      });
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
