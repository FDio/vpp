/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <ibverbs.h>
#include <common/common.h>
#include <vlib/file.h>
#include <errno.h>
#include <fcntl.h>

static u8 ibv_rss_hash_key[] = {
  0x2c, 0xc6, 0x81, 0xd1, 0x5b, 0xdb, 0xf4, 0xf7, 0xfc, 0xa2, 0x83, 0x19, 0xdb, 0x1a,
  0x3e, 0x94, 0x6b, 0x9e, 0x38, 0xd9, 0x2c, 0x9c, 0x03, 0xd1, 0xad, 0x99, 0x44, 0xa7,
  0xd9, 0x56, 0x3d, 0x59, 0x06, 0x3c, 0x25, 0xf3, 0xfc, 0x1f, 0xdc, 0x2a,
};

VLIB_REGISTER_LOG_CLASS (ibv_log, static) = {
  .class_name = "ibverbs",
  .subclass_name = "port",
};

static void
ibv_port_collect_addrs (vnet_dev_port_t *port, vnet_dev_port_cfg_change_req_t *req,
			vnet_dev_hw_addr_t **addrs)
{
  rdma_port_collect_addrs (port, req, addrs);
}

static void
ibv_port_rss_disable (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  ibv_port_t *ip = vnet_dev_get_port_data (port);
  int rv_ibv;

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
      iq->use_rss = 0;
    }

  rdma_rxq_destroy_flows (&ip->flows);
  vec_free (ip->ucast_flows);
  ip->ucast_flows = 0;
  ip->promisc_flow_index = RDMA_RX_FLOW_INDEX_INVALID;
  ip->mcast_flow_index = RDMA_RX_FLOW_INDEX_INVALID;
  if (ip->rss_qp)
    {
      rv_ibv = rdma_qp_stop (ip->rss_qp);
      if (rv_ibv && rv_ibv != 95)
	log_err (dev, "rss qp reset failed rv %d", rv_ibv);
      rv_ibv = ibv_destroy_qp (ip->rss_qp);
      if (rv_ibv)
	log_err (dev, "ibv_destroy_qp rss failed rv %d", rv_ibv);
      ip->rss_qp = 0;
    }
  if (ip->rwq_ind_tbl)
    {
      ibv_destroy_rwq_ind_table (ip->rwq_ind_tbl);
      ip->rwq_ind_tbl = 0;
    }
  ip->rss_enabled = 0;
}

static vnet_dev_rv_t
ibv_port_rss_enable (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  ibv_dev_t *rd = vnet_dev_get_data (dev);
  ibv_port_t *ip = vnet_dev_get_port_data (port);
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

  if (rd->rss == 0)
    return VNET_DEV_ERR_UNSUPPORTED_DEVICE;

  ibv_port_rss_disable (port);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
      if (iq->ibv_wq == 0)
	return VNET_DEV_OK;
      vec_add1 (wqs, iq->ibv_wq);
    }

  n_rxq = vec_len (wqs);
  if (n_rxq == 0)
    goto done;

  max_ind = rd->rss_max_ind_tbl_size;
  if (max_ind == 0)
    goto done;
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
  ip->rwq_ind_tbl = ibv_create_rwq_ind_table (rd->ctx, &rwqia);
  if (ip->rwq_ind_tbl == 0)
    {
      log_err (dev, "ibv_create_rwq_ind_table failed");
      vec_free (ind_tbl);
      vec_free (wqs);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  qpia.qp_type = IBV_QPT_RAW_PACKET;
  qpia.comp_mask = IBV_QP_INIT_ATTR_PD | IBV_QP_INIT_ATTR_IND_TABLE | IBV_QP_INIT_ATTR_RX_HASH;
  qpia.pd = rd->pd;
  qpia.rwq_ind_tbl = ip->rwq_ind_tbl;
  if (!(rd->rss_hash_function & IBV_RX_HASH_FUNC_TOEPLITZ))
    {
      log_err (dev, "toeplitz hash function is not supported");
      ibv_port_rss_disable (port);
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
      ibv_port_rss_disable (port);
      vec_free (ind_tbl);
      vec_free (wqs);
      return VNET_DEV_ERR_UNSUPPORTED_DEVICE;
    }
  qpia.rx_hash_conf.rx_hash_function = IBV_RX_HASH_FUNC_TOEPLITZ;
  qpia.rx_hash_conf.rx_hash_fields_mask = rx_hash_fields;
  qpia.rx_hash_conf.rx_hash_key_len = sizeof (ibv_rss_hash_key);
  qpia.rx_hash_conf.rx_hash_key = ibv_rss_hash_key;
  ip->rss_qp = ibv_create_qp_ex (rd->ctx, &qpia);
  if (ip->rss_qp == 0)
    {
      log_err (dev, "ibv_create_qp_ex failed errno %d", errno);
      ibv_port_rss_disable (port);
      vec_free (ind_tbl);
      vec_free (wqs);
      return VNET_DEV_ERR_INIT_FAILED;
    }
  rv_ibv = rdma_qp_start (ip->rss_qp, (u8) port->port_id, &failed_stage);
  if (rv_ibv)
    {
      if (rv_ibv == 95 && failed_stage == RDMA_QP_STAGE_RESET)
	log_debug (dev, "rss qp start skipped rv %d stage %u", rv_ibv, failed_stage);
      else
	{
	  log_err (dev, "rss qp start failed rv %d stage %u", rv_ibv, failed_stage);
	  ibv_port_rss_disable (port);
	  vec_free (ind_tbl);
	  vec_free (wqs);
	  return VNET_DEV_ERR_INIT_FAILED;
	}
    }

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
      rdma_rxq_destroy_flows (&iq->flows);
      vec_reset_length (iq->ucast_flows);
      iq->promisc_flow_index = RDMA_RX_FLOW_INDEX_INVALID;
      iq->mcast_flow_index = RDMA_RX_FLOW_INDEX_INVALID;
      iq->use_rss = 1;
    }
  ip->rss_enabled = 1;

done:
  vec_free (ind_tbl);
  vec_free (wqs);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
ibv_port_program_flows (vnet_dev_port_t *port, vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_t *dev = port->dev;
  ibv_port_t *ip = vnet_dev_get_port_data (port);
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
  if (ip->rss_enabled == 0 || ip->rss_qp == 0)
    {
      rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;
      goto done;
    }

  rv = rdma_program_flow_state (ip->rss_qp, &ip->flows, &ip->ucast_flows, &ip->promisc_flow_index,
				&ip->mcast_flow_index, addrs, promisc, ibv_port);

done:
  vec_free (addrs);
  return rv;
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
  else
    log_debug (dev, "ibv_modify_qp reset ok");
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
  speed_lane = port_attr.active_speed ? rdma_port_speed (port_attr.active_speed) : 0;
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
  ibv_port_t *ip = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv;
  u8 ibv_port;

  log_debug (dev, "ibv_port_start: port %u", port->port_id);

  ibv_port = (u8) port->port_id;
  rv = ibv_port_rss_enable (port);
  if (rv != VNET_DEV_OK)
    return rv;
  if (ip->rss_enabled == 0)
    return VNET_DEV_ERR_UNSUPPORTED_DEVICE;

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
      rv = ibv_drv_qp_start (dev, tq->ibv_qp, ibv_port);
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
  ibv_port_t *ip = vnet_dev_get_port_data (port);

  log_debug (dev, "ibv_port_stop: port %u", port->port_id);

  vnet_dev_poll_port_remove (vm, port, ibv_port_poll_state);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
      ibv_rxq_irq_disable (vm, rxq);
      if (ip->rss_enabled == 0)
	ibv_drv_qp_stop (dev, iq->ibv_qp);

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
      iq->use_rss = 0;
    }

  foreach_vnet_dev_port_tx_queue (txq, port)
    {
      ibv_txq_t *tq;

      tq = vnet_dev_get_tx_queue_data (txq);
      ibv_drv_qp_stop (dev, tq->ibv_qp);
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
  ibv_port_rss_disable (port);

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
