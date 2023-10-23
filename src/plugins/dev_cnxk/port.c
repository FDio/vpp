/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/pci.h>
#include <vnet/dev/counters.h>
#include <dev_cnxk/cnxk.h>
#include <vnet/ethernet/ethernet.h>

VLIB_REGISTER_LOG_CLASS (cnxk_log, static) = {
  .class_name = "cnxk",
  .subclass_name = "port",
};

static const u8 default_rss_key[] = {
  0xfe, 0xed, 0x0b, 0xad, 0xfe, 0xed, 0x0b, 0xad, 0xad, 0x0b, 0xed, 0xfe,
  0xad, 0x0b, 0xed, 0xfe, 0x13, 0x57, 0x9b, 0xef, 0x24, 0x68, 0xac, 0x0e,
  0x91, 0x72, 0x53, 0x11, 0x82, 0x64, 0x20, 0x44, 0x12, 0xef, 0x34, 0xcd,
  0x56, 0xbc, 0x78, 0x9a, 0x9a, 0x78, 0xbc, 0x56, 0xcd, 0x34, 0xef, 0x12
};

static const u64 rxq_cfg =
  ROC_NIX_LF_RX_CFG_DIS_APAD | ROC_NIX_LF_RX_CFG_IP6_UDP_OPT |
  ROC_NIX_LF_RX_CFG_L2_LEN_ERR | ROC_NIX_LF_RX_CFG_DROP_RE |
  ROC_NIX_LF_RX_CFG_CSUM_OL4 | ROC_NIX_LF_RX_CFG_CSUM_IL4 |
  ROC_NIX_LF_RX_CFG_LEN_OL3 | ROC_NIX_LF_RX_CFG_LEN_OL4 |
  ROC_NIX_LF_RX_CFG_LEN_IL3 | ROC_NIX_LF_RX_CFG_LEN_IL4;

vnet_dev_rv_t
cnxk_roc_err (vnet_dev_t *dev, int rv, char *fmt, ...)
{
  u8 *s = 0;
  va_list va;

  va_start (va, fmt);
  s = va_format (s, fmt, &va);
  va_end (va);

  log_err (dev, "%v - ROC error %s (%d)", s, roc_error_msg_get (rv), rv);

  vec_free (s);
  return VNET_DEV_ERR_INTERNAL;
}

static void
cnxk_rxq_deinit (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  cnxk_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_t *dev = rxq->port->dev;
  int rrv;

  if (crq->rq_initialized)
    {
      rrv = roc_nix_rq_fini (&crq->rq);
      if (rrv)
	cnxk_roc_err (dev, rrv, "roc_nix_rq_fini() failed");
      crq->rq_initialized = 0;
    }

  if (crq->cq_initialized)
    {
      rrv = roc_nix_cq_fini (&crq->cq);
      if (rrv)
	cnxk_roc_err (dev, rrv, "roc_nix_cq_fini() failed");
      crq->cq_initialized = 0;
    }

  if (crq->npa_pool_initialized)
    {
      rrv = roc_npa_pool_destroy (crq->aura_handle);
      if (rrv)
	cnxk_roc_err (dev, rrv, "roc_npa_pool_destroy() failed");
      crq->npa_pool_initialized = 0;
    }
}

static vnet_dev_rv_t
cnxk_rxq_init (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  cnxk_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_t *dev = rxq->port->dev;
  cnxk_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;
  int rrv;
  struct npa_aura_s aura = {};
  struct npa_pool_s npapool = {
    .nat_align = 1,
    .buf_offset = 1,
  };

  if ((rrv =
	 roc_npa_pool_create (&crq->aura_handle, 2048, 8, &aura, &npapool, 0)))
    return cnxk_roc_err (dev, rrv, "roc_npa_pool_create() failed");
  log_debug (dev, "NPA pool created, aura_handle = 0x%lx", crq->aura_handle);
  crq->npa_pool_initialized = 1;

  crq->cq = (struct roc_nix_cq){
    .nb_desc = rxq->size,
    .qid = rxq->queue_id,
  };

  if ((rrv = roc_nix_cq_init (nix, &crq->cq)))
    return cnxk_roc_err (dev, rrv,
			 "roc_nix_cq_init(qid = %u, nb_desc = %u) failed",
			 crq->cq.nb_desc, crq->cq.nb_desc);
  log_debug (dev, "CQ %u initialsed", crq->cq.qid);
  crq->cq_initialized = 1;

  u32 first_skip = sizeof (vlib_buffer_t); // + sizeof (cnxk_pktio_meta_t);

  crq->rq = (struct roc_nix_rq){
    .qid = rxq->queue_id,
    .cqid = crq->cq.qid,
    .aura_handle = crq->aura_handle,
    .first_skip = first_skip,
    .later_skip = first_skip,
    .lpb_size = vlib_buffer_get_default_data_size (vm) + first_skip,
    .flow_tag_width = 32,
  };

  if ((rrv = roc_nix_rq_init (nix, &crq->rq, 1 /* disable */)))
    return cnxk_roc_err (dev, rrv, "roc_nix_rq_init(qid = %u) failed",
			 crq->rq.qid);
  log_debug (dev, "RQ %u initialsed", crq->cq.qid);
  crq->rq_initialized = 1;

  return VNET_DEV_OK;
}

static void
cnxk_txq_deinit (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  cnxk_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
  vnet_dev_t *dev = txq->port->dev;
  int rrv;

  if (ctq->sq_initialized)
    {
      rrv = roc_nix_sq_fini (&ctq->sq);
      if (rrv)
	cnxk_roc_err (dev, rrv, "roc_nix_sq_fini() failed");
      ctq->sq_initialized = 0;
    }
}

static vnet_dev_rv_t
cnxk_txq_init (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  cnxk_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
  vnet_dev_t *dev = txq->port->dev;
  cnxk_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;
  int rrv;

  ctq->sq = (struct roc_nix_sq){
    .nb_desc = txq->size,
    .qid = txq->queue_id,
    .max_sqe_sz = NIX_MAXSQESZ_W8,
  };

  rrv = roc_nix_sq_init (nix, &ctq->sq);
  if (rrv)
    return cnxk_roc_err (
      dev, rrv,
      "roc_nix_sq_init(qid = %u, nb_desc = %u, max_sqe_sz = %u) failed",
      ctq->sq.nb_desc, ctq->sq.max_sqe_sz);
  log_debug (dev, "SQ initialsed, qid - %u, nb_desc = %u, max_sqe_sz = %u",
	     ctq->sq.qid, ctq->sq.nb_desc, ctq->sq.max_sqe_sz);

  return VNET_DEV_OK;
}

vnet_dev_rv_t
cnxk_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  cnxk_device_t *cd = vnet_dev_get_data (dev);
  cnxk_port_t *cp = vnet_dev_get_port_data (port);
  struct roc_nix *nix = cd->nix;
  vnet_dev_rv_t rv;
  int rrv;

  log_debug (dev, "port init: port %u", port->port_id);

  vnet_dev_dma_mem_alloc (vm, dev, 16384, 2048, &cd->buffer);
  memset (cd->buffer, 0, 16384);

  rrv = roc_nix_lf_alloc (nix, port->intf.num_rx_queues,
			  port->intf.num_tx_queues, rxq_cfg);
  if (rrv)
    return cnxk_roc_err (
      dev, rrv,
      "roc_nix_lf_alloc(nb_rxq = %u, nb_txq = %d, rxq_cfg=0x%lx) failed",
      port->intf.num_rx_queues, port->intf.num_tx_queues, rxq_cfg);

  rrv = roc_nix_tm_init (nix);
  if (rrv)
    return cnxk_roc_err (dev, rrv, "roc_nix_tm_init() failed");

  rrv =
    roc_nix_tm_hierarchy_enable (nix, ROC_NIX_TM_DEFAULT, /* xmit_enable*/ 0);
  if (rrv)
    return cnxk_roc_err (dev, rrv, "roc_nix_tm_hierarchy_enable() failed");

  roc_nix_rss_key_set (nix, default_rss_key);

  cp->npc.roc_nix = nix;
  rrv = roc_npc_init (&cp->npc);
  if (rrv)
    return cnxk_roc_err (dev, rrv, "roc_nix_tm_init() failed");

  foreach_vnet_dev_port_rx_queue (q, port)
    if (q->enabled)
      if ((rv = cnxk_rxq_init (vm, q)))
	goto done;

  foreach_vnet_dev_port_tx_queue (q, port)
    if (q->enabled)
      if ((rv = cnxk_txq_init (vm, q)))
	goto done;

done:
  roc_npa_dump ();
  if (rv != VNET_DEV_OK)
    {
      foreach_vnet_dev_port_rx_queue (q, port)
	cnxk_rxq_deinit (vm, q);
      foreach_vnet_dev_port_tx_queue (q, port)
	cnxk_txq_deinit (vm, q);
    }

  return VNET_DEV_OK;
}

vnet_dev_rv_t
cnxk_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  cnxk_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;
  log_debug (port->dev, "port start: port %u", port->port_id);
  int rrv;

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      cnxk_rxq_t *crq = vnet_dev_get_rx_queue_data (q);
      for (int i = 0; i < 4; i++)
	roc_npa_aura_op_free (crq->aura_handle, 0,
			      (u64) cd->buffer + (q->queue_id + 4 * i) * 2048);
      log_notice (dev, "Q %u AVAIL %u", q->queue_id,
		  roc_npa_aura_op_available (crq->aura_handle));
      roc_nix_rq_ena_dis (&crq->rq, 1);
      log_notice (dev, "Q %u AVAIL %u", q->queue_id,
		  roc_npa_aura_op_available (crq->aura_handle));
    }

  rrv = roc_nix_npc_rx_ena_dis (nix, true);
  if (rrv)
    return cnxk_roc_err (dev, rrv, "roc_nix_npc_rx_ena_dis() failed");

  rrv = roc_nix_npc_rx_ena_dis (nix, true);
  if (rrv)
    return cnxk_roc_err (dev, rrv, "roc_nix_npc_rx_ena_dis() failed");

#if 0
  roc_npa_aura_op_free (aura_handle, 0, (u64) cd->buffer);
  log_notice (dev, "FREE %p", cd->buffer);
  roc_npa_aura_op_free (aura_handle, 0, (u64) cd->buffer + 2048);
  roc_npa_aura_op_free (aura_handle, 0, (u64) cd->buffer + 4096);
  log_notice (dev, "AVAIL %u", roc_npa_aura_op_available (aura_handle));
  log_notice (dev, "ALLOC %p", roc_npa_aura_op_alloc (aura_handle, 0));
  log_notice (dev, "ALLOC %p", roc_npa_aura_op_alloc (aura_handle, 0));
  log_notice (dev, "ALLOC %p", roc_npa_aura_op_alloc (aura_handle, 0));
  log_notice (dev, "AVAIL %u", roc_npa_aura_op_available (aura_handle));
  log_notice (dev, "%U", format_hexdump_u64, cd->buffer, 64);
#endif

  return VNET_DEV_OK;
}

void
cnxk_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  log_debug (port->dev, "port stop: port %u", port->port_id);
}

vnet_dev_rv_t
cnxk_port_cfg_change_validate (vlib_main_t *vm, vnet_dev_port_t *port,
			       vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;

  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_MAX_FRAME_SIZE:
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
cnxk_port_cfg_change (vlib_main_t *vm, vnet_dev_port_t *port,
		      vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;

  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_PROMISC_MODE:
      {
      }
      break;

    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
      break;

    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
      break;

    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
      break;

    case VNET_DEV_PORT_CFG_MAX_FRAME_SIZE:
      break;

    default:
      return VNET_DEV_ERR_NOT_SUPPORTED;
    };

  return rv;
}
