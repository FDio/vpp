/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/pci.h>
#include <vnet/dev/counters.h>
#include <dev_cnxk/cnxk.h>
#include <dev_cnxk/common.h>
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

static vnet_dev_rv_t
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

  if ((rrv = roc_nix_lf_alloc (nix, port->intf.num_rx_queues,
			       port->intf.num_tx_queues, rxq_cfg)))
    {
      cnxk_port_deinit (vm, port);
      return cnxk_roc_err (
	dev, rrv,
	"roc_nix_lf_alloc(nb_rxq = %u, nb_txq = %d, rxq_cfg=0x%lx) failed",
	port->intf.num_rx_queues, port->intf.num_tx_queues, rxq_cfg);
    }
  cp->lf_allocated = 1;

  if ((rrv = roc_nix_tm_init (nix)))
    {
      cnxk_port_deinit (vm, port);
      return cnxk_roc_err (dev, rrv, "roc_nix_tm_init() failed");
    }
  cp->tm_initialized = 1;

  if ((rrv = roc_nix_tm_hierarchy_enable (nix, ROC_NIX_TM_DEFAULT,
					  /* xmit_enable */ 0)))
    {
      cnxk_port_deinit (vm, port);
      return cnxk_roc_err (dev, rrv, "roc_nix_tm_hierarchy_enable() failed");
    }

  roc_nix_rss_key_set (nix, default_rss_key);

  cp->npc.roc_nix = nix;
  if ((rrv = roc_npc_init (&cp->npc)))
    {
      cnxk_port_deinit (vm, port);
      return cnxk_roc_err (dev, rrv, "roc_npc_init() failed");
    }
  cp->npc_initialized = 1;

  foreach_vnet_dev_port_rx_queue (q, port)
    if (q->enabled)
      if ((rv = cnxk_rxq_init (vm, q)))
	{
	  cnxk_port_deinit (vm, port);
	  return rv;
	}

  foreach_vnet_dev_port_tx_queue (q, port)
    if (q->enabled)
      if ((rv = cnxk_txq_init (vm, q)))
	{
	  cnxk_port_deinit (vm, port);
	  return rv;
	}

  return VNET_DEV_OK;
}

void
cnxk_port_deinit (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  cnxk_device_t *cd = vnet_dev_get_data (dev);
  cnxk_port_t *cp = vnet_dev_get_port_data (port);
  struct roc_nix *nix = cd->nix;
  int rrv;

  foreach_vnet_dev_port_rx_queue (q, port)
    cnxk_rxq_deinit (vm, q);
  foreach_vnet_dev_port_tx_queue (q, port)
    cnxk_txq_deinit (vm, q);

  if (cp->npc_initialized)
    {
      if ((rrv = roc_npc_fini (&cp->npc)))
	cnxk_roc_err (dev, rrv, "roc_npc_fini() failed");
      cp->npc_initialized = 0;
    }

  if (cp->tm_initialized)
    {
      roc_nix_tm_fini (nix);
      cp->tm_initialized = 0;
    }

  if (cp->lf_allocated)
    {
      if ((rrv = roc_nix_lf_free (nix)))
	cnxk_roc_err (dev, rrv, "roc_nix_lf_free() failed");
      cp->lf_allocated = 0;
    }
}

void
cnxk_port_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  cnxk_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;
  struct roc_nix_link_info link_info = {};
  struct roc_nix_eeprom_info eeprom_info = {};
  vnet_dev_port_state_changes_t changes = {};
  int rrv;

  rrv = roc_nix_mac_link_info_get (nix, &link_info);
  if (rrv)
    return;

  if (cd->status != link_info.status)
    {
      changes.change.link_state = 1;
      changes.link_state = link_info.status;
      cd->status = link_info.status;
    }

  if (cd->full_duplex != link_info.full_duplex)
    {
      changes.change.link_duplex = 1;
      changes.full_duplex = link_info.full_duplex;
      cd->full_duplex = link_info.full_duplex;
    }

  if (cd->speed != link_info.speed)
    {
      changes.change.link_speed = 1;
      changes.link_speed = link_info.speed;
      cd->speed = link_info.speed;
    }

  if (changes.change.any == 0)
    return;

  log_debug (dev,
	     "status %u full_duplex %u speed %u port %u lmac_type_id %u "
	     "fec %u aautoneg %u",
	     link_info.status, link_info.full_duplex, link_info.speed,
	     link_info.port, link_info.lmac_type_id, link_info.fec,
	     link_info.autoneg);
  vnet_dev_port_state_change (vm, port, changes);

  if (roc_nix_eeprom_info_get (nix, &eeprom_info) == 0)
    {
      log_debug (dev, "sff_id %u data %U", eeprom_info.sff_id, format_hexdump,
		 eeprom_info.buf, sizeof (eeprom_info.buf));
    }
}

vnet_dev_rv_t
cnxk_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  cnxk_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;
  int rrv;

  log_debug (port->dev, "port start: port %u", port->port_id);

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      cnxk_rxq_t *crq = vnet_dev_get_rx_queue_data (q);
      u8 bpi = vnet_dev_get_rx_queue_buffer_pool_index (q);

      cnxk_aura_fill_with_buffers (vm, crq->aura_handle, bpi, q->size,
				   crq->hdr_off);
      if (roc_npa_aura_op_available (crq->aura_handle) != q->size)
	log_warn (dev, "rx queue %u buffer pool not filled completelly",
		  q->queue_id);
      roc_nix_rq_ena_dis (&crq->rq, 1);
    }

  rrv = roc_nix_npc_rx_ena_dis (nix, true);
  if (rrv)
    return cnxk_roc_err (dev, rrv, "roc_nix_npc_rx_ena_dis() failed");

  vnet_dev_poll_port_add (vm, port, 0.5, cnxk_port_poll);

  return VNET_DEV_OK;
}

void
cnxk_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  cnxk_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;
  int rrv;

  log_debug (port->dev, "port stop: port %u", port->port_id);

  vnet_dev_poll_port_remove (vm, port, cnxk_port_poll);

  rrv = roc_nix_npc_rx_ena_dis (nix, false);
  if (rrv)
    {
      cnxk_roc_err (dev, rrv, "roc_nix_npc_rx_ena_dis() failed");
      return;
    }

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      cnxk_rxq_t *crq = vnet_dev_get_rx_queue_data (q);
      u32 n, avail;

      roc_nix_rq_ena_dis (&crq->rq, 0);
      avail = roc_npa_aura_op_available (crq->aura_handle);
      n = cnxk_aura_free_buffers (vm, crq->aura_handle, avail, crq->hdr_off);

      log_debug (dev, "%u buffers freed from rx queue %u (avail %u)", n,
		 q->queue_id, avail);
    }

  foreach_vnet_dev_port_tx_queue (q, port)
    {
      cnxk_txq_t *ctq = vnet_dev_get_tx_queue_data (q);
      u32 n, avail;

      avail = roc_npa_aura_op_available (ctq->aura_handle);
      if (avail)
	{
	  n =
	    cnxk_aura_free_buffers (vm, ctq->aura_handle, avail, ctq->hdr_off);

	  log_debug (dev, "%u buffers freed from tx queue %u (avail %u)", n,
		     q->queue_id, avail);
	}
    }
}

vnet_dev_rv_t
cnxk_port_cfg_change_precheck (vlib_main_t *vm, vnet_dev_port_t *port,
			       vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;

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

    case VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE:
      break;

    default:
      return VNET_DEV_ERR_NOT_SUPPORTED;
    };

  return rv;
}
