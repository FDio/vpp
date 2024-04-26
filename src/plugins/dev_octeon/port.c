/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/pci.h>
#include <vnet/dev/counters.h>
#include <dev_octeon/octeon.h>
#include <dev_octeon/common.h>
#include <vnet/ethernet/ethernet.h>

#define OCT_FLOW_PREALLOC_SIZE	1
#define OCT_FLOW_MAX_PRIORITY	7
#define OCT_ETH_LINK_SPEED_100G 100000 /**< 100 Gbps */

VLIB_REGISTER_LOG_CLASS (oct_log, static) = {
  .class_name = "octeon",
  .subclass_name = "port",
};

static const u8 default_rss_key[] = {
  0xfe, 0xed, 0x0b, 0xad, 0xfe, 0xed, 0x0b, 0xad, 0xad, 0x0b, 0xed, 0xfe,
  0xad, 0x0b, 0xed, 0xfe, 0x13, 0x57, 0x9b, 0xef, 0x24, 0x68, 0xac, 0x0e,
  0x91, 0x72, 0x53, 0x11, 0x82, 0x64, 0x20, 0x44, 0x12, 0xef, 0x34, 0xcd,
  0x56, 0xbc, 0x78, 0x9a, 0x9a, 0x78, 0xbc, 0x56, 0xcd, 0x34, 0xef, 0x12
};

static const u32 default_rss_flowkey =
  (FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6 | FLOW_KEY_TYPE_TCP |
   FLOW_KEY_TYPE_UDP | FLOW_KEY_TYPE_SCTP);

static const u64 rxq_cfg =
  ROC_NIX_LF_RX_CFG_DIS_APAD | ROC_NIX_LF_RX_CFG_IP6_UDP_OPT |
  ROC_NIX_LF_RX_CFG_L2_LEN_ERR | ROC_NIX_LF_RX_CFG_DROP_RE |
  ROC_NIX_LF_RX_CFG_CSUM_OL4 | ROC_NIX_LF_RX_CFG_CSUM_IL4 |
  ROC_NIX_LF_RX_CFG_LEN_OL3 | ROC_NIX_LF_RX_CFG_LEN_OL4 |
  ROC_NIX_LF_RX_CFG_LEN_IL3 | ROC_NIX_LF_RX_CFG_LEN_IL4;

static vnet_dev_rv_t
oct_roc_err (vnet_dev_t *dev, int rv, char *fmt, ...)
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
oct_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  oct_port_t *cp = vnet_dev_get_port_data (port);
  struct roc_nix *nix = cd->nix;
  vnet_dev_rv_t rv;
  int rrv;

  log_debug (dev, "port init: port %u", port->port_id);

  if ((rrv = roc_nix_lf_alloc (nix, port->intf.num_rx_queues,
			       port->intf.num_tx_queues, rxq_cfg)))
    {
      oct_port_deinit (vm, port);
      return oct_roc_err (
	dev, rrv,
	"roc_nix_lf_alloc(nb_rxq = %u, nb_txq = %d, rxq_cfg=0x%lx) failed",
	port->intf.num_rx_queues, port->intf.num_tx_queues, rxq_cfg);
    }
  cp->lf_allocated = 1;

  if ((rrv = roc_nix_tm_init (nix)))
    {
      oct_port_deinit (vm, port);
      return oct_roc_err (dev, rrv, "roc_nix_tm_init() failed");
    }
  cp->tm_initialized = 1;

  if ((rrv = roc_nix_tm_hierarchy_enable (nix, ROC_NIX_TM_DEFAULT,
					  /* xmit_enable */ 0)))
    {
      oct_port_deinit (vm, port);
      return oct_roc_err (dev, rrv, "roc_nix_tm_hierarchy_enable() failed");
    }

  if ((rrv = roc_nix_rss_default_setup (nix, default_rss_flowkey)))
    {
      oct_port_deinit (vm, port);
      return oct_roc_err (dev, rrv, "roc_nix_rss_default_setup() failed");
    }

  roc_nix_rss_key_set (nix, default_rss_key);

  cp->npc.roc_nix = nix;
  cp->npc.flow_prealloc_size = OCT_FLOW_PREALLOC_SIZE;
  cp->npc.flow_max_priority = OCT_FLOW_MAX_PRIORITY;
  if ((rrv = roc_npc_init (&cp->npc)))
    {
      oct_port_deinit (vm, port);
      return oct_roc_err (dev, rrv, "roc_npc_init() failed");
    }
  cp->npc_initialized = 1;

  foreach_vnet_dev_port_rx_queue (q, port)
    if (q->enabled)
      if ((rv = oct_rxq_init (vm, q)))
	{
	  oct_port_deinit (vm, port);
	  return rv;
	}

  foreach_vnet_dev_port_tx_queue (q, port)
    if (q->enabled)
      if ((rv = oct_txq_init (vm, q)))
	{
	  oct_port_deinit (vm, port);
	  return rv;
	}

  return VNET_DEV_OK;
}

void
oct_port_deinit (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  oct_port_t *cp = vnet_dev_get_port_data (port);
  struct roc_nix *nix = cd->nix;
  int rrv;

  foreach_vnet_dev_port_rx_queue (q, port)
    oct_rxq_deinit (vm, q);
  foreach_vnet_dev_port_tx_queue (q, port)
    oct_txq_deinit (vm, q);

  if (cp->npc_initialized)
    {
      if ((rrv = roc_npc_fini (&cp->npc)))
	oct_roc_err (dev, rrv, "roc_npc_fini() failed");
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
	oct_roc_err (dev, rrv, "roc_nix_lf_free() failed");
      cp->lf_allocated = 0;
    }
}

void
oct_port_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;
  struct roc_nix_link_info link_info = {};
  vnet_dev_port_state_changes_t changes = {};
  int rrv;

  if (roc_nix_is_lbk (nix))
    {
      link_info.status = 1;
      link_info.full_duplex = 1;
      link_info.autoneg = 0;
      link_info.speed = OCT_ETH_LINK_SPEED_100G;
    }
  else
    {
      rrv = roc_nix_mac_link_info_get (nix, &link_info);
      if (rrv)
	return;
    }

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
}

vnet_dev_rv_t
oct_rxq_start (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  oct_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);
  u32 buffer_indices[rxq->size], n_alloc;
  u8 bpi = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  int rrv;

  n_alloc = vlib_buffer_alloc_from_pool (vm, buffer_indices, rxq->size, bpi);

  for (int i = 0; i < n_alloc; i++)
    roc_npa_aura_op_free (
      crq->aura_handle, 0,
      pointer_to_uword (vlib_get_buffer (vm, buffer_indices[i])) -
	crq->hdr_off);

  crq->n_enq = n_alloc;

  if (roc_npa_aura_op_available (crq->aura_handle) != rxq->size)
    log_warn (rxq->port->dev, "rx queue %u aura not filled completelly",
	      rxq->queue_id);

  if ((rrv = roc_nix_rq_ena_dis (&crq->rq, 1)))
    return oct_roc_err (dev, rrv, "roc_nix_rq_ena_dis() failed");

  return VNET_DEV_OK;
}
void
oct_rxq_stop (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  oct_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);
  int rrv;
  u32 n;

  if ((rrv = roc_nix_rq_ena_dis (&crq->rq, 0)))
    oct_roc_err (dev, rrv, "roc_nix_rq_ena_dis() failed");

  n = oct_aura_free_all_buffers (vm, crq->aura_handle, crq->hdr_off);

  if (crq->n_enq - n > 0)
    log_err (dev, "%u buffers leaked on rx queue %u stop", crq->n_enq - n,
	     rxq->queue_id);
  else
    log_debug (dev, "%u buffers freed from rx queue %u", n, rxq->queue_id);

  crq->n_enq = 0;
}

void
oct_txq_stop (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  oct_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
  oct_npa_batch_alloc_cl128_t *cl;
  u32 n, off = ctq->hdr_off;

  n = oct_aura_free_all_buffers (vm, ctq->aura_handle, off);
  ctq->n_enq -= n;

  if (ctq->n_enq > 0 && ctq->ba_num_cl > 0)
    for (n = ctq->ba_num_cl, cl = ctq->ba_buffer + ctq->ba_first_cl; n;
	 cl++, n--)
      {
	oct_npa_batch_alloc_status_t st;

	st.as_u64 = __atomic_load_n (cl->iova, __ATOMIC_ACQUIRE);
	if (st.status.ccode != ALLOC_CCODE_INVAL)
	  for (u32 i = 0; i < st.status.count; i++)
	    {
	      vlib_buffer_t *b = (vlib_buffer_t *) (cl->iova[i] + off);
	      vlib_buffer_free_one (vm, vlib_get_buffer_index (vm, b));
	      ctq->n_enq--;
	    }
      }

  if (ctq->n_enq > 0)
    log_err (dev, "%u buffers leaked on tx queue %u stop", ctq->n_enq,
	     txq->queue_id);
  else
    log_debug (dev, "%u buffers freed from tx queue %u", n, txq->queue_id);

  ctq->n_enq = 0;
}

vnet_dev_rv_t
oct_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;
  struct roc_nix_eeprom_info eeprom_info = {};
  vnet_dev_rv_t rv;
  int rrv;

  log_debug (port->dev, "port start: port %u", port->port_id);

  foreach_vnet_dev_port_rx_queue (q, port)
    if ((rv = oct_rxq_start (vm, q)) != VNET_DEV_OK)
      goto done;

  foreach_vnet_dev_port_tx_queue (q, port)
    {
      oct_txq_t *ctq = vnet_dev_get_tx_queue_data (q);
      ctq->n_enq = 0;
    }

  if ((rrv = roc_nix_mac_mtu_set (nix, 9200)))
    {
      rv = oct_roc_err (dev, rrv, "roc_nix_mac_mtu_set() failed");
      goto done;
    }

  if ((rrv = roc_nix_npc_rx_ena_dis (nix, true)))
    {
      rv = oct_roc_err (dev, rrv, "roc_nix_npc_rx_ena_dis() failed");
      goto done;
    }

  vnet_dev_poll_port_add (vm, port, 0.5, oct_port_poll);

  if (roc_nix_eeprom_info_get (nix, &eeprom_info) == 0)
    {
      log_debug (dev, "sff_id %u data %U", eeprom_info.sff_id, format_hexdump,
		 eeprom_info.buf, sizeof (eeprom_info.buf));
    }
done:
  if (rv != VNET_DEV_OK)
    oct_port_stop (vm, port);
  return VNET_DEV_OK;
}

void
oct_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;
  int rrv;

  log_debug (port->dev, "port stop: port %u", port->port_id);

  vnet_dev_poll_port_remove (vm, port, oct_port_poll);

  rrv = roc_nix_npc_rx_ena_dis (nix, false);
  if (rrv)
    {
      oct_roc_err (dev, rrv, "roc_nix_npc_rx_ena_dis() failed");
      return;
    }

  foreach_vnet_dev_port_rx_queue (q, port)
    oct_rxq_stop (vm, q);

  foreach_vnet_dev_port_tx_queue (q, port)
    oct_txq_stop (vm, q);
}

vnet_dev_rv_t
oct_validate_config_promisc_mode (vnet_dev_port_t *port, int enable)
{
  vnet_dev_t *dev = port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;

  if (roc_nix_is_vf_or_sdp (nix))
    return VNET_DEV_ERR_UNSUPPORTED_DEVICE;

  return VNET_DEV_OK;
}

vnet_dev_rv_t
oct_op_config_promisc_mode (vlib_main_t *vm, vnet_dev_port_t *port, int enable)
{
  vnet_dev_t *dev = port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;
  int rv;

  rv = roc_nix_npc_promisc_ena_dis (nix, enable);
  if (rv)
    {
      return oct_roc_err (dev, rv, "roc_nix_npc_promisc_ena_dis failed");
    }

  rv = roc_nix_mac_promisc_mode_enable (nix, enable);
  if (rv)
    {
      return oct_roc_err (dev, rv,
			  "roc_nix_mac_promisc_mode_enable(%s) failed",
			  enable ? "true" : "false");
    }

  return VNET_DEV_OK;
}

static vnet_dev_rv_t
oct_port_add_del_eth_addr (vlib_main_t *vm, vnet_dev_port_t *port,
			   vnet_dev_hw_addr_t *addr, int is_add,
			   int is_primary)
{
  vnet_dev_t *dev = port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  i32 rrv;

  if (is_primary)
    {
      if (is_add)
	{
	  /* Update mac address at NPC */
	  rrv = roc_nix_npc_mac_addr_set (nix, (u8 *) addr);
	  if (rrv)
	    rv = oct_roc_err (dev, rrv, "roc_nix_npc_mac_addr_set() failed");

	  /* Update mac address at CGX for PFs only */
	  if (!roc_nix_is_vf_or_sdp (nix))
	    {
	      rrv = roc_nix_mac_addr_set (nix, (u8 *) addr);
	      if (rrv)
		{
		  /* Rollback to previous mac address */
		  roc_nix_npc_mac_addr_set (nix,
					    (u8 *) &port->primary_hw_addr);
		  rv = oct_roc_err (dev, rrv, "roc_nix_mac_addr_set() failed");
		}
	    }
	}
    }
  return rv;
}

vnet_dev_rv_t
oct_port_cfg_change_validate (vlib_main_t *vm, vnet_dev_port_t *port,
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
      rv = oct_validate_config_promisc_mode (port, req->promisc);
      break;
    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
      break;

    case VNET_DEV_PORT_CFG_ADD_RX_FLOW:
    case VNET_DEV_PORT_CFG_DEL_RX_FLOW:
    case VNET_DEV_PORT_CFG_GET_RX_FLOW_COUNTER:
    case VNET_DEV_PORT_CFG_RESET_RX_FLOW_COUNTER:
      rv = oct_flow_validate_params (vm, port, req->type, req->flow_index,
				     req->private_data);
      break;

    default:
      rv = VNET_DEV_ERR_NOT_SUPPORTED;
    };

  return rv;
}

vnet_dev_rv_t
oct_port_cfg_change (vlib_main_t *vm, vnet_dev_port_t *port,
		     vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;

  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_PROMISC_MODE:
      rv = oct_op_config_promisc_mode (vm, port, req->promisc);
      break;

    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
      rv = oct_port_add_del_eth_addr (vm, port, &req->addr,
				      /* is_add */ 1,
				      /* is_primary */ 1);
      break;

    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
      break;

    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
      break;

    case VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE:
      break;

    case VNET_DEV_PORT_CFG_ADD_RX_FLOW:
    case VNET_DEV_PORT_CFG_DEL_RX_FLOW:
    case VNET_DEV_PORT_CFG_GET_RX_FLOW_COUNTER:
    case VNET_DEV_PORT_CFG_RESET_RX_FLOW_COUNTER:
      rv = oct_flow_ops_fn (vm, port, req->type, req->flow_index,
			    req->private_data);

      break;

    default:
      return VNET_DEV_ERR_NOT_SUPPORTED;
    };

  return rv;
}
