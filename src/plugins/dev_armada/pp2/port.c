/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/dev/bus/platform.h>
#include <vppinfra/ring.h>
#include <dev_armada/musdk.h>
#include <dev_armada/pp2/pp2.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "pp2-port",
};

vnet_dev_rv_t
mvpp2_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv = VNET_DEV_OK;
  struct pp2_ppio_link_info li;
  char match[16];
  int mrv;

  log_debug (port->dev, "");

  snprintf (match, sizeof (match), "ppio-%d:%d", md->pp_id, port->port_id);

  struct pp2_ppio_params ppio_params = {
    .match = match,
    .type = PP2_PPIO_T_NIC,
    .eth_start_hdr = mp->is_dsa ? PP2_PPIO_HDR_ETH_DSA : PP2_PPIO_HDR_ETH,
    .inqs_params = {
      .num_tcs = 1,
      .tcs_params[0] = {
        .pkt_offset = 0,
	.num_in_qs = 1,
	.inqs_params = &(struct pp2_ppio_inq_params) { .size = 512 },
	.pools[0][0] = md->thread[0].bpool,
      },
    },
  };

  foreach_vnet_dev_port_tx_queue (q, port)
    {
      struct pp2_ppio_outqs_params *oqs = &ppio_params.outqs_params;
      oqs->outqs_params[q->queue_id].weight = 1;
      oqs->outqs_params[q->queue_id].size = q->size;
      oqs->num_outqs++;
    }

  mrv = pp2_ppio_init (&ppio_params, &mp->ppio);
  if (mrv)
    {
      rv = VNET_DEV_ERR_INIT_FAILED;
      log_err (dev, "port %u ppio '%s' init failed, rv %d", port->port_id,
	       match, mrv);
      goto done;
    }
  log_debug (dev, "port %u ppio '%s' init ok", port->port_id, match);

  mrv = pp2_ppio_get_link_info (mp->ppio, &li);
  if (mrv)
    {
      rv = VNET_DEV_ERR_INIT_FAILED;
      log_err (dev, "failed to get link info for port %u, rv %d",
	       port->port_id, mrv);
      goto done;
    }

  log_debug (dev, "port %u %U", port->port_id, format_pp2_ppio_link_info, &li);

  mvpp2_port_add_counters (vm, port);

done:
  if (rv != VNET_DEV_OK)
    mvpp2_port_stop (vm, port);
  return rv;
}

void
mvpp2_port_deinit (vlib_main_t *vm, vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);

  log_debug (port->dev, "");

  if (mp->ppio)
    {
      pp2_ppio_deinit (mp->ppio);
      mp->ppio = 0;
    }
}

void
mvpp2_port_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  vnet_dev_t *dev = port->dev;
  vnet_dev_port_state_changes_t changes = {};
  struct pp2_ppio_link_info li;
  int mrv;

  mrv = pp2_ppio_get_link_info (mp->ppio, &li);

  if (mrv)
    {
      log_debug (dev, "pp2_ppio_get_link_info: failed, rv %d", mrv);
      return;
    }

  if (mp->last_link_info.up != li.up)
    {
      changes.change.link_state = 1;
      changes.link_state = li.up != 0;
      log_debug (dev, "link state changed to %u", changes.link_state);
    }

  if (mp->last_link_info.duplex != li.duplex)
    {
      changes.change.link_duplex = 1;
      changes.full_duplex = li.duplex != 0;
      log_debug (dev, "link full duplex changed to %u", changes.full_duplex);
    }

  if (mp->last_link_info.speed != li.speed)
    {
      u32 speeds[] = {
	[MV_NET_LINK_SPEED_AN] = 0,
	[MV_NET_LINK_SPEED_10] = 10000,
	[MV_NET_LINK_SPEED_100] = 100000,
	[MV_NET_LINK_SPEED_1000] = 1000000,
	[MV_NET_LINK_SPEED_2500] = 2500000,
	[MV_NET_LINK_SPEED_10000] = 10000000,
      };

      if (li.speed < ARRAY_LEN (speeds))
	{
	  changes.change.link_speed = 1;
	  changes.link_speed = speeds[li.speed];
	  log_debug (dev, "link speed changed to %u", changes.link_speed);
	}
    }

  if (changes.change.any)
    {
      mp->last_link_info = li;
      vnet_dev_port_state_change (vm, port, changes);
    }

  mvpp2_port_get_stats (vm, port);
}

vnet_dev_rv_t
mvpp2_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int mrv;

  log_debug (port->dev, "");

  mrv = pp2_ppio_enable (mp->ppio);
  if (mrv)
    {
      log_err (port->dev, "pp2_ppio_enable() failed, rv %d", mrv);
      return VNET_DEV_ERR_NOT_READY;
    }

  mp->is_enabled = 1;

  vnet_dev_poll_port_add (vm, port, 0.5, mvpp2_port_poll);

  return VNET_DEV_OK;
}

void
mvpp2_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  int rv;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);

  log_debug (port->dev, "");

  if (mp->is_enabled)
    {
      vnet_dev_poll_port_remove (vm, port, mvpp2_port_poll);

      rv = pp2_ppio_disable (mp->ppio);
      if (rv)
	log_err (port->dev, "pp2_ppio_disable() failed, rv %d", rv);

      vnet_dev_port_state_change (vm, port,
				  (vnet_dev_port_state_changes_t){
				    .change.link_state = 1,
				    .change.link_speed = 1,
				    .link_speed = 0,
				    .link_state = 0,
				  });
      mp->is_enabled = 0;
    }
}

vnet_dev_rv_t
mvpp2_port_cfg_change_validate (vlib_main_t *vm, vnet_dev_port_t *port,
				vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;

  switch (req->type)
    {
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
mvpp2_port_cfg_change (vlib_main_t *vm, vnet_dev_port_t *port,
		       vnet_dev_port_cfg_change_req_t *req)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv = VNET_DEV_OK;
  eth_addr_t addr;
  int mrv;

  switch (req->type)
    {

    case VNET_DEV_PORT_CFG_PROMISC_MODE:
      mrv = pp2_ppio_set_promisc (mp->ppio, req->promisc);
      if (mrv)
	{
	  log_err (port->dev, "pp2_ppio_set_promisc: failed, rv %d", mrv);
	  rv = VNET_DEV_ERR_INTERNAL;
	}
      else
	log_debug (port->dev, "pp2_ppio_set_promisc: promisc %u",
		   req->promisc);
      break;

    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
      clib_memcpy (&addr, req->addr.eth_mac, sizeof (addr));
      mrv = pp2_ppio_set_mac_addr (mp->ppio, addr);
      if (mrv)
	{
	  log_err (port->dev, "pp2_ppio_set_mac_addr: failed, rv %d", mrv);
	  rv = VNET_DEV_ERR_INTERNAL;
	}
      else
	log_debug (port->dev, "pp2_ppio_set_mac_addr: %U added",
		   format_ethernet_address, &addr);
      break;

    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
      clib_memcpy (&addr, req->addr.eth_mac, sizeof (addr));
      mrv = pp2_ppio_add_mac_addr (mp->ppio, addr);
      if (mrv)
	{
	  log_err (port->dev, "pp2_ppio_add_mac_addr: failed, rv %d", mrv);
	  rv = VNET_DEV_ERR_INTERNAL;
	}
      else
	log_debug (port->dev, "pp2_ppio_add_mac_addr: %U added",
		   format_ethernet_address, &addr);
      break;

    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
      clib_memcpy (&addr, req->addr.eth_mac, sizeof (addr));
      mrv = pp2_ppio_remove_mac_addr (mp->ppio, addr);
      if (mrv)
	{
	  log_err (port->dev, "pp2_ppio_remove_mac_addr: failed, rv %d", mrv);
	  rv = VNET_DEV_ERR_INTERNAL;
	}
      else
	log_debug (port->dev, "pp2_ppio_remove_mac_addr: %U added",
		   format_ethernet_address, &addr);
      break;

    default:
      return VNET_DEV_ERR_NOT_SUPPORTED;
    };

  return rv;
}
