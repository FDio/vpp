/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vppinfra/ring.h>
#include <dev_armada/musdk.h>
#include <dev_armada/bus.h>
#include <dev_armada/pp2.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "pp2-port",
};

vnet_dev_rv_t
mvpp2_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  vnet_dev_bus_armada_device_data_t *d = vnet_dev_get_bus_data (dev);
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  char match[16];
  vnet_dev_rv_t rv = VNET_DEV_OK;

  struct pp2_ppio_inq_params inq_params = {
    .size = 512,
  };

  struct pp2_ppio_params ppio_params = {
    .match = match,
    .type = PP2_PPIO_T_NIC,
    .inqs_params = {
      .num_tcs = 1,
      .tcs_params[0] = {
        .pkt_offset = 0,
	.num_in_qs = 1,
	.inqs_params = &inq_params,
	.pools[0][0] = md->bpool[0],
      },
    },
  };

  snprintf (match, sizeof (match), "ppio-%d:%d", d->pp_id, port->port_id);

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      struct pp2_ppio_outqs_params *oqs = &ppio_params.outqs_params;
      oqs->outqs_params[0].weight = 1;
      oqs->outqs_params[0].size = q->size;
      oqs->num_outqs++;
    }

  log_debug (port->dev, "init");

  if (pp2_ppio_init (&ppio_params, &mp->ppio))
    {
      rv = VNET_DEV_ERR_INIT_FAILED;
      log_err (dev, "port %u ppio '%s' init failed", port->port_id, match);
      goto done;
    }
  log_debug (dev, "port %u ppio '%s' init ok", port->port_id, match);

  struct pp2_ppio_link_info li;

  if (pp2_ppio_get_link_info (mp->ppio, &li))
    {
      rv = VNET_DEV_ERR_INIT_FAILED;
      log_err (dev, "failed to get link info for port %u", port->port_id);
      goto done;
    }

  char *port_duplex[] = {
    [MV_NET_LINK_DUPLEX_HALF] = "half",
    [MV_NET_LINK_DUPLEX_FULL] = "full",
  };

  u32 port_speeds[] = {
    [MV_NET_LINK_SPEED_10] = 10,       [MV_NET_LINK_SPEED_100] = 100,
    [MV_NET_LINK_SPEED_1000] = 1000,   [MV_NET_LINK_SPEED_2500] = 2500,
    [MV_NET_LINK_SPEED_10000] = 10000,
  };

  char *port_phy_modes[] = {
    [MV_NET_PHY_MODE_NONE] = "NONE",
    [MV_NET_PHY_MODE_MII] = "MII",
    [MV_NET_PHY_MODE_GMII] = "GMII",
    [MV_NET_PHY_MODE_SGMII] = "SGMII",
    [MV_NET_PHY_MODE_TBI] = "TBI",
    [MV_NET_PHY_MODE_REVMII] = "REVMII",
    [MV_NET_PHY_MODE_RMII] = "RMII",
    [MV_NET_PHY_MODE_RGMII] = "RGMII",
    [MV_NET_PHY_MODE_RGMII_ID] = "RGMII_ID",
    [MV_NET_PHY_MODE_RGMII_RXID] = "RGMII_RXID",
    [MV_NET_PHY_MODE_RGMII_TXID] = "RGMII_TXID",
    [MV_NET_PHY_MODE_RTBI] = "RTBI",
    [MV_NET_PHY_MODE_SMII] = "SMII",
    [MV_NET_PHY_MODE_XGMII] = "XGMII",
    [MV_NET_PHY_MODE_MOCA] = "MOCA",
    [MV_NET_PHY_MODE_QSGMII] = "QSGMII",
    [MV_NET_PHY_MODE_XAUI] = "XAUI",
    [MV_NET_PHY_MODE_RXAUI] = "RXAUI",
    [MV_NET_PHY_MODE_KR] = "KR",
  };

  log_debug (dev, "port %u duplex %s speed %d up %d phy_mode %s",
	     port->port_id, port_duplex[li.duplex], port_speeds[li.speed],
	     li.up, port_phy_modes[li.phy_mode]);

done:
  if (rv != VNET_DEV_OK)
    mvpp2_port_deinit (vm, port);
  return rv;
}

void
mvpp2_port_deinit (vlib_main_t *vm, vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);

  log_debug (port->dev, "deinit");

  if (mp->ppio)
    {
      pp2_ppio_deinit (mp->ppio);
      mp->ppio = 0;
    }
}

vnet_dev_rv_t
mvpp2_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  log_debug (port->dev, "start");
  return VNET_DEV_OK;
}

void
mvpp2_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  log_debug (port->dev, "stop");
}
