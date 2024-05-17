/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
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
  // vnet_dev_bus_platform_device_data_t *d = vnet_dev_get_bus_data (dev);
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  struct pp2_ppio_link_info li;
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

  snprintf (match, sizeof (match), "ppio-%d:%d", md->pp_id, port->port_id);

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

  if (pp2_ppio_get_link_info (mp->ppio, &li))
    {
      rv = VNET_DEV_ERR_INIT_FAILED;
      log_err (dev, "failed to get link info for port %u", port->port_id);
      goto done;
    }

  log_debug (dev, "port %u %U", port->port_id, format_pp2_ppio_link_info, &li);

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
