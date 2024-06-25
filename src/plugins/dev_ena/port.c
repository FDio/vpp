/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <dev_ena/ena.h>
#include <dev_ena/ena_inlines.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

VLIB_REGISTER_LOG_CLASS (ena_log, static) = {
  .class_name = "ena",
  .subclass_name = "port",
};

vnet_dev_rv_t
ena_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;

  log_debug (dev, "port %u", port->port_id);

  return VNET_DEV_OK;
}

vnet_dev_rv_t
ena_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  vnet_dev_rv_t rv;

  log_debug (dev, "port start: port %u", port->port_id);

  if (ena_aq_feature_is_supported (dev, ENA_ADMIN_FEAT_ID_MTU))
    {
      ena_aq_feat_mtu_t mtu = { .mtu = port->max_rx_frame_size };

      if ((rv = ena_aq_set_feature (vm, dev, ENA_ADMIN_FEAT_ID_MTU, &mtu)))
	return rv;
    }

  if ((rv = vnet_dev_port_start_all_rx_queues (vm, port)))
    return rv;

  if ((rv = vnet_dev_port_start_all_tx_queues (vm, port)))
    return rv;

  return VNET_DEV_OK;
}

void
ena_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  log_debug (port->dev, "port stop: port %u", port->port_id);
}

vnet_dev_rv_t
ena_port_cfg_change_validate (vlib_main_t *vm, vnet_dev_port_t *port,
			      vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;

  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE:
      if (port->started)
	rv = VNET_DEV_ERR_PORT_STARTED;
      break;

    default:
      rv = VNET_DEV_ERR_NOT_SUPPORTED;
    };

  return rv;
}

vnet_dev_rv_t
ena_port_cfg_change (vlib_main_t *vm, vnet_dev_port_t *port,
		     vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;

  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE:
      break;

    default:
      return VNET_DEV_ERR_NOT_SUPPORTED;
    };

  return rv;
}
