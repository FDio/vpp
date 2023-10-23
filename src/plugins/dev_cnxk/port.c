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
  .class_name = "cnkx",
  .subclass_name = "port",
};

vnet_dev_rv_t
cnxk_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;

  log_debug (dev, "port init: port %u", port->port_id);

  return VNET_DEV_OK;
}

vnet_dev_rv_t
cnxk_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  log_debug (port->dev, "port start: port %u", port->port_id);

  return VNET_DEV_OK;
}

void
cnxk_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  log_debug (port->dev, "port stop: port %u", port->port_id);
}

vnet_dev_rv_t
cnxk_port_cfg_change_precheck (vlib_main_t *vm, vnet_dev_port_t *port,
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
