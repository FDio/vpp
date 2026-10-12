/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <qppe.h>

VLIB_REGISTER_LOG_CLASS (qppe_log, static) = {
  .class_name = "qppe",
  .subclass_name = "port",
};

vnet_dev_rv_t
qppe_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  qppe_port_t *qp = vnet_dev_get_port_data (port);

  log_debug (port->dev, "port %u label %s phy-mode %s managed %s", qp->id,
	     qp->label ? qp->label : "(none)", qp->phy_mode ? qp->phy_mode : "(unspecified)",
	     qp->managed ? qp->managed : "(unspecified)");

  return VNET_DEV_OK;
}

void
qppe_port_deinit (vlib_main_t *vm, vnet_dev_port_t *port)
{
  qppe_port_t *qp = vnet_dev_get_port_data (port);

  log_debug (port->dev, "port %u label %s", qp->id, qp->label ? qp->label : "(none)");
}

vnet_dev_rv_t
qppe_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  qppe_port_t *qp = vnet_dev_get_port_data (port);

  log_debug (port->dev, "starting port %u label %s", qp->id, qp->label ? qp->label : "(none)");

  log_warn (port->dev,
	    "port %u cannot start: PPE port hardware and packet queues are "
	    "not initialized",
	    port->port_id);

  return VNET_DEV_ERR_NOT_SUPPORTED;
}

void
qppe_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  qppe_port_t *qp = vnet_dev_get_port_data (port);

  log_debug (port->dev, "stopping port %u label %s", qp->id, qp->label ? qp->label : "(none)");
}
