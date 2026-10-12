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
  vnet_dev_rv_t rv;

  log_debug (port->dev, "port %u label %s phy-mode %s managed %s", port->port_id,
	     qp->label ? qp->label : "(none)", qp->phy_mode ? qp->phy_mode : "(unspecified)",
	     qp->managed ? qp->managed : "(unspecified)");
  rv = qppe_port_counters_init (vm, port);
  if (rv != VNET_DEV_OK)
    return rv;

  vnet_dev_poll_port_add (vm, port, 3, qppe_port_counters_poll);
  log_debug (port->dev, "port %u hardware counters initialized; polling every 3 seconds",
	     port->port_id);

  return rv;
}

void
qppe_port_deinit (vlib_main_t *vm, vnet_dev_port_t *port)
{
  qppe_port_t *qp = vnet_dev_get_port_data (port);

  vnet_dev_poll_port_remove (vm, port, qppe_port_counters_poll);
  log_debug (port->dev, "port %u label %s", port->port_id, qp->label ? qp->label : "(none)");
}

vnet_dev_rv_t
qppe_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  qppe_port_t *qp = vnet_dev_get_port_data (port);

  log_debug (port->dev, "starting port %u label %s", port->port_id,
	     qp->label ? qp->label : "(none)");

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

  log_debug (port->dev, "stopping port %u label %s", port->port_id,
	     qp->label ? qp->label : "(none)");
}
