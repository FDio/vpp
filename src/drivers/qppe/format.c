/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <qppe.h>

u8 *
format_qppe_dev_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  vnet_dev_platform_clock_t *clock;
  vnet_dev_platform_reset_t *reset;
  vnet_dev_platform_interconnect_t *interconnect;
  vnet_dev_platform_phy_t *phy;
  u32 indent = format_get_indent (s);

  s = format (s, "platform device %s, device tree node %v", dev->device_id, qd->dt_path);
  s = format_newline (s, indent);
  s = format (s, "register window virtual %p", qd->regs);
  s = format_newline (s, indent);
  s = format (s, "PPE port mux control 0x%08x (XGMAC select 0x%02x, port 5 PCS1 %s)",
	      qd->hw_state.port_mux_control,
	      (qd->hw_state.port_mux_control & QPPE_PORT_MUX_XGMAC_SELECT_MASK) >> 8,
	      qd->hw_state.port_mux_control & QPPE_PORT_MUX_PORT5_PCS1_SELECT ? "selected" :
										"not selected");
  s = format_newline (s, indent);
  s = format (s, "BM shared group 0 config 0x%08x (shared buffer limit %u)",
	      qd->hw_state.bm_shared_group0_config,
	      qd->hw_state.bm_shared_group0_config & QPPE_BM_SHARED_GROUP_LIMIT_MASK);
  s = format_newline (s, indent);
  s = format (s, "EDMA version %u (0x%08x)", qd->hw_state.edma_version, qd->hw_state.edma_version);
  s = format_newline (s, indent);
  s = format (s, "%u configured ports", qd->n_ports);

  vec_foreach (clock, qd->clocks)
    {
      s = format_newline (s, indent);
      s = format (s, "Clock '%s'", clock->name);
    }

  vec_foreach (reset, qd->resets)
    {
      s = format_newline (s, indent);
      s = format (s, "Reset '%s'", reset->name);
    }

  vec_foreach (interconnect, qd->interconnects)
    {
      s = format_newline (s, indent);
      s = format (s, "Interconnect '%s'", interconnect->name);
    }

  vec_foreach (phy, qd->phys)
    {
      s = format_newline (s, indent);
      s = format (s, "PHY '%s'", phy->name);
    }

  foreach_vnet_dev_port (port, dev)
    {
      qppe_port_t *qp = vnet_dev_get_port_data (port);

      s = format_newline (s, indent);
      s = format (s,
		  "Port %u: label %s, PHY mode %s, managed %s, MAC %U, "
		  "GMAC enable 0x%08x (TX %s, RX %s), "
		  "%u RX queues (max %u), %u TX queues (max %u), max frame %u, link %s",
		  qp->id, qp->label ? qp->label : "(none)",
		  qp->phy_mode ? qp->phy_mode : "(unspecified)",
		  qp->managed ? qp->managed : "(unspecified)", format_vnet_dev_hw_addr,
		  &port->attr.hw_addr, qp->hw_state.gmac_enable,
		  qp->hw_state.gmac_enable & QPPE_GMAC_TX_ENABLE ? "enabled" : "disabled",
		  qp->hw_state.gmac_enable & QPPE_GMAC_RX_ENABLE ? "enabled" : "disabled",
		  pool_elts (port->rx_queues), port->attr.max_rx_queues,
		  pool_elts (port->tx_queues), port->attr.max_tx_queues,
		  port->attr.max_supported_rx_frame_size, port->link_up ? "up" : "down");
    }

  if (a->debug)
    {
      s = format_newline (s, indent);
      s = format (s, "hardware data path not initialized");
    }

  return s;
}

u8 *
format_qppe_port_status (u8 *s, va_list *args)
{
  vnet_dev_format_args_t __clib_unused *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  qppe_port_t *qp = vnet_dev_get_port_data (port);

  s = format (s, "port id %u", qp->id);
  if (qp->label)
    s = format (s, ", device tree label '%s'", qp->label);
  if (qp->phy_mode)
    s = format (s, ", PHY mode '%s'", qp->phy_mode);
  if (qp->managed)
    s = format (s, ", managed '%s'", qp->managed);

  return s;
}
