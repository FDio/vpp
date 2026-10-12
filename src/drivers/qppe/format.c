/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <qppe.h>

u8 *
format_ppe_edma_rx_metadata (u8 *s, va_list *args)
{
  const ppe_edma_rx_metadata_t *metadata = va_arg (*args, const ppe_edma_rx_metadata_t *);

  return format (s, "0x%08x (PID %u, L3 offset %u)", metadata->as_u32, metadata->fields.pid,
		 metadata->fields.l3_offset);
}

u8 *
format_qppe_dev_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 indent = format_get_indent (s);

  s = format (s, "platform device %s, device tree node %v", dev->device_id, qd->dt_path);
  s = format_newline (s, indent);
  s = format (s, "register window virtual %p", qd->regs);
  s = format_newline (s, indent);
  s =
    format (s, "PPE port mux control 0x%08x (XGMAC select 0x%02x, port 5 PCS1 %s)",
	    qd->hw_state.port_mux_control.as_u32, qd->hw_state.port_mux_control.fields.xgmac_select,
	    qd->hw_state.port_mux_control.fields.port5_pcs1_select ? "selected" : "not selected");
  s = format_newline (s, indent);
  s = format (s, "BM shared group 0 config 0x%08x (shared buffer limit %u)",
	      qd->hw_state.bm_shared_group0_config.as_u32,
	      qd->hw_state.bm_shared_group0_config.fields.shared_buffer_limit);
  s = format_newline (s, indent);
  s = format (s, "EDMA version %u (0x%08x)", qd->hw_state.edma_master_control.fields.version,
	      qd->hw_state.edma_master_control.as_u32);
  s = format_newline (s, indent);
  s = format (s, "EDMA port control 0x%08x (EDMA %s, TX padding %s)",
	      qd->hw_state.edma_port_control.as_u32,
	      qd->hw_state.edma_port_control.fields.edma_enable ? "enabled" : "disabled",
	      qd->hw_state.edma_port_control.fields.tx_padding_enable ? "enabled" : "disabled");

  if (a->debug)
    {
      s = format_newline (s, indent);
      s = format (s, "hardware data path not initialized");
    }

  return s;
}

u8 *
format_qppe_rxq_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_rx_queue_t *rxq = va_arg (*args, vnet_dev_rx_queue_t *);
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);

  if (a->debug)
    s = format (s,
		"EDMA RX fill ring %u descriptors VA %p DMA 0x%lx; RX descriptor ring %u primary "
		"VA %p DMA 0x%lx, preheader VA %p DMA 0x%lx",
		qr->fill_ring_id, qr->fill_descs, qr->fill_dma, qr->desc_ring_id, qr->primary_descs,
		qr->primary_dma, qr->secondary_descs, qr->secondary_dma);

  return s;
}

u8 *
format_qppe_port_status (u8 *s, va_list *args)
{
  vnet_dev_format_args_t __clib_unused *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  qppe_port_t *qp = vnet_dev_get_port_data (port);
  u32 indent = format_get_indent (s);

  s = format (s, "port id %u", port->port_id);
  if (qp->label)
    s = format (s, ", device tree label '%s'", qp->label);
  if (qp->phy_mode)
    s = format (s, ", PHY mode '%s'", qp->phy_mode);
  if (qp->managed)
    s = format (s, ", managed '%s'", qp->managed);

  if (qp->is_xgmac)
    {
      s = format (s, "\n%UXGMAC TX config 0x%08x (speed %u, TX %s)", format_white_space, indent,
		  qp->hw_state.xgmac_tx_config.as_u32, qp->hw_state.xgmac_tx_config.fields.speed,
		  qp->hw_state.xgmac_tx_config.fields.tx_enable ? "enabled" : "disabled");
      s = format (s, "\n%UXGMAC RX config 0x%08x (RX %s)", format_white_space, indent,
		  qp->hw_state.xgmac_rx_config.as_u32,
		  qp->hw_state.xgmac_rx_config.fields.rx_enable ? "enabled" : "disabled");
    }
  else
    s = format (s, "\n%UGMAC enable 0x%08x (TX %s, RX %s)", format_white_space, indent,
		qp->hw_state.gmac_enable.as_u32,
		qp->hw_state.gmac_enable.fields.tx_enable ? "enabled" : "disabled",
		qp->hw_state.gmac_enable.fields.rx_enable ? "enabled" : "disabled");

  return s;
}
