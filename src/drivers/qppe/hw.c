/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <qppe.h>

VLIB_REGISTER_LOG_CLASS (qppe_log, static) = {
  .class_name = "qppe",
  .subclass_name = "hw",
};

#define log_debug(dev, f, ...)                                                                     \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, qppe_log.class, "%U" f, format_vnet_dev_log, (dev),              \
	    clib_string_skip_prefix (__func__, "qppe_"), ##__VA_ARGS__)

vnet_dev_rv_t
qppe_hw_init (vnet_dev_t *dev)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);

  log_debug (dev, "reading port mux control at offset 0x%x", PPE_REG_PORT_MUX_CONTROL);
  qd->hw_state.port_mux_control.as_u32 = qppe_mmio_read32 (qd, PPE_REG_PORT_MUX_CONTROL);
  log_debug (dev,
	     "read port mux control at offset 0x%x: 0x%08x, XGMAC select 0x%02x, port 5 PCS1 %s",
	     PPE_REG_PORT_MUX_CONTROL, qd->hw_state.port_mux_control.as_u32,
	     qd->hw_state.port_mux_control.xgmac_select,
	     qd->hw_state.port_mux_control.port5_pcs1_select ? "selected" : "not selected");
  if (qd->hw_state.port_mux_control.as_u32 == 0xffffffff)
    {
      log_err (dev, "MMIO read check failed: port mux control returned all ones");
      return VNET_DEV_ERR_INIT_FAILED;
    }

  log_debug (dev, "reading BM shared group 0 config at offset 0x%x",
	     PPE_REG_BM_SHARED_GROUP0_CONFIG);
  qd->hw_state.bm_shared_group0_config.as_u32 =
    qppe_mmio_read32 (qd, PPE_REG_BM_SHARED_GROUP0_CONFIG);
  log_debug (dev, "read BM shared group 0 config at offset 0x%x: 0x%08x, shared buffer limit %u",
	     PPE_REG_BM_SHARED_GROUP0_CONFIG, qd->hw_state.bm_shared_group0_config.as_u32,
	     qd->hw_state.bm_shared_group0_config.shared_buffer_limit);
  if (qd->hw_state.bm_shared_group0_config.as_u32 == 0xffffffff)
    {
      log_err (dev, "MMIO read check failed: BM shared group 0 config returned all ones");
      return VNET_DEV_ERR_INIT_FAILED;
    }

  foreach_vnet_dev_port (port, dev)
    {
      qppe_port_t *qp = vnet_dev_get_port_data (port);
      u32 offset;

      if (port->port_id == 0)
	{
	  log_err (dev, "cannot read GMAC enable for port 0: PPE MAC port IDs are 1-based");
	  return VNET_DEV_ERR_INIT_FAILED;
	}
      if (qp->is_xgmac)
	{
	  offset = PPE_REG_XGMAC_BASE (port->port_id) + PPE_XGMAC_REG_TX_CONFIG;
	  log_debug (dev, "reading port %u XGMAC TX config at offset 0x%x", port->port_id, offset);
	  qp->hw_state.xgmac_tx_config.as_u32 = qppe_mmio_read32 (qd, offset);
	  log_debug (dev, "read port %u XGMAC TX config at offset 0x%x: 0x%08x, speed %u, TX %s",
		     port->port_id, offset, qp->hw_state.xgmac_tx_config.as_u32,
		     qp->hw_state.xgmac_tx_config.speed,
		     qp->hw_state.xgmac_tx_config.tx_enable ? "enabled" : "disabled");
	  offset = PPE_REG_XGMAC_BASE (port->port_id) + PPE_XGMAC_REG_RX_CONFIG;
	  log_debug (dev, "reading port %u XGMAC RX config at offset 0x%x", port->port_id, offset);
	  qp->hw_state.xgmac_rx_config.as_u32 = qppe_mmio_read32 (qd, offset);
	  log_debug (dev, "read port %u XGMAC RX config at offset 0x%x: 0x%08x, RX %s",
		     port->port_id, offset, qp->hw_state.xgmac_rx_config.as_u32,
		     qp->hw_state.xgmac_rx_config.rx_enable ? "enabled" : "disabled");
	  if (qp->hw_state.xgmac_tx_config.as_u32 == 0xffffffff ||
	      qp->hw_state.xgmac_rx_config.as_u32 == 0xffffffff)
	    {
	      log_err (dev, "MMIO read check failed: port %u XGMAC configuration returned all ones",
		       port->port_id);
	      return VNET_DEV_ERR_INIT_FAILED;
	    }
	}
      else
	{
	  offset = PPE_REG_GMAC_ENABLE (port->port_id);
	  log_debug (dev, "reading port %u GMAC enable at offset 0x%x", port->port_id, offset);
	  qp->hw_state.gmac_enable.as_u32 = qppe_mmio_read32 (qd, offset);
	  qp->hw_state.gmac_speed.as_u32 =
	    qppe_mmio_read32 (qd, PPE_REG_GMAC_BASE (port->port_id) + PPE_GMAC_REG_SPEED);
	  log_debug (dev, "read port %u GMAC enable at offset 0x%x: 0x%08x, TX %s, RX %s",
		     port->port_id, offset, qp->hw_state.gmac_enable.as_u32,
		     qp->hw_state.gmac_enable.tx_enable ? "enabled" : "disabled",
		     qp->hw_state.gmac_enable.rx_enable ? "enabled" : "disabled");
	  if (qp->hw_state.gmac_enable.as_u32 == 0xffffffff ||
	      qp->hw_state.gmac_speed.as_u32 == 0xffffffff)
	    {
	      log_err (dev, "MMIO read check failed: port %u GMAC configuration returned all ones",
		       port->port_id);
	      return VNET_DEV_ERR_INIT_FAILED;
	    }
	}
    }

  log_debug (dev, "reading EDMA version at offset 0x%x",
	     PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_MAS_CTRL_ADDR);
  qd->hw_state.edma_version =
    qppe_mmio_read32 (qd, PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_MAS_CTRL_ADDR);
  log_debug (dev, "read EDMA version at offset 0x%x: %u (0x%08x)",
	     PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_MAS_CTRL_ADDR, qd->hw_state.edma_version,
	     qd->hw_state.edma_version);
  if (qd->hw_state.edma_version == 0xffffffff)
    {
      log_err (dev, "MMIO read check failed: EDMA version returned all ones");
      return VNET_DEV_ERR_INIT_FAILED;
    }

  log_debug (dev, "reading EDMA port control at offset 0x%x",
	     PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_PORT_CTRL_ADDR);
  qd->hw_state.edma_port_control.as_u32 =
    qppe_mmio_read32 (qd, PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_PORT_CTRL_ADDR);
  log_debug (dev, "read EDMA port control at offset 0x%x: 0x%08x, EDMA %s, TX padding %s",
	     PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_PORT_CTRL_ADDR,
	     qd->hw_state.edma_port_control.as_u32,
	     qd->hw_state.edma_port_control.edma_enable ? "enabled" : "disabled",
	     qd->hw_state.edma_port_control.tx_padding_enable ? "enabled" : "disabled");
  if (qd->hw_state.edma_port_control.as_u32 == 0xffffffff)
    {
      log_err (dev, "MMIO read check failed: EDMA port control returned all ones");
      return VNET_DEV_ERR_INIT_FAILED;
    }

  log_debug (dev, "MMIO read checks passed for port mux, BM shared group 0, configured GMACs, EDMA "
		  "version, and EDMA port control");
  qd->hw_initialized = 1;
  return VNET_DEV_OK;
}
