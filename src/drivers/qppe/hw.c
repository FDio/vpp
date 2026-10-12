/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vppinfra/format_table.h>
#include <qppe.h>

VLIB_REGISTER_LOG_CLASS (qppe_log, static) = {
  .class_name = "qppe",
  .subclass_name = "hw",
};

#define log_debug(dev, f, ...)                                                                     \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, qppe_log.class, "%U" f, format_vnet_dev_log, (dev),              \
	    clib_string_skip_prefix (__func__, "qppe_"), ##__VA_ARGS__)

vnet_dev_rv_t
qppe_bm_port_configure (vnet_dev_t *dev, u32 bm_port_id, u32 ceil, u32 weight, u32 resume_offset,
			u32 resume_threshold, u8 dynamic, u32 react_limit, u32 pre_alloc, u8 enable)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  ppe_reg_bm_port_fc_cfg_w0_t w0 = {
    .react_limit = react_limit,
    .resume_threshold = resume_threshold,
    .resume_offset = resume_offset,
    .ceiling_low = ceil & 0x7,
  };
  ppe_reg_bm_port_fc_cfg_w1_t w1 = {
    .ceiling_high = ceil >> 3,
    .weight = weight,
    .dynamic = dynamic,
    .pre_alloc = pre_alloc,
  };
  ppe_reg_bm_port_group_id_t group_id = {};
  ppe_reg_bm_port_fc_mode_t fc_mode = { .enable = enable };
  u32 offset;

  offset = PPE_REG_BM_PORT_FC_CFG_W0 (bm_port_id);
  qppe_mmio_write32 (qd, offset, w0.as_u32);
  qppe_mmio_write32 (qd, offset + 4, w1.as_u32);
  if (qppe_mmio_read32 (qd, offset) != w0.as_u32 || qppe_mmio_read32 (qd, offset + 4) != w1.as_u32)
    {
      log_err (dev, "BM port %u flow-control config readback mismatch at offset 0x%x", bm_port_id,
	       offset);
      return VNET_DEV_ERR_INIT_FAILED;
    }
  log_debug (dev,
	     "wrote BM port %u flow-control config at offset 0x%x: ceil %u, weight %u, "
	     "resume_offset %u, resume_threshold %u, dynamic %u, react_limit %u, pre_alloc %u",
	     bm_port_id, offset, ceil, weight, resume_offset, resume_threshold, dynamic,
	     react_limit, pre_alloc);

  offset = PPE_REG_BM_PORT_GROUP_ID (bm_port_id);
  qppe_mmio_write32 (qd, offset, group_id.as_u32);
  if (qppe_mmio_read32 (qd, offset) != group_id.as_u32)
    {
      log_err (dev, "BM port %u shared group id readback mismatch at offset 0x%x", bm_port_id,
	       offset);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = PPE_REG_BM_PORT_FC_MODE (bm_port_id);
  qppe_mmio_write32 (qd, offset, fc_mode.as_u32);
  if (qppe_mmio_read32 (qd, offset) != fc_mode.as_u32)
    {
      log_err (dev, "BM port %u flow control mode readback mismatch at offset 0x%x", bm_port_id,
	       offset);
      return VNET_DEV_ERR_INIT_FAILED;
    }
  log_debug (dev, "BM port %u flow control %s", bm_port_id, enable ? "enabled" : "disabled");

  return VNET_DEV_OK;
}

/* QM (Queue Manager) admission control, a separate subsystem from BM
 * above: BM gates buffer admission per physical port, QM gates them again
 * per hardware queue, and queues additionally reset with enqueue/dequeue
 * explicitly disabled per-queue. One-time, whole-chip init, not tied to
 * any VPP port's lifecycle - matches mainline's ppe_config_qm() exactly. */
static vnet_dev_rv_t
qppe_qm_init (vnet_dev_t *dev)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  ppe_reg_ac_grp_cfg_w1_t ac_grp_w1 = { .buf_limit = PPE_QM_GROUP0_BUF_LIMIT };
  ppe_reg_eg_bridge_config_t eg_bridge_config;
  u32 offset, queue;

  {
    u32 base = PPE_REG_AC_GRP_CFG_W0 (0);
    u32 words[3];

    for (u32 w = 0; w < ARRAY_LEN (words); w++)
      words[w] = qppe_mmio_read32 (qd, base + 4 * w);
    words[1] = ac_grp_w1.as_u32;
    for (u32 w = 0; w < ARRAY_LEN (words); w++)
      qppe_mmio_write32 (qd, base + 4 * w, words[w]);
    for (u32 w = 0; w < ARRAY_LEN (words); w++)
      if (qppe_mmio_read32 (qd, base + 4 * w) != words[w])
	{
	  log_err (dev, "AC group 0 config readback mismatch at word %u", w);
	  return VNET_DEV_ERR_INIT_FAILED;
	}
  }
  log_debug (dev, "set AC group 0 buffer limit to %u", PPE_QM_GROUP0_BUF_LIMIT);

  for (queue = 0; queue < PPE_AC_UNICAST_QUEUE_COUNT; queue++)
    {
      ppe_reg_ac_unicast_queue_cfg_w0_t w0 = {
	.en = 1,
	.dynamic = 1,
	.weight = PPE_QM_UCAST_WEIGHT,
	.threshold = PPE_QM_UCAST_CEIL,
      };
      ppe_reg_ac_unicast_queue_cfg_w3_t w3 = { .grn_resume = PPE_QM_UCAST_RESUME_OFFSET };
      u32 base = PPE_REG_AC_UNICAST_QUEUE_CFG_W0 (queue);
      u32 words[4];

      for (u32 w = 0; w < ARRAY_LEN (words); w++)
	words[w] = qppe_mmio_read32 (qd, base + 4 * w);
      words[0] = w0.as_u32;
      words[3] = w3.as_u32;
      for (u32 w = 0; w < ARRAY_LEN (words); w++)
	qppe_mmio_write32 (qd, base + 4 * w, words[w]);
      for (u32 w = 0; w < ARRAY_LEN (words); w++)
	if (qppe_mmio_read32 (qd, base + 4 * w) != words[w])
	  {
	    log_err (dev, "AC unicast queue %u config readback mismatch at word %u", queue, w);
	    return VNET_DEV_ERR_INIT_FAILED;
	  }
    }
  log_debug (dev, "configured AC admission control for %u unicast queues",
	     PPE_AC_UNICAST_QUEUE_COUNT);

  for (queue = PPE_AC_MULTICAST_QUEUE_BASE;
       queue < PPE_AC_MULTICAST_QUEUE_BASE + PPE_AC_MULTICAST_QUEUE_COUNT; queue++)
    {
      ppe_reg_ac_multicast_queue_cfg_w0_t w0 = {
	.en = 1,
	.threshold = PPE_QM_MCAST_CEIL,
      };
      ppe_reg_ac_multicast_queue_cfg_w2_t w2 = { .resume = PPE_QM_MCAST_RESUME_OFFSET };
      u32 base = PPE_REG_AC_MULTICAST_QUEUE_CFG_W0 (queue);
      u32 words[5];

      for (u32 w = 0; w < ARRAY_LEN (words); w++)
	words[w] = qppe_mmio_read32 (qd, base + 4 * w);
      words[0] = w0.as_u32;
      words[2] = w2.as_u32;
      for (u32 w = 0; w < ARRAY_LEN (words); w++)
	qppe_mmio_write32 (qd, base + 4 * w, words[w]);
      for (u32 w = 0; w < ARRAY_LEN (words); w++)
	if (qppe_mmio_read32 (qd, base + 4 * w) != words[w])
	  {
	    log_err (dev, "AC multicast queue %u config readback mismatch at word %u", queue, w);
	    return VNET_DEV_ERR_INIT_FAILED;
	  }
    }
  log_debug (dev, "configured AC admission control for %u multicast queues",
	     PPE_AC_MULTICAST_QUEUE_COUNT);

  for (queue = 0; queue < PPE_AC_MULTICAST_QUEUE_BASE + PPE_AC_MULTICAST_QUEUE_COUNT; queue++)
    {
      ppe_reg_enq_deq_opr_t enq = {};
      ppe_reg_enq_deq_opr_t deq = {};

      offset = PPE_REG_ENQ_OPR (queue);
      qppe_mmio_write32 (qd, offset, enq.as_u32);
      if (qppe_mmio_read32 (qd, offset) != enq.as_u32)
	{
	  log_err (dev, "enqueue enable for queue %u readback mismatch at offset 0x%x", queue,
		   offset);
	  return VNET_DEV_ERR_INIT_FAILED;
	}

      offset = PPE_REG_DEQ_OPR (queue);
      qppe_mmio_write32 (qd, offset, deq.as_u32);
      if (qppe_mmio_read32 (qd, offset) != deq.as_u32)
	{
	  log_err (dev, "dequeue enable for queue %u readback mismatch at offset 0x%x", queue,
		   offset);
	  return VNET_DEV_ERR_INIT_FAILED;
	}
    }
  log_debug (dev, "enabled enqueue/dequeue for %u hardware queues",
	     PPE_AC_MULTICAST_QUEUE_BASE + PPE_AC_MULTICAST_QUEUE_COUNT);

  offset = PPE_REG_EG_BRIDGE_CONFIG;
  eg_bridge_config.as_u32 = qppe_mmio_read32 (qd, offset);
  eg_bridge_config.queue_cnt_en = 1;
  qppe_mmio_write32 (qd, offset, eg_bridge_config.as_u32);
  if (!((ppe_reg_eg_bridge_config_t) { .as_u32 = qppe_mmio_read32 (qd, offset) }).queue_cnt_en)
    {
      log_err (dev, "failed to enable queue counters at offset 0x%x", offset);
      return VNET_DEV_ERR_INIT_FAILED;
    }
  log_debug (dev, "enabled hardware queue counters");

  return VNET_DEV_OK;
}

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

  qd->hw_state.bm_shared_group0_config.shared_buffer_limit = PPE_BM_SHARED_GROUP0_LIMIT;
  qppe_mmio_write32 (qd, PPE_REG_BM_SHARED_GROUP0_CONFIG,
		     qd->hw_state.bm_shared_group0_config.as_u32);
  if (qppe_mmio_read32 (qd, PPE_REG_BM_SHARED_GROUP0_CONFIG) !=
      qd->hw_state.bm_shared_group0_config.as_u32)
    {
      log_err (dev, "BM shared group 0 config readback mismatch at offset 0x%x",
	       PPE_REG_BM_SHARED_GROUP0_CONFIG);
      return VNET_DEV_ERR_INIT_FAILED;
    }
  log_debug (dev, "set BM shared group 0 buffer limit to %u", PPE_BM_SHARED_GROUP0_LIMIT);

  /* Fixed BM-port buckets not tied to any VPP port's lifecycle: BM port 0
   * is the CPU/EDMA primary port, BM ports 1-7 are EDMA's other profiles,
   * BM port 14 is EIP. All three stay configured as long as the device
   * runs. The physical-port bucket (BM ports 8-13) is configured per VPP
   * port in qppe_edma_rx_ring_start/stop instead. */
  if (qppe_bm_port_configure (dev, PPE_BM_PORT_ID_CPU, 1146, 7, 8, 0, 1, 100, 0, 1) != VNET_DEV_OK)
    return VNET_DEV_ERR_INIT_FAILED;
  for (u32 bm_port_id = 1; bm_port_id <= 7; bm_port_id++)
    if (qppe_bm_port_configure (dev, bm_port_id, 250, 4, 36, 0, 1, 100, 0, 1) != VNET_DEV_OK)
      return VNET_DEV_ERR_INIT_FAILED;
  if (qppe_bm_port_configure (dev, 14, 250, 4, 36, 0, 1, 40, 0, 1) != VNET_DEV_OK)
    return VNET_DEV_ERR_INIT_FAILED;

  if (qppe_qm_init (dev) != VNET_DEV_OK)
    return VNET_DEV_ERR_INIT_FAILED;

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

  log_debug (dev, "reading EDMA version at offset 0x%x", EDMA_BASE_OFFSET + EDMA_REG_MAS_CTRL_ADDR);
  qd->hw_state.edma_version = qppe_mmio_read32 (qd, EDMA_BASE_OFFSET + EDMA_REG_MAS_CTRL_ADDR);
  log_debug (dev, "read EDMA version at offset 0x%x: %u (0x%08x)",
	     EDMA_BASE_OFFSET + EDMA_REG_MAS_CTRL_ADDR, qd->hw_state.edma_version,
	     qd->hw_state.edma_version);
  if (qd->hw_state.edma_version == 0xffffffff)
    {
      log_err (dev, "MMIO read check failed: EDMA version returned all ones");
      return VNET_DEV_ERR_INIT_FAILED;
    }

  log_debug (dev, "reading EDMA port control at offset 0x%x",
	     EDMA_BASE_OFFSET + EDMA_REG_PORT_CTRL_ADDR);
  qd->hw_state.edma_port_control.as_u32 =
    qppe_mmio_read32 (qd, EDMA_BASE_OFFSET + EDMA_REG_PORT_CTRL_ADDR);
  log_debug (dev, "read EDMA port control at offset 0x%x: 0x%08x, EDMA %s, TX padding %s",
	     EDMA_BASE_OFFSET + EDMA_REG_PORT_CTRL_ADDR, qd->hw_state.edma_port_control.as_u32,
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

u8 *
format_qppe_bm_shared_group_cfg (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;

  if (!qd->hw_initialized || !qd->regs)
    return s;

  table_add_hdr_row (&table, 2, "grp", "shared buffer limit");
  for (u32 grp = 0; grp < 4; grp++)
    {
      ppe_reg_bm_shared_group_config_t cfg = {
	.as_u32 = qppe_mmio_read32 (qd, PPE_REG_BM_SHARED_GROUP0_CONFIG + 4 * grp),
      };

      if (cfg.shared_buffer_limit == 0)
	continue;

      table_format_cell (&table, row, 0, "%u", grp);
      table_format_cell (&table, row, 1, "%u", cfg.shared_buffer_limit);
      row++;
    }
  u32 indent = format_get_indent (s);
  s = format (s, "PPE BM_SHARED_GROUP_CFG:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

u8 *
format_qppe_bm_port_fc_cfg (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;

  if (!qd->hw_initialized || !qd->regs)
    return s;

  table_add_hdr_row (&table, 9, "bm_port", "fc_en", "grp", "ceil", "weight", "dynamic",
		     "react_limit", "resume_offset", "resume_threshold");
  for (u32 bm_port = 0; bm_port < 15; bm_port++)
    {
      ppe_reg_bm_port_fc_mode_t mode = {
	.as_u32 = qppe_mmio_read32 (qd, PPE_REG_BM_PORT_FC_MODE (bm_port)),
      };
      ppe_reg_bm_port_group_id_t grp;
      ppe_reg_bm_port_fc_cfg_w0_t w0;
      ppe_reg_bm_port_fc_cfg_w1_t w1;
      u32 ceil;

      if (!mode.enable)
	continue;

      grp.as_u32 = qppe_mmio_read32 (qd, PPE_REG_BM_PORT_GROUP_ID (bm_port));
      w0.as_u32 = qppe_mmio_read32 (qd, PPE_REG_BM_PORT_FC_CFG_W0 (bm_port));
      w1.as_u32 = qppe_mmio_read32 (qd, PPE_REG_BM_PORT_FC_CFG_W1 (bm_port));
      ceil = w0.ceiling_low | (w1.ceiling_high << 3);

      table_format_cell (&table, row, 0, "%u", bm_port);
      table_format_cell (&table, row, 1, "%u", mode.enable);
      table_format_cell (&table, row, 2, "%u", grp.shared_group_id);
      table_format_cell (&table, row, 3, "%u", ceil);
      table_format_cell (&table, row, 4, "%u", w1.weight);
      table_format_cell (&table, row, 5, "%u", w1.dynamic);
      table_format_cell (&table, row, 6, "%u", w0.react_limit);
      table_format_cell (&table, row, 7, "%u", w0.resume_offset);
      table_format_cell (&table, row, 8, "%u", w0.resume_threshold);
      row++;
    }
  u32 indent = format_get_indent (s);
  s = format (s, "PPE BM_PORT_FC_CFG/MODE/GROUP_ID:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

u8 *
format_qppe_ac_grp_cfg (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;

  if (!qd->hw_initialized || !qd->regs)
    return s;

  table_add_hdr_row (&table, 7, "grp", "ac_en", "fc_en", "threshold", "buf_limit", "resume_grn",
		     "pre_alloc");
  for (u32 grp = 0; grp < 4; grp++)
    {
      u32 offset = PPE_REG_AC_GRP_CFG_W0 (grp);
      ppe_reg_ac_grp_cfg_w0_t w0 = { .as_u32 = qppe_mmio_read32 (qd, offset) };
      ppe_reg_ac_grp_cfg_w1_t w1;
      ppe_reg_ac_grp_cfg_w2_t w2;
      u32 threshold;

      if (!w0.ac_en)
	continue;

      w1.as_u32 = qppe_mmio_read32 (qd, offset + 4);
      w2.as_u32 = qppe_mmio_read32 (qd, offset + 8);
      threshold = w0.threshold_low | (w1.threshold_high << 7);

      table_format_cell (&table, row, 0, "%u", grp);
      table_format_cell (&table, row, 1, "%u", w0.ac_en);
      table_format_cell (&table, row, 2, "%u", w0.ac_fc_en);
      table_format_cell (&table, row, 3, "%u", threshold);
      table_format_cell (&table, row, 4, "%u", w1.buf_limit);
      table_format_cell (&table, row, 5, "%u", w2.resume_grn);
      table_format_cell (&table, row, 6, "%u", w2.pre_alloc);
      row++;
    }
  u32 indent = format_get_indent (s);
  s = format (s, "PPE AC_GRP_CFG_TBL:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

u8 *
format_qppe_ac_unicast_queue_cfg (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;

  if (!qd->hw_initialized || !qd->regs)
    return s;

  table_add_hdr_row (&table, 7, "queue", "grp", "dynamic", "weight", "threshold", "pre_limit",
		     "grn_resume");
  for (u32 queue = 0; queue < PPE_AC_UNICAST_QUEUE_COUNT; queue++)
    {
      u32 offset = PPE_REG_AC_UNICAST_QUEUE_CFG_W0 (queue);
      ppe_reg_ac_unicast_queue_cfg_w0_t w0 = { .as_u32 = qppe_mmio_read32 (qd, offset) };
      ppe_reg_ac_unicast_queue_cfg_w3_t w3;

      if (!w0.en)
	continue;

      w3.as_u32 = qppe_mmio_read32 (qd, PPE_REG_AC_UNICAST_QUEUE_CFG_W3 (queue));

      table_format_cell (&table, row, 0, "%u", queue);
      table_format_cell (&table, row, 1, "%u", w0.grp_id);
      table_format_cell (&table, row, 2, "%u", w0.dynamic);
      table_format_cell (&table, row, 3, "%u", w0.weight);
      table_format_cell (&table, row, 4, "%u", w0.threshold);
      table_format_cell (&table, row, 5, "%u", w0.pre_limit);
      table_format_cell (&table, row, 6, "%u", w3.grn_resume);
      row++;
    }
  u32 indent = format_get_indent (s);
  s = format (s, "PPE AC_UNICAST_QUEUE_CFG_TBL:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

u8 *
format_qppe_ac_multicast_queue_cfg (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;

  if (!qd->hw_initialized || !qd->regs)
    return s;

  table_add_hdr_row (&table, 5, "queue", "grp", "threshold", "pre_limit", "resume");
  for (u32 queue = PPE_AC_MULTICAST_QUEUE_BASE;
       queue < PPE_AC_MULTICAST_QUEUE_BASE + PPE_AC_MULTICAST_QUEUE_COUNT; queue++)
    {
      u32 offset = PPE_REG_AC_MULTICAST_QUEUE_CFG_W0 (queue);
      ppe_reg_ac_multicast_queue_cfg_w0_t w0 = { .as_u32 = qppe_mmio_read32 (qd, offset) };
      ppe_reg_ac_multicast_queue_cfg_w2_t w2;

      if (!w0.en)
	continue;

      w2.as_u32 = qppe_mmio_read32 (qd, PPE_REG_AC_MULTICAST_QUEUE_CFG_W2 (queue));

      table_format_cell (&table, row, 0, "%u", queue);
      table_format_cell (&table, row, 1, "%u", w0.grp_id);
      table_format_cell (&table, row, 2, "%u", w0.threshold);
      table_format_cell (&table, row, 3, "%u", w0.pre_limit);
      table_format_cell (&table, row, 4, "%u", w2.resume);
      row++;
    }
  u32 indent = format_get_indent (s);
  s = format (s, "PPE AC_MULTICAST_QUEUE_CFG_TBL:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

u8 *
format_qppe_enq_deq_opr (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;

  if (!qd->hw_initialized || !qd->regs)
    return s;

  table_add_hdr_row (&table, 3, "queue", "enq_disable", "deq_disable");
  /* qppe's own init clears both disable bits for every queue, so every
   * row is expected to show 0/0; only show rows that deviate from that
   * (the anomalous/interesting ones), rather than 300 all-identical
   * "enabled" rows. */
  for (u32 queue = 0; queue < 300; queue++)
    {
      ppe_reg_enq_deq_opr_t enq = { .as_u32 = qppe_mmio_read32 (qd, PPE_REG_ENQ_OPR (queue)) };
      ppe_reg_enq_deq_opr_t deq = { .as_u32 = qppe_mmio_read32 (qd, PPE_REG_DEQ_OPR (queue)) };

      if (!enq.disable && !deq.disable)
	continue;

      table_format_cell (&table, row, 0, "%u", queue);
      table_format_cell (&table, row, 1, "%u", enq.disable);
      table_format_cell (&table, row, 2, "%u", deq.disable);
      row++;
    }
  u32 indent = format_get_indent (s);
  s = format (s, "PPE ENQ_OPR/DEQ_OPR (queues disabled, if any):");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}
