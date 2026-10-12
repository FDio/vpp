/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vppinfra/format_table.h>
#include <qppe.h>

VLIB_REGISTER_LOG_CLASS (qppe_log, static) = {
  .class_name = "qppe",
  .subclass_name = "bm",
};

#define log_debug(dev, f, ...)                                                                     \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, qppe_log.class, "%U" f, format_vnet_dev_log, (dev),              \
	    clib_string_skip_prefix (__func__, "qppe_"), ##__VA_ARGS__)

vnet_dev_rv_t
qppe_bm_port_configure (vnet_dev_t *dev, u32 bm_port_id, const qppe_bm_port_config_t *config)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  ppe_reg_bm_port_fc_cfg_w0_t w0 = {
    .react_limit = config->react_limit,
    .resume_threshold = config->resume_threshold,
    .resume_offset = config->resume_offset,
    .ceiling_low = config->ceil & 0x7,
  };
  ppe_reg_bm_port_fc_cfg_w1_t w1 = {
    .ceiling_high = config->ceil >> 3,
    .weight = config->weight,
    .dynamic = config->dynamic,
    .pre_alloc = config->pre_alloc,
  };
  ppe_reg_bm_port_group_id_t group_id = {};
  ppe_reg_bm_port_fc_mode_t fc_mode = { .enable = config->enable };
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
	     bm_port_id, offset, config->ceil, config->weight, config->resume_offset,
	     config->resume_threshold, config->dynamic, config->react_limit, config->pre_alloc);

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
  log_debug (dev, "BM port %u flow control %s", bm_port_id,
	     config->enable ? "enabled" : "disabled");

  return VNET_DEV_OK;
}

vnet_dev_rv_t
qppe_bm_init (vnet_dev_t *dev)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_bm_port_config_t cpu_port_config = {
    .ceil = 1146,
    .weight = 7,
    .resume_offset = 8,
    .dynamic = 1,
    .react_limit = 100,
    .enable = 1,
  };
  qppe_bm_port_config_t edma_port_config = {
    .ceil = 250,
    .weight = 4,
    .resume_offset = 36,
    .dynamic = 1,
    .react_limit = 100,
    .enable = 1,
  };
  qppe_bm_port_config_t eip_port_config = {
    .ceil = 250,
    .weight = 4,
    .resume_offset = 36,
    .dynamic = 1,
    .react_limit = 40,
    .enable = 1,
  };
  ppe_reg_bm_shared_group_config_t shared_group0_config = {};
  vnet_dev_rv_t rv;

  log_debug (dev, "reading BM shared group 0 config at offset 0x%x",
	     PPE_REG_BM_SHARED_GROUP0_CONFIG);
  shared_group0_config.as_u32 = qppe_mmio_read32 (qd, PPE_REG_BM_SHARED_GROUP0_CONFIG);
  log_debug (dev, "read BM shared group 0 config at offset 0x%x: 0x%08x, shared buffer limit %u",
	     PPE_REG_BM_SHARED_GROUP0_CONFIG, shared_group0_config.as_u32,
	     shared_group0_config.shared_buffer_limit);
  if (shared_group0_config.as_u32 == 0xffffffff)
    {
      log_err (dev, "MMIO read check failed: BM shared group 0 config returned all ones");
      return VNET_DEV_ERR_INIT_FAILED;
    }

  shared_group0_config.shared_buffer_limit = PPE_BM_SHARED_GROUP0_LIMIT;
  qppe_mmio_write32 (qd, PPE_REG_BM_SHARED_GROUP0_CONFIG, shared_group0_config.as_u32);
  if (qppe_mmio_read32 (qd, PPE_REG_BM_SHARED_GROUP0_CONFIG) != shared_group0_config.as_u32)
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
  rv = qppe_bm_port_configure (dev, PPE_BM_PORT_ID_CPU, &cpu_port_config);
  if (rv != VNET_DEV_OK)
    return rv;
  for (u32 bm_port_id = 1; bm_port_id <= 7; bm_port_id++)
    {
      rv = qppe_bm_port_configure (dev, bm_port_id, &edma_port_config);
      if (rv != VNET_DEV_OK)
	return rv;
    }
  rv = qppe_bm_port_configure (dev, 14, &eip_port_config);
  if (rv != VNET_DEV_OK)
    return rv;

  return VNET_DEV_OK;
}

u8 *
format_qppe_bm_shared_group_cfg (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;

  if (!qd->regs)
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

  if (!qd->regs)
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
