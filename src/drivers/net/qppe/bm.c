/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <edma_hw.h>
#include <qppe.h>
#include <ppe_hw.h>

VLIB_REGISTER_LOG_CLASS (qppe_log, static) = {
  .class_name = "qppe",
  .subclass_name = "bm",
};

vnet_dev_rv_t
qppe_bm_port_configure (vnet_dev_t *dev, u32 bm_port_id, const qppe_bm_port_config_t *config)
{
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
  const qppe_reg_val_t regs[] = {
    {
      .off = HPPE_REG_BM_PORT_FC_CFG_W0 (bm_port_id),
      .val = w0.as_u32,
    },
    {
      .off = HPPE_REG_BM_PORT_FC_CFG_W0 (bm_port_id) + 4,
      .val = w1.as_u32,
    },
    {
      .off = HPPE_REG_BM_PORT_GROUP_ID (bm_port_id),
      .val = group_id.as_u32,
    },
    {
      .off = HPPE_REG_BM_PORT_FC_MODE (bm_port_id),
      .val = fc_mode.as_u32,
    },
  };
  vnet_dev_rv_t rv = qppe_mmio_write_validate (dev, regs, ARRAY_LEN (regs));

  if (rv != VNET_DEV_OK)
    return rv;
  log_debug (dev,
	     "wrote BM port %u flow-control config at offset 0x%x: ceil %u, weight %u, "
	     "resume_offset %u, resume_threshold %u, dynamic %u, react_limit %u, pre_alloc %u",
	     bm_port_id, regs[0].off, config->ceil, config->weight, config->resume_offset,
	     config->resume_threshold, config->dynamic, config->react_limit, config->pre_alloc);

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
  ppe_reg_bm_shared_group_config_t shared_group0_config;
  vnet_dev_rv_t rv;

  log_debug (dev, "reading BM shared group 0 config at offset 0x%x",
	     HPPE_REG_BM_SHARED_GROUP0_CONFIG);
  shared_group0_config.as_u32 = qppe_mmio_read32 (qd, HPPE_REG_BM_SHARED_GROUP0_CONFIG);
  log_debug (dev, "read BM shared group 0 config at offset 0x%x: 0x%08x, shared buffer limit %u",
	     HPPE_REG_BM_SHARED_GROUP0_CONFIG, shared_group0_config.as_u32,
	     shared_group0_config.shared_buffer_limit);
  if (shared_group0_config.as_u32 == 0xffffffff)
    {
      log_err (dev, "MMIO read check failed: BM shared group 0 config returned all ones");
      return VNET_DEV_ERR_INIT_FAILED;
    }

  shared_group0_config.shared_buffer_limit = HPPE_BM_SHARED_GROUP0_LIMIT;
  qppe_mmio_write32 (qd, HPPE_REG_BM_SHARED_GROUP0_CONFIG, shared_group0_config.as_u32);
  if (qppe_mmio_read32 (qd, HPPE_REG_BM_SHARED_GROUP0_CONFIG) != shared_group0_config.as_u32)
    {
      log_err (dev, "BM shared group 0 config readback mismatch at offset 0x%x",
	       HPPE_REG_BM_SHARED_GROUP0_CONFIG);
      return VNET_DEV_ERR_INIT_FAILED;
    }
  log_debug (dev, "set BM shared group 0 buffer limit to %u", HPPE_BM_SHARED_GROUP0_LIMIT);

  rv = qppe_bm_port_configure (dev, HPPE_BM_PORT_ID_CPU, &cpu_port_config);
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
