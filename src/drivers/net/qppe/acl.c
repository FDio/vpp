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
  .subclass_name = "acl",
};

vnet_dev_rv_t
qppe_acl_init (vnet_dev_t *dev)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);

  for (u32 index = 0; index < HPPE_ACL_TOTAL_ROWS; index++)
    {
      u32 rule_offset = HPPE_REG_IPO_RULE_REG (index);
      u32 mask_offset = HPPE_REG_IPO_MASK_REG (index);
      u32 action_offset = HPPE_REG_IPO_ACTION (index);

      qppe_mmio_write32 (qd, rule_offset, 0);
      qppe_mmio_write32 (qd, rule_offset + 4, 0);
      qppe_mmio_write32 (qd, rule_offset + 8, 0);
      qppe_mmio_write32 (qd, mask_offset, 0);
      qppe_mmio_write32 (qd, mask_offset + 4, 0);
      for (u32 i = 0; i < HPPE_ACL_ACTION_WORDS; i++)
	qppe_mmio_write32 (qd, action_offset + i * sizeof (u32), 0);

      if (qppe_mmio_read32 (qd, rule_offset) != 0 || qppe_mmio_read32 (qd, mask_offset) != 0 ||
	  qppe_mmio_read32 (qd, action_offset) != 0)
	{
	  log_err (dev, "ACL row %u clear readback failed at offset 0x%x", index, rule_offset);
	  return VNET_DEV_ERR_INIT_FAILED;
	}
    }

  log_debug (dev, "cleared all %u ACL (IPO) TCAM rows", HPPE_ACL_TOTAL_ROWS);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
qppe_acl_pre_ipo_write_row (vnet_dev_t *dev, u32 row, const vnet_dev_hw_addr_t *addr,
			    u8 exact_match, u32 pri, u32 fwd_cmd, u32 port_bitmap)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 rule_offset = APPE_REG_PRE_IPO_RULE_REG (row);
  u32 mask_offset = APPE_REG_PRE_IPO_MASK_REG (row);
  u32 action_offset = APPE_REG_PRE_IPO_ACTION (row);
  u32 mac_mask = exact_match ? 0xffffffff : 0;
  ppe_reg_pre_ipo_rule_reg_t rule = {
    .bf = {
      .rule_field_0 = ((u32) addr->eth_mac[2] << 24) | ((u32) addr->eth_mac[3] << 16) |
		      ((u32) addr->eth_mac[4] << 8) | addr->eth_mac[5],
      .rule_field_1 = ((u32) addr->eth_mac[0] << 8) | addr->eth_mac[1],
      .rule_type = HPPE_ACL_RULE_TYPE_MAC_DA,
      .src_type = HPPE_ACL_SRC_TYPE_PORTBITMAP,
      .src_0 = port_bitmap & 1,
      .src_1 = port_bitmap >> 1,
      .pri = pri,
    },
  };
  ppe_reg_pre_ipo_mask_reg_t mask = {
    .bf = {
      .maskfield_0 = mac_mask,
      .maskfield_1 = mac_mask & 0xffff,
    },
  };
  ppe_reg_pre_ipo_action_t action = {
    .bf = {
      .dest_info_change_en = 1,
      .fwd_cmd = fwd_cmd,
    },
  };

  qppe_mmio_write32 (qd, rule_offset, rule.val[0]);
  qppe_mmio_write32 (qd, rule_offset + 4, rule.val[1]);
  qppe_mmio_write32 (qd, rule_offset + 8, rule.val[2]);
  qppe_mmio_write32 (qd, mask_offset, mask.val[0]);
  qppe_mmio_write32 (qd, mask_offset + 4, mask.val[1]);
  qppe_mmio_write32 (qd, action_offset, action.val[0]);
  for (u32 i = 1; i < APPE_PRE_ACL_ACTION_WORDS; i++)
    qppe_mmio_write32 (qd, action_offset + i * sizeof (u32), 0);

  if (qppe_mmio_read32 (qd, rule_offset) != rule.val[0] ||
      qppe_mmio_read32 (qd, rule_offset + 4) != rule.val[1] ||
      qppe_mmio_read32 (qd, rule_offset + 8) != rule.val[2] ||
      qppe_mmio_read32 (qd, mask_offset) != mask.val[0] ||
      qppe_mmio_read32 (qd, mask_offset + 4) != mask.val[1] ||
      qppe_mmio_read32 (qd, action_offset) != action.val[0])
    {
      log_err (dev, "Pre-IPO row %u readback failed at offset 0x%x", row, rule_offset);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  log_debug (dev, "Pre-IPO row %u: dest MAC %U %s port bitmap 0x%x fwd_cmd %u pri %u", row,
	     format_vnet_dev_hw_addr, addr, exact_match ? "(exact)" : "(any)", port_bitmap, fwd_cmd,
	     pri);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
qppe_acl_pre_ipo_init (vnet_dev_t *dev)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);

  for (u32 index = 0; index < APPE_PRE_ACL_TOTAL_ROWS; index++)
    {
      u32 rule_offset = APPE_REG_PRE_IPO_RULE_REG (index);
      u32 mask_offset = APPE_REG_PRE_IPO_MASK_REG (index);
      u32 action_offset = APPE_REG_PRE_IPO_ACTION (index);

      qppe_mmio_write32 (qd, rule_offset, 0);
      qppe_mmio_write32 (qd, rule_offset + 4, 0);
      qppe_mmio_write32 (qd, rule_offset + 8, 0);
      qppe_mmio_write32 (qd, mask_offset, 0);
      qppe_mmio_write32 (qd, mask_offset + 4, 0);
      for (u32 i = 0; i < APPE_PRE_ACL_ACTION_WORDS; i++)
	qppe_mmio_write32 (qd, action_offset + i * sizeof (u32), 0);

      if (qppe_mmio_read32 (qd, rule_offset) != 0 || qppe_mmio_read32 (qd, mask_offset) != 0 ||
	  qppe_mmio_read32 (qd, action_offset) != 0)
	{
	  log_err (dev, "Pre-IPO row %u clear readback failed at offset 0x%x", index, rule_offset);
	  return VNET_DEV_ERR_INIT_FAILED;
	}
    }

  log_debug (dev, "cleared all %u Pre-IPO TCAM rows", APPE_PRE_ACL_TOTAL_ROWS);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
qppe_acl_pre_ipo_port_configure (vnet_dev_port_t *port, const vnet_dev_hw_addr_t *addr)
{
  static const vnet_dev_hw_addr_t bcast = {
    .eth_mac = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
  };
  u32 port_bitmap = 1u << port->port_id;
  vnet_dev_rv_t rv;

  rv = qppe_acl_pre_ipo_write_row (port->dev, APPE_PRE_ACL_BCAST_ROW (port->port_id), &bcast,
				   /* exact_match */ 1, APPE_ACL_PRI_PERMIT, HPPE_ACL_ACTION_FWD,
				   port_bitmap);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = qppe_acl_pre_ipo_write_row (port->dev, APPE_PRE_ACL_PRIMARY_ROW (port->port_id), addr,
				   /* exact_match */ 1, APPE_ACL_PRI_PERMIT, HPPE_ACL_ACTION_FWD,
				   port_bitmap);
  if (rv != VNET_DEV_OK)
    return rv;

  return qppe_acl_pre_ipo_write_row (port->dev, APPE_PRE_ACL_DENY_ROW (port->port_id), addr,
				     /* exact_match */ 0, APPE_ACL_PRI_DENY, HPPE_ACL_ACTION_DROP,
				     port_bitmap);
}

void
qppe_acl_pre_ipo_read_row (vnet_dev_t *dev, u32 row, u32 *port_bitmap, vnet_dev_hw_addr_t *addr)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 rule_offset = APPE_REG_PRE_IPO_RULE_REG (row);
  ppe_reg_pre_ipo_rule_reg_t rule = {
    .val = {
      qppe_mmio_read32 (qd, rule_offset),
      qppe_mmio_read32 (qd, rule_offset + 4),
      qppe_mmio_read32 (qd, rule_offset + 8),
    },
  };

  *port_bitmap = rule.bf.src_0 | (rule.bf.src_1 << 1);
  addr->eth_mac[0] = rule.bf.rule_field_1 >> 8;
  addr->eth_mac[1] = rule.bf.rule_field_1 & 0xff;
  addr->eth_mac[2] = rule.bf.rule_field_0 >> 24;
  addr->eth_mac[3] = (rule.bf.rule_field_0 >> 16) & 0xff;
  addr->eth_mac[4] = (rule.bf.rule_field_0 >> 8) & 0xff;
  addr->eth_mac[5] = rule.bf.rule_field_0 & 0xff;
}
