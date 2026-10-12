/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vppinfra/format_table.h>
#include <edma_hw.h>
#include <qppe.h>
#include <ppe_hw.h>

#define HPPE_REG_AC_UNICAST_QUEUE_CFG_W3(queue) (0x84800c + 0x10 * (queue))
#define HPPE_REG_AC_MULTICAST_QUEUE_CFG_W2(queue)                                                  \
  (0x84a008 + 0x10 * ((queue) - HPPE_AC_MULTICAST_QUEUE_BASE))

u8 *
format_qppe_ac_grp_cfg (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 7, "grp", "ac_en", "fc_en", "threshold", "buf_limit", "resume_grn",
		     "pre_alloc");
  for (u32 grp = 0; grp < 4; grp++)
    {
      u32 offset = HPPE_REG_AC_GRP_CFG_W0 (grp);
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

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 7, "queue", "grp", "dynamic", "weight", "threshold", "pre_limit",
		     "grn_resume");
  for (u32 queue = 0; queue < HPPE_AC_UNICAST_QUEUE_COUNT; queue++)
    {
      u32 offset = HPPE_REG_AC_UNICAST_QUEUE_CFG_W0 (queue);
      ppe_reg_ac_unicast_queue_cfg_w0_t w0 = { .as_u32 = qppe_mmio_read32 (qd, offset) };
      ppe_reg_ac_unicast_queue_cfg_w3_t w3;

      if (!w0.en)
	continue;

      w3.as_u32 = qppe_mmio_read32 (qd, HPPE_REG_AC_UNICAST_QUEUE_CFG_W3 (queue));

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

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 5, "queue", "grp", "threshold", "pre_limit", "resume");
  for (u32 queue = HPPE_AC_MULTICAST_QUEUE_BASE;
       queue < HPPE_AC_MULTICAST_QUEUE_BASE + HPPE_AC_MULTICAST_QUEUE_COUNT; queue++)
    {
      u32 offset = HPPE_REG_AC_MULTICAST_QUEUE_CFG_W0 (queue);
      ppe_reg_ac_multicast_queue_cfg_w0_t w0 = { .as_u32 = qppe_mmio_read32 (qd, offset) };
      ppe_reg_ac_multicast_queue_cfg_w2_t w2;

      if (!w0.en)
	continue;

      w2.as_u32 = qppe_mmio_read32 (qd, HPPE_REG_AC_MULTICAST_QUEUE_CFG_W2 (queue));

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
