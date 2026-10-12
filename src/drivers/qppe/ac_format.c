/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vppinfra/format_table.h>
#include <edma_hw.h>
#include <qppe.h>
#include <ppe_hw.h>

u8 *
format_qppe_ac_grp_cfg (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 10, "grp", "en", "force_ac", "color", "gap_grn_red", "gap_grn_yel",
		     "drop_threshold", "buf_limit", "resume", "pre_alloc");
  table_add_hdr_row (&table, 10, "", "", "", "aware", "", "", "", "", "green/yellow/red", "");
  table_set_cell_align (&table, -2, 8, TTAA_CENTER);
  table_set_cell_align (&table, -1, 8, TTAA_CENTER);
  for (u32 grp = 0; grp < 4; grp++)
    {
      u32 first = grp;
      u32 offset = HPPE_REG_AC_GRP_CFG_W0 (grp);
      ppe_reg_ac_grp_cfg_w0_t w0 = { .as_u32 = qppe_mmio_read32 (qd, offset) };
      ppe_reg_ac_grp_cfg_w1_t w1;
      ppe_reg_ac_grp_cfg_w2_t w2;
      u32 threshold;

      w1.as_u32 = qppe_mmio_read32 (qd, offset + 4);
      w2.as_u32 = qppe_mmio_read32 (qd, offset + 8);
      w2.reserved_27_31 = 0;
      threshold = w0.threshold_low | (w1.threshold_high << 7);

      while (grp + 1 < 4)
	{
	  u32 next_offset = HPPE_REG_AC_GRP_CFG_W0 (grp + 1);
	  ppe_reg_ac_grp_cfg_w0_t next_w0 = {
	    .as_u32 = qppe_mmio_read32 (qd, next_offset),
	  };
	  ppe_reg_ac_grp_cfg_w1_t next_w1;
	  ppe_reg_ac_grp_cfg_w2_t next_w2;

	  next_w1.as_u32 = qppe_mmio_read32 (qd, next_offset + 4);
	  next_w2.as_u32 = qppe_mmio_read32 (qd, next_offset + 8);
	  next_w2.reserved_27_31 = 0;
	  if (next_w0.as_u32 != w0.as_u32 || next_w1.as_u32 != w1.as_u32 ||
	      next_w2.as_u32 != w2.as_u32)
	    break;
	  grp++;
	}

      if (first == grp)
	table_format_cell (&table, row, 0, "%u", first);
      else
	table_format_cell (&table, row, 0, "%u-%u", first, grp);
      table_format_cell (&table, row, 1, "%u", w0.ac_en);
      table_format_cell (&table, row, 2, "%u", w0.ac_fc_en);
      table_format_cell (&table, row, 3, "%u", w0.clr_aware);
      table_format_cell (&table, row, 4, "%u", w0.gap_grn_red);
      table_format_cell (&table, row, 5, "%u", w0.gap_grn_yel);
      table_format_cell (&table, row, 6, "%u", threshold);
      table_format_cell (&table, row, 7, "%u", w1.buf_limit);
      table_format_cell (&table, row, 8, "%u/%u/%u", w2.resume_grn,
			 w1.resume_yel_low | (w2.resume_yel_high << 6), w1.resume_red);
      table_set_cell_align (&table, row, 8, TTAA_CENTER);
      table_format_cell (&table, row, 9, "%u", w2.pre_alloc);
      row++;
    }
  u32 indent = format_get_indent (s);
  s = format (s, "AC_GRP_CFG_TBL:");
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

  table_add_hdr_row (&table, 14, "queue", "en", "wred", "force_ac", "color", "grp", "dynamic",
		     "weight", "shared", "pre_limit", "gap_grn_grn_min", "gap_grn_yel",
		     "gap_grn_red", "resume");
  table_add_hdr_row (&table, 14, "", "", "", "", "aware", "", "", "", "ceiling", "", "", "min/max",
		     "min/max", "green/yellow/red");
  for (u32 col = 11; col <= 13; col++)
    {
      table_set_cell_align (&table, -2, col, TTAA_CENTER);
      table_set_cell_align (&table, -1, col, TTAA_CENTER);
    }
  for (u32 queue = 0; queue < HPPE_AC_UNICAST_QUEUE_COUNT; queue++)
    {
      u32 first = queue;
      u32 offset = HPPE_REG_AC_UNICAST_QUEUE_CFG_W0 (queue);
      ppe_reg_ac_unicast_queue_cfg_w0_t w0 = { .as_u32 = qppe_mmio_read32 (qd, offset) };
      ppe_reg_ac_unicast_queue_cfg_w1_t w1;
      ppe_reg_ac_unicast_queue_cfg_w2_t w2;
      ppe_reg_ac_unicast_queue_cfg_w3_t w3;

      w1.as_u32 = qppe_mmio_read32 (qd, offset + 4);
      w2.as_u32 = qppe_mmio_read32 (qd, offset + 8);
      w3.as_u32 = qppe_mmio_read32 (qd, offset + 12);
      w3.reserved_24 = 0;

      while (queue + 1 < HPPE_AC_UNICAST_QUEUE_COUNT)
	{
	  u32 next_offset = HPPE_REG_AC_UNICAST_QUEUE_CFG_W0 (queue + 1);
	  ppe_reg_ac_unicast_queue_cfg_w0_t next_w0 = {
	    .as_u32 = qppe_mmio_read32 (qd, next_offset),
	  };
	  ppe_reg_ac_unicast_queue_cfg_w1_t next_w1;
	  ppe_reg_ac_unicast_queue_cfg_w2_t next_w2;
	  ppe_reg_ac_unicast_queue_cfg_w3_t next_w3;

	  next_w1.as_u32 = qppe_mmio_read32 (qd, next_offset + 4);
	  next_w2.as_u32 = qppe_mmio_read32 (qd, next_offset + 8);
	  next_w3.as_u32 = qppe_mmio_read32 (qd, next_offset + 12);
	  next_w3.reserved_24 = 0;
	  if (next_w0.as_u32 != w0.as_u32 || next_w1.as_u32 != w1.as_u32 ||
	      next_w2.as_u32 != w2.as_u32 || next_w3.as_u32 != w3.as_u32)
	    break;
	  queue++;
	}

      if (first == queue)
	table_format_cell (&table, row, 0, "%u", first);
      else
	table_format_cell (&table, row, 0, "%u-%u", first, queue);
      table_format_cell (&table, row, 1, "%u", w0.en);
      table_format_cell (&table, row, 2, "%u", w0.wred_en);
      table_format_cell (&table, row, 3, "%u", w0.fc_en);
      table_format_cell (&table, row, 4, "%u", w0.clr_aware);
      table_format_cell (&table, row, 5, "%u", w0.grp_id);
      table_format_cell (&table, row, 6, "%u", w0.dynamic);
      table_format_cell (&table, row, 7, "%u", w0.weight);
      table_format_cell (&table, row, 8, "%u", w0.threshold);
      table_format_cell (&table, row, 9, "%u", w0.pre_limit);
      table_format_cell (&table, row, 10, "%u", w1.gap_grn_grn_min);
      table_format_cell (&table, row, 11, "%u/%u",
			 w1.gap_grn_yel_min_low | (w2.gap_grn_yel_min_high << 10),
			 w1.gap_grn_yel_max);
      table_format_cell (&table, row, 12, "%u/%u", w2.gap_grn_red_min, w2.gap_grn_red_max);
      table_format_cell (&table, row, 13, "%u/%u/%u", w3.grn_resume, w3.yel_resume,
			 w2.red_resume_low | (w3.red_resume_high << 9));
      for (u32 col = 11; col <= 13; col++)
	table_set_cell_align (&table, row, col, TTAA_CENTER);
      row++;
    }
  u32 indent = format_get_indent (s);
  s = format (s, "AC_UNICAST_QUEUE_CFG_TBL:");
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

  table_add_hdr_row (&table, 10, "queue", "en", "force_ac", "color", "grp", "shared", "pre_limit",
		     "gap_grn_yel", "gap_grn_red", "resume");
  table_add_hdr_row (&table, 10, "", "", "", "aware", "", "ceiling", "", "", "",
		     "green/yellow/red");
  table_set_cell_align (&table, -2, 9, TTAA_CENTER);
  table_set_cell_align (&table, -1, 9, TTAA_CENTER);
  for (u32 queue = HPPE_AC_MULTICAST_QUEUE_BASE;
       queue < HPPE_AC_MULTICAST_QUEUE_BASE + HPPE_AC_MULTICAST_QUEUE_COUNT; queue++)
    {
      u32 first = queue;
      u32 offset = HPPE_REG_AC_MULTICAST_QUEUE_CFG_W0 (queue);
      ppe_reg_ac_multicast_queue_cfg_w0_t w0 = { .as_u32 = qppe_mmio_read32 (qd, offset) };
      ppe_reg_ac_multicast_queue_cfg_w1_t w1;
      ppe_reg_ac_multicast_queue_cfg_w2_t w2;

      w1.as_u32 = qppe_mmio_read32 (qd, offset + 4);
      w2.as_u32 = qppe_mmio_read32 (qd, offset + 8);
      w2.reserved_18 = 0;

      while (queue + 1 < HPPE_AC_MULTICAST_QUEUE_BASE + HPPE_AC_MULTICAST_QUEUE_COUNT)
	{
	  u32 next_offset = HPPE_REG_AC_MULTICAST_QUEUE_CFG_W0 (queue + 1);
	  ppe_reg_ac_multicast_queue_cfg_w0_t next_w0 = {
	    .as_u32 = qppe_mmio_read32 (qd, next_offset),
	  };
	  ppe_reg_ac_multicast_queue_cfg_w1_t next_w1;
	  ppe_reg_ac_multicast_queue_cfg_w2_t next_w2;

	  next_w1.as_u32 = qppe_mmio_read32 (qd, next_offset + 4);
	  next_w2.as_u32 = qppe_mmio_read32 (qd, next_offset + 8);
	  next_w2.reserved_18 = 0;
	  if (next_w0.as_u32 != w0.as_u32 || next_w1.as_u32 != w1.as_u32 ||
	      next_w2.as_u32 != w2.as_u32)
	    break;
	  queue++;
	}

      if (first == queue)
	table_format_cell (&table, row, 0, "%u", first);
      else
	table_format_cell (&table, row, 0, "%u-%u", first, queue);
      table_format_cell (&table, row, 1, "%u", w0.en);
      table_format_cell (&table, row, 2, "%u", w0.fc_en);
      table_format_cell (&table, row, 3, "%u", w0.clr_aware);
      table_format_cell (&table, row, 4, "%u", w0.grp_id);
      table_format_cell (&table, row, 5, "%u", w0.threshold);
      table_format_cell (&table, row, 6, "%u", w0.pre_limit);
      table_format_cell (&table, row, 7, "%u", w0.gap_grn_yel_low | (w1.gap_grn_yel_high << 5));
      table_format_cell (&table, row, 8, "%u", w1.gap_grn_red);
      table_format_cell (&table, row, 9, "%u/%u/%u", w2.resume,
			 w1.yel_resume_low | (w2.yel_resume_high << 4), w1.red_resume);
      table_set_cell_align (&table, row, 9, TTAA_CENTER);
      row++;
    }
  u32 indent = format_get_indent (s);
  s = format (s, "AC_MULTICAST_QUEUE_CFG_TBL:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

static u8 *
format_qppe_ac_value_tbl (u8 *s, vnet_dev_t *dev, const char *name, const char *index_name,
			  const char *value_name, u32 base, u32 first_index, u32 count, u32 mask)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;
  u32 indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 2, index_name, value_name);
  for (u32 i = 0; i < count; i++)
    {
      u32 first = i;
      u32 value = qppe_mmio_read32 (qd, base + 0x10 * i) & mask;

      while (i + 1 < count)
	{
	  u32 next = qppe_mmio_read32 (qd, base + 0x10 * (i + 1)) & mask;

	  if (next != value)
	    break;
	  i++;
	}

      if (first == i)
	table_format_cell (&table, row, 0, "%u", first_index + first);
      else
	table_format_cell (&table, row, 0, "%u-%u", first_index + first, first_index + i);
      table_format_cell (&table, row, 1, "%u", value);
      row++;
    }

  s = format (s, "%s:", name);
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

u8 *
format_qppe_ac_mseq (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);

  return format_qppe_ac_value_tbl (s, dev, "AC_MSEQ_TBL", "index", "mseq", HPPE_REG_AC_MSEQ_TBL (0),
				   0, HPPE_AC_MSEQ_COUNT, HPPE_AC_MSEQ_MASK);
}

u8 *
format_qppe_ac_unicast_queue_cnt (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);

  return format_qppe_ac_value_tbl (s, dev, "AC_UNICAST_QUEUE_CNT_TBL", "queue", "buffers",
				   HPPE_REG_AC_UNICAST_QUEUE_CNT_TBL (0), 0,
				   HPPE_AC_UNICAST_QUEUE_COUNT, HPPE_AC_UNICAST_QUEUE_CNT_MASK);
}

u8 *
format_qppe_ac_multicast_queue_cnt (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);

  return format_qppe_ac_value_tbl (
    s, dev, "AC_MULTICAST_QUEUE_CNT_TBL", "queue", "buffers",
    HPPE_REG_AC_MULTICAST_QUEUE_CNT_TBL (HPPE_AC_MULTICAST_QUEUE_BASE),
    HPPE_AC_MULTICAST_QUEUE_BASE, HPPE_AC_MULTICAST_QUEUE_COUNT, HPPE_AC_MULTICAST_QUEUE_CNT_MASK);
}

u8 *
format_qppe_ac_grp_cnt (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;
  u32 indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 3, "grp", "buffers", "alloc_used");
  for (u32 grp = 0; grp < 4; grp++)
    {
      u32 first = grp;
      ppe_reg_ac_grp_cnt_t value = {
	.as_u32 = qppe_mmio_read32 (qd, HPPE_REG_AC_GRP_CNT_TBL (grp)),
      };

      while (grp + 1 < 4)
	{
	  u32 next = qppe_mmio_read32 (qd, HPPE_REG_AC_GRP_CNT_TBL (grp + 1));

	  if (next != value.as_u32)
	    break;
	  grp++;
	}

      if (first == grp)
	table_format_cell (&table, row, 0, "%u", first);
      else
	table_format_cell (&table, row, 0, "%u-%u", first, grp);
      table_format_cell (&table, row, 1, "%u", value.buffers);
      table_format_cell (&table, row, 2, "%u", value.alloc_used);
      row++;
    }

  s = format (s, "AC_GRP_CNT_TBL:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

static u8 *
format_qppe_ac_drop_state_tbl (u8 *s, vnet_dev_t *dev, const char *name, const char *index_name,
			       u32 base, u32 first_index, u32 count, int is_unicast)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;
  u32 indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 3, index_name, "resume_threshold", "drop_state");
  table_add_hdr_row (&table, 3, "", "green/yellow/red", "green/yellow/red");
  for (u32 col = 1; col <= 2; col++)
    {
      table_set_cell_align (&table, -2, col, TTAA_CENTER);
      table_set_cell_align (&table, -1, col, TTAA_CENTER);
    }
  for (u32 i = 0; i < count; i++)
    {
      u32 first = i;
      u32 offset = base + 0x10 * i;
      ppe_reg_ac_drop_state_w0_t w0 = {
	.as_u32 = qppe_mmio_read32 (qd, offset),
      };
      ppe_reg_ac_drop_state_w1_t w1;

      w1.as_u32 = qppe_mmio_read32 (qd, offset + 4);
      if (is_unicast)
	w1.unicast.reserved = 0;
      else
	w1.multicast.reserved = 0;

      while (i + 1 < count)
	{
	  u32 next_offset = base + 0x10 * (i + 1);
	  ppe_reg_ac_drop_state_w0_t next_w0 = {
	    .as_u32 = qppe_mmio_read32 (qd, next_offset),
	  };
	  ppe_reg_ac_drop_state_w1_t next_w1;

	  next_w1.as_u32 = qppe_mmio_read32 (qd, next_offset + 4);
	  if (is_unicast)
	    next_w1.unicast.reserved = 0;
	  else
	    next_w1.multicast.reserved = 0;
	  if (next_w0.as_u32 != w0.as_u32 || next_w1.as_u32 != w1.as_u32)
	    break;
	  i++;
	}

      if (first == i)
	table_format_cell (&table, row, 0, "%u", first_index + first);
      else
	table_format_cell (&table, row, 0, "%u-%u", first_index + first, first_index + i);
      table_format_cell (&table, row, 1, "%u/%u/%u",
			 w0.grn_resume_low | (w1.unicast.grn_resume_high << 10), w0.yel_resume,
			 w0.red_resume);
      table_format_cell (&table, row, 2, "%u/%u/%u",
			 is_unicast ? w1.unicast.grn_drop : w1.multicast.grn_drop,
			 is_unicast ? w1.unicast.yel_drop : w1.multicast.yel_drop,
			 is_unicast ? w1.unicast.red_drop : w1.multicast.red_drop);
      for (u32 col = 1; col <= 2; col++)
	table_set_cell_align (&table, row, col, TTAA_CENTER);
      row++;
    }

  s = format (s, "%s:", name);
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

u8 *
format_qppe_ac_unicast_queue_drop_state (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);

  return format_qppe_ac_drop_state_tbl (s, dev, "AC_UNICAST_QUEUE_DROP_STATE_TBL", "queue",
					HPPE_REG_AC_UNICAST_QUEUE_DROP_STATE_TBL (0), 0,
					HPPE_AC_UNICAST_QUEUE_COUNT, 1);
}

u8 *
format_qppe_ac_multicast_queue_drop_state (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);

  return format_qppe_ac_drop_state_tbl (
    s, dev, "AC_MULTICAST_QUEUE_DROP_STATE_TBL", "queue",
    HPPE_REG_AC_MULTICAST_QUEUE_DROP_STATE_TBL (HPPE_AC_MULTICAST_QUEUE_BASE),
    HPPE_AC_MULTICAST_QUEUE_BASE, HPPE_AC_MULTICAST_QUEUE_COUNT, 0);
}

u8 *
format_qppe_ac_grp_drop_state (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);

  return format_qppe_ac_drop_state_tbl (s, dev, "AC_GRP_DROP_STATE_TBL", "grp",
					HPPE_REG_AC_GRP_DROP_STATE_TBL (0), 0, 4, 0);
}
