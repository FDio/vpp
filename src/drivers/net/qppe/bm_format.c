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
      u32 first = grp;
      ppe_reg_bm_shared_group_config_t cfg = {
	.as_u32 = qppe_mmio_read32 (qd, HPPE_REG_BM_SHARED_GROUP0_CONFIG + 4 * grp),
      };

      while (grp + 1 < HPPE_BM_GROUP_COUNT)
	{
	  ppe_reg_bm_shared_group_config_t next = {
	    .as_u32 = qppe_mmio_read32 (qd, HPPE_REG_BM_SHARED_GROUP0_CONFIG + 4 * (grp + 1)),
	  };

	  if (next.shared_buffer_limit != cfg.shared_buffer_limit)
	    break;
	  grp++;
	}

      if (first == grp)
	table_format_cell (&table, row, 0, "%u", first);
      else
	table_format_cell (&table, row, 0, "%u-%u", first, grp);
      table_format_cell (&table, row, 1, "%u", cfg.shared_buffer_limit);
      row++;
    }
  u32 indent = format_get_indent (s);
  s = format (s, "BM_SHARED_GROUP_CFG:");
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

  table_add_hdr_row (&table, 10, "bm_port", "fc_en", "grp", "shared", "weight", "dynamic",
		     "react_limit", "resume_offset", "resume_floor", "pre_alloc");
  table_add_hdr_row (&table, 10, "", "", "", "ceiling", "", "", "", "", "", "");
  for (u32 bm_port = 0; bm_port < 15; bm_port++)
    {
      u32 first = bm_port;
      ppe_reg_bm_port_fc_mode_t mode = {
	.as_u32 = qppe_mmio_read32 (qd, HPPE_REG_BM_PORT_FC_MODE (bm_port)),
      };
      ppe_reg_bm_port_group_id_t grp;
      ppe_reg_bm_port_fc_cfg_w0_t w0;
      ppe_reg_bm_port_fc_cfg_w1_t w1;
      u32 ceil;

      grp.as_u32 = qppe_mmio_read32 (qd, HPPE_REG_BM_PORT_GROUP_ID (bm_port));
      w0.as_u32 = qppe_mmio_read32 (qd, HPPE_REG_BM_PORT_FC_CFG_W0 (bm_port));
      w1.as_u32 = qppe_mmio_read32 (qd, HPPE_REG_BM_PORT_FC_CFG_W1 (bm_port));
      mode.reserved_1 = 0;
      grp.reserved_2 = 0;
      w1.reserved_23 = 0;
      ceil = w0.ceiling_low | (w1.ceiling_high << 3);

      while (bm_port + 1 < 15)
	{
	  ppe_reg_bm_port_fc_mode_t next_mode = {
	    .as_u32 = qppe_mmio_read32 (qd, HPPE_REG_BM_PORT_FC_MODE (bm_port + 1)),
	  };
	  ppe_reg_bm_port_group_id_t next_grp;
	  ppe_reg_bm_port_fc_cfg_w0_t next_w0;
	  ppe_reg_bm_port_fc_cfg_w1_t next_w1;

	  next_grp.as_u32 = qppe_mmio_read32 (qd, HPPE_REG_BM_PORT_GROUP_ID (bm_port + 1));
	  next_w0.as_u32 = qppe_mmio_read32 (qd, HPPE_REG_BM_PORT_FC_CFG_W0 (bm_port + 1));
	  next_w1.as_u32 = qppe_mmio_read32 (qd, HPPE_REG_BM_PORT_FC_CFG_W1 (bm_port + 1));
	  next_mode.reserved_1 = 0;
	  next_grp.reserved_2 = 0;
	  next_w1.reserved_23 = 0;
	  if (next_mode.as_u32 != mode.as_u32 || next_grp.as_u32 != grp.as_u32 ||
	      next_w0.as_u32 != w0.as_u32 || next_w1.as_u32 != w1.as_u32)
	    break;
	  bm_port++;
	}

      if (first == bm_port)
	table_format_cell (&table, row, 0, "%u", first);
      else
	table_format_cell (&table, row, 0, "%u-%u", first, bm_port);
      table_format_cell (&table, row, 1, "%u", mode.enable);
      table_format_cell (&table, row, 2, "%u", grp.shared_group_id);
      table_format_cell (&table, row, 3, "%u", ceil);
      table_format_cell (&table, row, 4, "%u", w1.weight);
      table_format_cell (&table, row, 5, "%u", w1.dynamic);
      table_format_cell (&table, row, 6, "%u", w0.react_limit);
      table_format_cell (&table, row, 7, "%u", w0.resume_offset);
      table_format_cell (&table, row, 8, "%u", w0.resume_threshold);
      table_format_cell (&table, row, 9, "%u", w1.pre_alloc);
      row++;
    }
  u32 indent = format_get_indent (s);
  s = format (s, "BM_PORT_FC_CFG/MODE/GROUP_ID:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

typedef void (qppe_bm_read_row_t) (qppe_device_t *, u32, u32 *);

static u8 *
format_qppe_bm_table (u8 *s, vnet_dev_t *dev, const char *name, const char *const *columns,
		      u32 n_columns, u32 count, qppe_bm_read_row_t *read_row, int hexadecimal)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;
  u32 indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  ASSERT (n_columns > 1 && n_columns <= 17);
  table_add_hdr_row (&table, 0);
  for (u32 col = 0; col < n_columns; col++)
    table_format_cell (&table, -1, col, "%s", columns[col]);

  for (u32 i = 0; i < count; i++)
    {
      u32 first = i;
      u32 values[16];

      read_row (qd, i, values);
      while (i + 1 < count)
	{
	  u32 next[16];

	  read_row (qd, i + 1, next);
	  if (memcmp (values, next, (n_columns - 1) * sizeof (values[0])))
	    break;
	  i++;
	}

      if (first == i)
	table_format_cell (&table, row, 0, "%u", first);
      else
	table_format_cell (&table, row, 0, "%u-%u", first, i);
      for (u32 col = 1; col < n_columns; col++)
	table_format_cell (&table, row, col, hexadecimal ? "%08x" : "%u", values[col - 1]);
      row++;
    }

  s = format (s, "%s:", name);
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

static const qppe_reg_field_t ppe_reg_bm_fb_fifo_cfg_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_bm_fb_fifo_cfg_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_bm_fp_fifo_cfg_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_bm_fp_fifo_cfg_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_bm_tick_dly_cfg_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_bm_tick_dly_cfg_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_bm_port_profile_cnt_en_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_bm_port_profile_cnt_en_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_bm_grp_profile_cnt_en_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_bm_grp_profile_cnt_en_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_bm_total_react_profile_th_cfg_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_bm_total_react_profile_th_cfg_t_fields
#undef _
};

u8 *
format_qppe_bm_cfg (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  static const struct
  {
    const char *name;
    u32 reg;
    const qppe_reg_field_t *fields;
    uword n_fields;
  } registers[] = {
    {
      "BM_FB_FIFO_CFG",
      HPPE_REG_BM_FB_FIFO_CFG,
      ppe_reg_bm_fb_fifo_cfg_fields,
      ARRAY_LEN (ppe_reg_bm_fb_fifo_cfg_fields),
    },
    {
      "BM_FP_FIFO_CFG",
      HPPE_REG_BM_FP_FIFO_CFG,
      ppe_reg_bm_fp_fifo_cfg_fields,
      ARRAY_LEN (ppe_reg_bm_fp_fifo_cfg_fields),
    },
    {
      "BM_TICK_DLY_CFG",
      HPPE_REG_BM_TICK_DLY_CFG,
      ppe_reg_bm_tick_dly_cfg_fields,
      ARRAY_LEN (ppe_reg_bm_tick_dly_cfg_fields),
    },
    {
      "BM_PORT_PROFILE_CNT_EN",
      HPPE_REG_BM_PORT_PROFILE_CNT_EN,
      ppe_reg_bm_port_profile_cnt_en_fields,
      ARRAY_LEN (ppe_reg_bm_port_profile_cnt_en_fields),
    },
    {
      "BM_GRP_PROFILE_CNT_EN",
      HPPE_REG_BM_GRP_PROFILE_CNT_EN,
      ppe_reg_bm_grp_profile_cnt_en_fields,
      ARRAY_LEN (ppe_reg_bm_grp_profile_cnt_en_fields),
    },
    {
      "BM_TOT_REACT_PROFILE_TH_CFG",
      HPPE_REG_BM_TOT_REACT_PROFILE_TH_CFG,
      ppe_reg_bm_total_react_profile_th_cfg_fields,
      ARRAY_LEN (ppe_reg_bm_total_react_profile_th_cfg_fields),
    },
  };
  u32 indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  for (u32 i = 0; i < ARRAY_LEN (registers); i++)
    {
      u32 value = qppe_mmio_read32 (qd, registers[i].reg);

      if (i)
	{
	  s = format (s, "\n");
	  s = format_newline (s, indent);
	}
      s = format (s, "%s: 0x%08x", registers[i].name, value);
      s = format_newline (s, indent + 2);
      s =
	format (s, "%U", format_qppe_reg_fields, value, registers[i].fields, registers[i].n_fields);
    }

  return s;
}

static void
qppe_bm_total_react_profile_read (qppe_device_t *qd, __clib_unused u32 i, u32 *v)
{
  v[0] = qppe_mmio_read32 (qd, HPPE_REG_BM_TOT_REACT_OUT_PROFILE_CNT);
  v[1] = qppe_mmio_read32 (qd, HPPE_REG_BM_TOT_REACT_IN_PROFILE_CNT);
}

u8 *
format_qppe_bm_total_react_profile (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  static const char *const columns[] = {
    "index",
    "out_profile",
    "in_profile",
  };

  return format_qppe_bm_table (s, dev, "BM_TOTAL_REACT_PROFILE_CNT", columns, ARRAY_LEN (columns),
			       1, qppe_bm_total_react_profile_read, 0);
}

static void
qppe_bm_deq_fifo_cfg_read (qppe_device_t *qd, u32 i, u32 *v)
{
  v[0] = qppe_mmio_read32 (qd, HPPE_REG_BM_DEQ_FIFO_CFG (i)) & HPPE_BM_DEQ_THRESHOLD_MASK;
}

u8 *
format_qppe_bm_deq_fifo_cfg (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  static const char *const columns[] = {
    "fifo",
    "threshold",
  };

  return format_qppe_bm_table (s, dev, "BM_DEQ_FIFO_CFG", columns, ARRAY_LEN (columns),
			       HPPE_BM_DEQ_FIFO_COUNT, qppe_bm_deq_fifo_cfg_read, 0);
}

static void
qppe_bm_port_status_read (qppe_device_t *qd, u32 i, u32 *v)
{
  ppe_reg_bm_port_fc_status_t status = {
    .as_u32 = qppe_mmio_read32 (qd, HPPE_REG_BM_PORT_FC_STATUS (i)),
  };

  v[0] = status.xon_threshold;
  v[1] = status.fc_status;
  v[2] = qppe_mmio_read32 (qd, HPPE_REG_BM_PORT_CNT (i)) & HPPE_BM_BUFFER_COUNT_MASK;
  v[3] = qppe_mmio_read32 (qd, HPPE_REG_BM_PORT_REACTED_CNT (i)) & HPPE_BM_REACT_COUNT_MASK;
}

u8 *
format_qppe_bm_port_status (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  static const char *const columns[] = {
    "bm_port", "xon_threshold", "fc_status", "buffers", "reacted_buffers",
  };

  return format_qppe_bm_table (s, dev, "BM_PORT_FC_STATUS/CNT/REACTED_CNT", columns,
			       ARRAY_LEN (columns), HPPE_BM_PORT_COUNT, qppe_bm_port_status_read,
			       0);
}

static void
qppe_bm_port_profile_read (qppe_device_t *qd, u32 i, u32 *v)
{
  ppe_reg_bm_port_profile_cnt_en_t en = {
    .as_u32 = qppe_mmio_read32 (qd, HPPE_REG_BM_PORT_PROFILE_CNT_EN),
  };

  v[0] = (en.as_u32 >> i) & 1;
  v[1] = qppe_mmio_read32 (qd, HPPE_REG_BM_PORT_PROFILE_TH_CFG (i)) & HPPE_BM_BUFFER_COUNT_MASK;
  v[2] = qppe_mmio_read32 (qd, HPPE_REG_BM_PORT_OUT_PROFILE_CNT (i));
  v[3] = qppe_mmio_read32 (qd, HPPE_REG_BM_PORT_IN_PROFILE_CNT (i));
  v[4] = (en.as_u32 >> (16 + i)) & 1;
  v[5] = qppe_mmio_read32 (qd, HPPE_REG_BM_REACT_PROFILE_TH_CFG (i)) & HPPE_BM_REACT_COUNT_MASK;
  v[6] = qppe_mmio_read32 (qd, HPPE_REG_BM_REACT_OUT_PROFILE_CNT (i));
  v[7] = qppe_mmio_read32 (qd, HPPE_REG_BM_REACT_IN_PROFILE_CNT (i));
}

u8 *
format_qppe_bm_port_profile (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  static const char *const columns[] = {
    "bm_port",	"port_en",	   "port_threshold", "port_out", "port_in",
    "react_en", "react_threshold", "react_out",	     "react_in",
  };

  return format_qppe_bm_table (s, dev, "BM_PORT/REACT_PROFILE", columns, ARRAY_LEN (columns),
			       HPPE_BM_PORT_COUNT, qppe_bm_port_profile_read, 0);
}

static void
qppe_bm_group_status_read (qppe_device_t *qd, u32 i, u32 *v)
{
  ppe_reg_bm_grp_profile_cnt_en_t en = {
    .as_u32 = qppe_mmio_read32 (qd, HPPE_REG_BM_GRP_PROFILE_CNT_EN),
  };

  v[0] = qppe_mmio_read32 (qd, HPPE_REG_BM_SHARED_GROUP_CNT (i)) & HPPE_BM_BUFFER_COUNT_MASK;
  v[1] = (en.as_u32 >> i) & 1;
  v[2] = qppe_mmio_read32 (qd, HPPE_REG_BM_GRP_PROFILE_TH_CFG (i)) & HPPE_BM_BUFFER_COUNT_MASK;
  v[3] = qppe_mmio_read32 (qd, HPPE_REG_BM_GRP_OUT_PROFILE_CNT (i));
  v[4] = qppe_mmio_read32 (qd, HPPE_REG_BM_GRP_IN_PROFILE_CNT (i));
}

u8 *
format_qppe_bm_group_status (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  static const char *const columns[] = {
    "grp", "buffers", "profile_en", "threshold", "out_profile", "in_profile",
  };

  return format_qppe_bm_table (s, dev, "BM_SHARED_GROUP_CNT/PROFILE", columns, ARRAY_LEN (columns),
			       HPPE_BM_GROUP_COUNT, qppe_bm_group_status_read, 0);
}

static void
qppe_bm_llm_read (qppe_device_t *qd, u32 i, u32 *v)
{
  ppe_reg_bm_llm_t entry = {
    .as_u32 = qppe_mmio_read32 (qd, HPPE_REG_BM_LLM (i)),
  };

  v[0] = entry.next_ptr;
  v[1] = entry.eop;
}

u8 *
format_qppe_bm_llm (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  static const char *const columns[] = {
    "buffer",
    "next_ptr",
    "eop",
  };

  return format_qppe_bm_table (s, dev, "BM_LLM", columns, ARRAY_LEN (columns), HPPE_BM_LLM_COUNT,
			       qppe_bm_llm_read, 0);
}

static void
qppe_bm_rcm_read (qppe_device_t *qd, u32 i, u32 *v)
{
  v[0] = qppe_mmio_read32 (qd, HPPE_REG_BM_RCM (i)) & HPPE_BM_REF_COUNT_MASK;
}

u8 *
format_qppe_bm_rcm (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  static const char *const columns[] = {
    "buffer",
    "ref_count",
  };

  return format_qppe_bm_table (s, dev, "BM_RCM", columns, ARRAY_LEN (columns), HPPE_BM_RCM_COUNT,
			       qppe_bm_rcm_read, 0);
}

static void
qppe_bm_dm_read (qppe_device_t *qd, u32 i, u32 *v)
{
  u32 offset = HPPE_REG_BM_DM (i);

  for (u32 word = 0; word < 16; word++)
    v[word] = qppe_mmio_read32 (qd, offset + sizeof (u32) * word);
}

u8 *
format_qppe_bm_dm (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  static const char *const columns[] = {
    "entry", "data0", "data1",	"data2",  "data3",  "data4",  "data5",	"data6",  "data7",
    "data8", "data9", "data10", "data11", "data12", "data13", "data14", "data15",
  };

  return format_qppe_bm_table (s, dev, "BM_DM", columns, ARRAY_LEN (columns), HPPE_BM_DM_COUNT,
			       qppe_bm_dm_read, 1);
}
