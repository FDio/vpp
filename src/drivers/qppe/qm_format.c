/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vppinfra/format_table.h>
#include <edma_hw.h>
#include <qppe.h>
#include <ppe_hw.h>

static const qppe_reg_field_t ppe_reg_qm_flush_cfg_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_qm_flush_cfg_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_qm_mirror_priority_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_qm_mirror_priority_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_qm_default_hash_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_qm_default_hash_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_eg_bridge_config_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_eg_bridge_config_t_fields
#undef _
};

u8 *
format_qppe_qm_cfg (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  const struct
  {
    const char *name;
    u32 reg;
    const qppe_reg_field_t *fields;
    uword n_fields;
  } registers[] = {
    {
      "FLUSH_CFG",
      HPPE_REG_QM_FLUSH_CFG,
      ppe_reg_qm_flush_cfg_fields,
      ARRAY_LEN (ppe_reg_qm_flush_cfg_fields),
    },
    {
      "IN_MIRROR_PRIORITY_CTRL",
      HPPE_REG_QM_IN_MIRROR_PRIORITY_CTRL,
      ppe_reg_qm_mirror_priority_fields,
      ARRAY_LEN (ppe_reg_qm_mirror_priority_fields),
    },
    {
      "EG_MIRROR_PRIORITY_CTRL",
      HPPE_REG_QM_EG_MIRROR_PRIORITY_CTRL,
      ppe_reg_qm_mirror_priority_fields,
      ARRAY_LEN (ppe_reg_qm_mirror_priority_fields),
    },
    {
      "UCAST_DEFAULT_HASH",
      HPPE_REG_QM_UCAST_DEFAULT_HASH,
      ppe_reg_qm_default_hash_fields,
      ARRAY_LEN (ppe_reg_qm_default_hash_fields),
    },
    {
      "EG_BRIDGE_CONFIG",
      HPPE_REG_EG_BRIDGE_CONFIG,
      ppe_reg_eg_bridge_config_fields,
      ARRAY_LEN (ppe_reg_eg_bridge_config_fields),
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

u8 *
format_qppe_ucast_queue_map_tbl (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  const char *const keys[] = {
    "VP",
    "CPU code",
    "service code",
  };
  u32 row = 0, indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 5, "Key", "Source", "VP/code", "Queue", "Queue");
  table_add_hdr_row (&table, 5, "", "profile", "", "profile", "base");
  for (u32 key = 0; key < HPPE_QM_QUEUE_MAP_DOMAINS; key++)
    for (u32 profile = 0; profile < HPPE_QM_SOURCE_PROFILES; profile++)
      for (u32 id = 0; id < HPPE_QM_MAP_KEYS; id++)
	{
	  u32 first = id;
	  u32 block = key * HPPE_QM_SOURCE_PROFILES + profile;
	  ppe_reg_ucast_queue_map_t value = {
	    .as_u32 = qppe_mmio_read32 (qd, HPPE_REG_UCAST_QUEUE_MAP_TBL (block, id)),
	  };

	  value.reserved_12_31 = 0;
	  while (id + 1 < HPPE_QM_MAP_KEYS)
	    {
	      ppe_reg_ucast_queue_map_t next = {
		.as_u32 = qppe_mmio_read32 (qd, HPPE_REG_UCAST_QUEUE_MAP_TBL (block, id + 1)),
	      };

	      next.reserved_12_31 = 0;
	      if (next.as_u32 != value.as_u32)
		break;
	      id++;
	    }
	  table_format_cell (&table, row, 0, "%s", keys[key]);
	  table_set_cell_align (&table, row, 0, TTAA_LEFT);
	  table_format_cell (&table, row, 1, "%u", profile);
	  if (first == id)
	    table_format_cell (&table, row, 2, "%u", first);
	  else
	    table_format_cell (&table, row, 2, "%u-%u", first, id);
	  table_format_cell (&table, row, 3, "%u", value.profile_id);
	  table_format_cell (&table, row, 4, "%u", value.queue_id);
	  row++;
	}

  s = format (s, "UCAST_QUEUE_MAP_TBL:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

/* Each reader returns only displayed fields, excluding reserved bits. */
typedef void (qppe_qm_read_row_t) (qppe_device_t *, u32, u32 *);

static u8 *
qppe_qm_format_table (u8 *s, vnet_dev_t *dev, const char *name, const char *const *columns,
		      u32 n_columns, u32 first_index, u32 count, u32 group_size, u32 index_col,
		      qppe_qm_read_row_t *read_row)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0, indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  ASSERT (n_columns > 1 && n_columns <= 8 && index_col < n_columns);
  table_add_hdr_row (&table, 0);
  for (u32 col = 0; col < n_columns; col++)
    table_format_cell (&table, -1, col, "%s", columns[col]);

  for (u32 i = first_index; i < first_index + count; i++)
    {
      u32 first = i, col_value = 0;
      u32 values[7];

      read_row (qd, i, values);
      while (i + 1 < first_index + count && (!group_size || i / group_size == (i + 1) / group_size))
	{
	  u32 next[7];

	  read_row (qd, i + 1, next);
	  if (memcmp (values, next, (n_columns - 1) * sizeof (values[0])))
	    break;
	  i++;
	}
      for (u32 col = 0; col < n_columns; col++)
	if (col == index_col)
	  {
	    u32 start = group_size ? first % group_size : first;
	    u32 end = group_size ? i % group_size : i;

	    if (start == end)
	      table_format_cell (&table, row, col, "%u", start);
	    else
	      table_format_cell (&table, row, col, "%u-%u", start, end);
	  }
	else
	  table_format_cell (&table, row, col, "%u", values[col_value++]);
      row++;
    }

  s = format (s, "%s:", name);
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

static void
qppe_enq_deq_opr_read (qppe_device_t *qd, u32 i, u32 *v)
{
  v[0] = qppe_mmio_read32 (qd, HPPE_REG_ENQ_OPR (i)) & 1;
  v[1] = qppe_mmio_read32 (qd, HPPE_REG_OQ_DEQ_OPR (i)) & 1;
}

u8 *
format_qppe_enq_deq_opr (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  const char *const columns[] = {
    "queue",
    "enq_disable",
    "deq_drop",
  };

  return qppe_qm_format_table (s, dev, "OQ_ENQ_OPR/OQ_DEQ_OPR", columns, ARRAY_LEN (columns), 0,
			       HPPE_QM_QUEUE_COUNT, 0, 0, qppe_enq_deq_opr_read);
}

/* Group identical adjacent maps, then equal adjacent keys within each map. */
static u8 *
qppe_qm_format_maps (u8 *s, vnet_dev_t *dev, const char *name, const char *const *columns,
		     u32 n_maps, u32 n_keys, qppe_qm_read_row_t *read_row)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  i32 *values = 0;
  u32 row = 0, indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  vec_validate (values, n_maps * n_keys - 1);
  for (u32 i = 0; i < n_maps * n_keys; i++)
    {
      u32 v[2];

      read_row (qd, i, v);
      values[i] = v[1];
    }
  table_add_hdr_row (&table, 3, columns[0], columns[1], columns[2]);
  for (u32 map = 0; map < n_maps; map++)
    {
      u32 first_map = map;
      const i32 *entries = values + map * n_keys;

      while (map + 1 < n_maps &&
	     !memcmp (entries, values + (map + 1) * n_keys, n_keys * sizeof (entries[0])))
	map++;
      for (u32 key = 0; key < n_keys; key++)
	{
	  u32 first_key = key;

	  while (key + 1 < n_keys && entries[key + 1] == entries[first_key])
	    key++;
	  if (first_map == map)
	    table_format_cell (&table, row, 0, "%u", first_map);
	  else
	    table_format_cell (&table, row, 0, "%u-%u", first_map, map);
	  if (first_key == key)
	    table_format_cell (&table, row, 1, "%u", first_key);
	  else
	    table_format_cell (&table, row, 1, "%u-%u", first_key, key);
	  table_format_cell (&table, row, 2, "%d", entries[first_key]);
	  row++;
	}
    }

  s = format (s, "%s:", name);
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  vec_free (values);
  return s;
}

static void
qppe_ucast_priority_map_read (qppe_device_t *qd, u32 i, u32 *v)
{
  u32 profile = i / HPPE_QM_PRIORITIES;
  u32 priority = i % HPPE_QM_PRIORITIES;

  v[0] = profile;
  v[1] = qppe_mmio_read32 (qd, HPPE_REG_UCAST_PRIORITY_MAP_TBL (profile, priority)) & 0xf;
}

u8 *
format_qppe_ucast_priority_map (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  const char *const columns[] = {
    "profile",
    "priority",
    "queue_class",
  };

  return qppe_qm_format_maps (s, dev, "UCAST_PRIORITY_MAP_TBL", columns, HPPE_QM_PRIORITY_PROFILES,
			      HPPE_QM_PRIORITIES, qppe_ucast_priority_map_read);
}

static void
qppe_mcast_priority_map_read (qppe_device_t *qd, u32 i, u32 *v)
{
  u32 port = i / HPPE_QM_PRIORITIES;
  u32 priority = i % HPPE_QM_PRIORITIES;

  v[0] = port;
  v[1] =
    qppe_mmio_read32 (qd, HPPE_REG_MCAST_PRIORITY_MAP_TBL (port, priority)) & (port == 0 ? 0xf : 3);
}

u8 *
format_qppe_mcast_priority_map (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  const char *const columns[] = {
    "port",
    "priority",
    "queue_class",
  };

  return qppe_qm_format_maps (s, dev, "MCAST_PRIORITY_MAP0-7", columns, QPPE_MAX_PORTS,
			      HPPE_QM_PRIORITIES, qppe_mcast_priority_map_read);
}

static void
qppe_mcast_queue_map_read (qppe_device_t *qd, u32 i, u32 *v)
{
  v[0] = qppe_mmio_read32 (qd, HPPE_REG_MCAST_QUEUE_MAP_TBL (i)) & 0xf;
}

u8 *
format_qppe_mcast_queue_map (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  const char *const columns[] = {
    "CPU code",
    "queue_class",
  };

  return qppe_qm_format_table (s, dev, "MCAST_QUEUE_MAP_TBL", columns, ARRAY_LEN (columns), 0,
			       HPPE_QM_MAP_KEYS, 0, 0, qppe_mcast_queue_map_read);
}

static void
qppe_qm_aggregation_read (qppe_device_t *qd, u32 i, u32 *v)
{
  ppe_reg_qm_aggregation_t entry = {
    .as_u32 = qppe_mmio_read32 (qd, HPPE_REG_UQ_AGG_PROFILE_MAP (i)),
  };

  v[0] = entry.aggregation_id;
  v[1] = entry.enable;
}

u8 *
format_qppe_qm_aggregation (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  const char *const columns[] = {
    "queue",
    "aggregation_id",
    "en",
  };

  return qppe_qm_format_table (s, dev, "UQ_AGG_PROFILE_MAP", columns, ARRAY_LEN (columns), 0,
			       HPPE_AC_UNICAST_QUEUE_COUNT, 0, 0, qppe_qm_aggregation_read);
}

static void
qppe_qm_unicast_head_read (qppe_device_t *qd, u32 i, u32 *v)
{
  ppe_reg_qm_oq_head_uni_t entry = {
    .as_u32 = qppe_mmio_read32 (qd, HPPE_REG_OQ_HEAD_UNI_TBL (i)),
  };

  v[0] = entry.empty;
  v[1] = entry.head;
  v[2] = entry.tail;
}

u8 *
format_qppe_qm_unicast_head (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  const char *const columns[] = {
    "queue",
    "empty",
    "head",
    "tail",
  };

  return qppe_qm_format_table (s, dev, "OQ_HEAD_UNI_TBL", columns, ARRAY_LEN (columns), 0,
			       HPPE_AC_UNICAST_QUEUE_COUNT, 0, 0, qppe_qm_unicast_head_read);
}

static void
qppe_qm_multicast_head_read (qppe_device_t *qd, u32 i, u32 *v)
{
  ppe_reg_qm_oq_head_mul_t entry = {
    .as_u32 = qppe_mmio_read32 (qd, HPPE_REG_OQ_HEAD_MUL_TBL (i)),
  };

  v[0] = entry.normal_fwd;
  v[1] = entry.egress_mirror;
  v[2] = entry.ingress_mirror;
  v[3] = entry.empty;
  v[4] = entry.head;
  v[5] = entry.tail;
}

u8 *
format_qppe_qm_multicast_head (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  const char *const columns[] = {
    "queue", "normal_fwd", "egress_mirror", "ingress_mirror", "empty", "head", "tail",
  };

  return qppe_qm_format_table (s, dev, "OQ_HEAD_MUL_TBL", columns, ARRAY_LEN (columns),
			       HPPE_AC_MULTICAST_QUEUE_BASE, HPPE_AC_MULTICAST_QUEUE_COUNT, 0, 0,
			       qppe_qm_multicast_head_read);
}

static void
qppe_qm_ucast_hash_map_read (qppe_device_t *qd, u32 i, u32 *v)
{
  i8 offset = qppe_mmio_read32 (qd, HPPE_REG_UCAST_HASH_MAP_TBL (i));

  v[0] = i / HPPE_QM_MAP_KEYS;
  v[1] = offset;
}

u8 *
format_qppe_qm_ucast_hash_map (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  const char *const columns[] = {
    "profile",
    "RSS hash",
    "queue_offset",
  };

  return qppe_qm_format_maps (s, dev, "UCAST_HASH_MAP_TBL", columns, HPPE_QM_PRIORITY_PROFILES,
			      HPPE_QM_MAP_KEYS, qppe_qm_ucast_hash_map_read);
}

static void
qppe_qm_oq_ll_uni_read (qppe_device_t *qd, u32 i, u32 *v)
{
  v[0] = qppe_mmio_read32 (qd, HPPE_REG_OQ_LL_UNI_TBL (i)) & 0x7ff;
}

u8 *
format_qppe_qm_unicast_links (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  const char *const columns[] = {
    "entry",
    "next_pointer",
  };

  return qppe_qm_format_table (s, dev, "OQ_LL_UNI_TBL", columns, ARRAY_LEN (columns), 0,
			       HPPE_QM_OQ_LL_ENTRIES, 0, 0, qppe_qm_oq_ll_uni_read);
}

static void
qppe_qm_oq_ll_mul_read (qppe_device_t *qd, u32 i, u32 *v)
{
  const u32 bases[] = {
    HPPE_REG_OQ_LL_MUL_P0_TBL (0), HPPE_REG_OQ_LL_MUL_P1_TBL (0), HPPE_REG_OQ_LL_MUL_P2_TBL (0),
    HPPE_REG_OQ_LL_MUL_P3_TBL (0), HPPE_REG_OQ_LL_MUL_P4_TBL (0), HPPE_REG_OQ_LL_MUL_P5_TBL (0),
    HPPE_REG_OQ_LL_MUL_P6_TBL (0), HPPE_REG_OQ_LL_MUL_P7_TBL (0),
  };
  u32 port = i / HPPE_QM_OQ_LL_ENTRIES;
  u32 index = i % HPPE_QM_OQ_LL_ENTRIES;
  ppe_reg_qm_oq_ll_mul_t entry = {
    .as_u32 = qppe_mmio_read32 (qd, bases[port] + 0x10 * index),
  };

  v[0] = port;
  v[1] = entry.normal_fwd;
  v[2] = entry.egress_mirror;
  v[3] = entry.ingress_mirror;
  v[4] = entry.next_pointer;
}

u8 *
format_qppe_qm_multicast_links (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  const char *const columns[] = {
    "port", "entry", "normal_fwd", "egress_mirror", "ingress_mirror", "next_pointer",
  };

  return qppe_qm_format_table (s, dev, "OQ_LL_MUL_P0-7_TBL", columns, ARRAY_LEN (columns), 0,
			       QPPE_MAX_PORTS * HPPE_QM_OQ_LL_ENTRIES, HPPE_QM_OQ_LL_ENTRIES, 1,
			       qppe_qm_oq_ll_mul_read);
}

typedef struct
{
  const char *name;
  u16 offset;
  u8 width;
  u8 view;
} qppe_qm_descriptor_field_t;

static const qppe_qm_descriptor_field_t qppe_qm_descriptor_fields[] = {
#define _(name, offset, width, view)                                                               \
  {                                                                                                \
    #name,                                                                                         \
    offset,                                                                                        \
    width,                                                                                         \
    view,                                                                                          \
  },
  foreach_qppe_qm_descriptor_field
#undef _
};

static void
qppe_qm_descriptor_read (qppe_device_t *qd, u32 index, const u32 masks[2][HPPE_QM_PKT_DESP_WORDS],
			 u32 *words)
{
  u32 base = HPPE_REG_PKT_DESP_TBL (index);

  for (u32 w = 0; w < HPPE_QM_PKT_DESP_WORDS; w++)
    words[w] = qppe_mmio_read32 (qd, base + sizeof (u32) * w);
  for (u32 w = 0, view = (words[1] >> 6) & 1; w < HPPE_QM_PKT_DESP_WORDS; w++)
    words[w] &= masks[view][w];
}

u8 *
format_qppe_qm_packet_descriptors (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 masks[2][HPPE_QM_PKT_DESP_WORDS] = {};
  u32 indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  /* Compare the selected timestamp view, excluding its reserved bits. */
  for (u32 f = 0; f < ARRAY_LEN (qppe_qm_descriptor_fields); f++)
    {
      const qppe_qm_descriptor_field_t *field = qppe_qm_descriptor_fields + f;

      ASSERT (field->width > 0 && field->width < 64 && field->offset % 32 + field->width <= 64 &&
	      field->offset + field->width <= HPPE_QM_PKT_DESP_WORDS * 32);
      for (u32 view = 0; view < 2; view++)
	if (!field->view || field->view == view + 1)
	  for (u32 bit = field->offset; bit < field->offset + field->width; bit++)
	    masks[view][bit / 32] |= 1u << (bit % 32);
    }

  for (u32 index = 0; index < HPPE_QM_PKT_DESP_ENTRIES; index++)
    {
      table_t table = {};
      u32 first = index, row = 0;
      u32 words[HPPE_QM_PKT_DESP_WORDS];
      u32 view;

      qppe_qm_descriptor_read (qd, index, masks, words);
      while (index + 1 < HPPE_QM_PKT_DESP_ENTRIES)
	{
	  u32 next[HPPE_QM_PKT_DESP_WORDS];

	  qppe_qm_descriptor_read (qd, index + 1, masks, next);
	  if (memcmp (words, next, sizeof (words)))
	    break;
	  index++;
	}

      /* TS_DIR is bit 38: TX fields for zero, RX timestamp fields for one. */
      view = ((words[1] >> 6) & 1) ? 2 : 1;
      table_add_hdr_col (&table, 1, "");
      for (u32 f = 0; f < ARRAY_LEN (qppe_qm_descriptor_fields); f++)
	{
	  const qppe_qm_descriptor_field_t *field = qppe_qm_descriptor_fields + f;
	  u32 word = field->offset / 32;
	  u64 value = words[word];

	  if (field->view && field->view != view)
	    continue;
	  if (field->offset % 32 + field->width > 32)
	    value |= (u64) words[word + 1] << 32;
	  value = (value >> (field->offset % 32)) & (((u64) 1 << field->width) - 1);
	  table_format_cell (&table, row, -1, "%s", field->name);
	  if (field->width > 4)
	    table_format_cell (&table, row, 0, "0x%llx (%llu)", value, value);
	  else
	    table_format_cell (&table, row, 0, "%llu", value);
	  row++;
	}
      table_add_hdr_row (&table, 2, "Field", "Value");
      if (first)
	{
	  s = format (s, "\n");
	  s = format_newline (s, indent);
	}
      if (first == index)
	s = format (s, "PKT_DESP_TBL[%u]:", first);
      else
	s = format (s, "PKT_DESP_TBL[%u-%u]:", first, index);
      s = format_newline (s, indent + 2);
      s = format (s, "%U", format_table, &table);
      table_free (&table);
    }
  return s;
}
