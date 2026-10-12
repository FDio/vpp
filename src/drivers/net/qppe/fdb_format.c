/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vppinfra/format_table.h>
#include <edma_hw.h>
#include <qppe.h>
#include <ppe_hw.h>

static const qppe_reg_field_t ppe_reg_age_timer_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_age_timer_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_l2_global_conf_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_l2_global_conf_t_fields
#undef _
};

static u8 *
format_qppe_fdb_action (u8 *s, va_list *args)
{
  u32 action = va_arg (*args, u32);
  const char *const names[] = {
    "forward",
    "drop",
    "copy-to-cpu",
    "redirect-to-cpu",
  };

  if (action < ARRAY_LEN (names))
    return format (s, "%s (%u)", names[action], action);
  return format (s, "Unknown(%u)", action);
}

u8 *
format_qppe_fdb_cfg (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 indent = format_get_indent (s), value;

  if (!qd->regs)
    return s;

  value = qppe_mmio_read32 (qd, HPPE_REG_AGE_TIMER);
  s = format (s, "AGE_TIMER: 0x%08x", value);
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_qppe_reg_fields, value, ppe_reg_age_timer_fields,
	      ARRAY_LEN (ppe_reg_age_timer_fields));
  s = format (s, "\n");
  s = format_newline (s, indent);
  value = qppe_mmio_read32 (qd, HPPE_REG_L2_GLOBAL_CONF);
  s = format (s, "L2_GLOBAL_CONF: 0x%08x", value);
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_qppe_reg_fields, value, ppe_reg_l2_global_conf_fields,
	      ARRAY_LEN (ppe_reg_l2_global_conf_fields));
  return s;
}

u8 *
format_qppe_fdb_port_ctrl (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0, indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 8, "port", "new_addr", "new_addr", "station_move", "station_move",
		     "isolation", "txmac", "promisc");
  table_add_hdr_row (&table, 8, "", "lrn_en", "fwd_cmd", "lrn_en", "fwd_cmd", "ports", "en", "en");
  for (u32 port = 0; port < QPPE_MAX_PORTS; port++)
    {
      u32 first = port;
      ppe_reg_port_bridge_ctrl_t value = {
	.as_u32 = qppe_mmio_read32 (qd, HPPE_REG_PORT_BRIDGE_CTRL (port)),
      };

      value.reserved_6_7 = value.reserved_18_31 = 0;
      while (port + 1 < QPPE_MAX_PORTS)
	{
	  ppe_reg_port_bridge_ctrl_t next = {
	    .as_u32 = qppe_mmio_read32 (qd, HPPE_REG_PORT_BRIDGE_CTRL (port + 1)),
	  };

	  next.reserved_6_7 = next.reserved_18_31 = 0;
	  if (next.as_u32 != value.as_u32)
	    break;
	  port++;
	}
      if (first == port)
	table_format_cell (&table, row, 0, "%u", first);
      else
	table_format_cell (&table, row, 0, "%u-%u", first, port);
      table_format_cell (&table, row, 1, "%u", value.new_addr_lrn_en);
      table_format_cell (&table, row, 2, "%U", format_qppe_fdb_action, value.new_addr_fwd_cmd);
      table_format_cell (&table, row, 3, "%u", value.station_move_lrn_en);
      table_format_cell (&table, row, 4, "%U", format_qppe_fdb_action, value.station_move_fwd_cmd);
      table_format_cell (&table, row, 5, "%U", format_qppe_port_bitmap,
			 value.port_isolation_bitmap);
      table_format_cell (&table, row, 6, "%u", value.txmac_en);
      table_format_cell (&table, row, 7, "%u", value.promisc_en);
      row++;
    }

  s = format (s, "PORT_BRIDGE_CTRL:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

u8 *
format_qppe_fdb_learning_limits (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0, indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 5, "port", "en", "limit", "exceed_fwd_cmd", "learned");
  for (u32 port = 0; port < QPPE_MAX_PORTS; port++)
    {
      u32 first = port;
      ppe_reg_port_lrn_limit_ctrl_t value = {
	.as_u32 = qppe_mmio_read32 (qd, HPPE_REG_PORT_LRN_LIMIT_CTRL (port)),
      };
      u32 count = qppe_mmio_read32 (qd, HPPE_REG_PORT_LRN_LIMIT_COUNTER (port)) & 0xfff;

      value._reserved_15 = 0;
      while (port + 1 < QPPE_MAX_PORTS)
	{
	  ppe_reg_port_lrn_limit_ctrl_t next = {
	    .as_u32 = qppe_mmio_read32 (qd, HPPE_REG_PORT_LRN_LIMIT_CTRL (port + 1)),
	  };
	  u32 next_count =
	    qppe_mmio_read32 (qd, HPPE_REG_PORT_LRN_LIMIT_COUNTER (port + 1)) & 0xfff;

	  next._reserved_15 = 0;
	  if (next.as_u32 != value.as_u32 || next_count != count)
	    break;
	  port++;
	}
      if (first == port)
	table_format_cell (&table, row, 0, "%u", first);
      else
	table_format_cell (&table, row, 0, "%u-%u", first, port);
      table_format_cell (&table, row, 1, "%u", value.lrn_lmt_en);
      table_format_cell (&table, row, 2, "%u", value.lrn_lmt_cnt);
      table_format_cell (&table, row, 3, "%U", format_qppe_fdb_action, value.lrn_lmt_exceed_fwd);
      table_format_cell (&table, row, 4, "%u", count);
      row++;
    }

  s = format (s, "PORT_LRN_LIMIT_CTRL/COUNTER:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

static void
qppe_fdb_entry_read (qppe_device_t *qd, u32 base, u32 n_words, qppe_fdb_entry_t *entry)
{
  for (u32 w = 0; w < n_words; w++)
    entry->val[w] = qppe_mmio_read32 (qd, base + sizeof (u32) * w);
}

static u8 *
format_qppe_fdb_mac (u8 *s, va_list *args)
{
  const qppe_fdb_entry_t *entry = va_arg (*args, const qppe_fdb_entry_t *);

  return format (s, "%02x:%02x:%02x:%02x:%02x:%02x", entry->bf.mac_addr_0, entry->bf.mac_addr_1,
		 entry->bf.mac_addr_2, entry->bf.mac_addr_3, entry->bf.mac_addr_4,
		 entry->bf.mac_addr_5);
}

u8 *
format_qppe_fdb_reserved_table (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0, indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 2, "index", "MAC");
  for (u32 index = 0; index < HPPE_RFDB_TBL_ENTRIES; index++)
    {
      qppe_fdb_entry_t entry;
      u32 first = index;

      /* RFDB shares the MAC and valid-bit positions of FDB. */
      qppe_fdb_entry_read (qd, HPPE_REG_RFDB_TBL (index), 2, &entry);
      if (!entry.bf.entry_valid)
	continue;
      entry.val[1] &= 0x1ffff;
      while (index + 1 < HPPE_RFDB_TBL_ENTRIES)
	{
	  qppe_fdb_entry_t next;

	  qppe_fdb_entry_read (qd, HPPE_REG_RFDB_TBL (index + 1), 2, &next);
	  next.val[1] &= 0x1ffff;
	  if (memcmp (entry.val, next.val, 2 * sizeof (u32)))
	    break;
	  index++;
	}
      if (first == index)
	table_format_cell (&table, row, 0, "%u", first);
      else
	table_format_cell (&table, row, 0, "%u-%u", first, index);
      table_format_cell (&table, row, 1, "%U", format_qppe_fdb_mac, &entry);
      row++;
    }

  s = format (s, "RFDB_TBL:");
  s = format_newline (s, indent + 2);
  if (row)
    s = format (s, "%U", format_table, &table);
  else
    s = format (s, "no valid entries");
  table_free (&table);
  return s;
}

u8 *
format_qppe_fdb_table (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0, indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 10, "index", "MAC", "lookup", "VSI", "destination", "destination",
		     "SA", "DA", "hit", "static");
  table_add_hdr_row (&table, 10, "", "", "valid", "", "type", "", "cmd", "cmd", "age", "");
  for (u32 index = 0; index < HPPE_FDB_TBL_ENTRIES; index++)
    {
      qppe_fdb_entry_t entry;
      u32 first = index, dst_value;

      qppe_fdb_entry_read (qd, HPPE_REG_FDB_TBL (index), ARRAY_LEN (entry.val), &entry);
      if (!entry.bf.entry_valid)
	continue;
      entry.bf._reserved0 = 0;
      while (index + 1 < HPPE_FDB_TBL_ENTRIES)
	{
	  qppe_fdb_entry_t next;

	  qppe_fdb_entry_read (qd, HPPE_REG_FDB_TBL (index + 1), ARRAY_LEN (next.val), &next);
	  next.bf._reserved0 = 0;
	  if (memcmp (entry.val, next.val, sizeof (entry.val)))
	    break;
	  index++;
	}
      dst_value = entry.bf.dst_value_0 | (entry.bf.dst_value_1 << 8);
      if (first == index)
	table_format_cell (&table, row, 0, "%u", first);
      else
	table_format_cell (&table, row, 0, "%u-%u", first, index);
      table_format_cell (&table, row, 1, "%U", format_qppe_fdb_mac, &entry);
      table_format_cell (&table, row, 2, "%u", entry.bf.lookup_valid);
      table_format_cell (&table, row, 3, "%u", entry.bf.vsi);
      if (entry.bf.dst_type == 2)
	{
	  table_format_cell (&table, row, 4, "port-id");
	  table_format_cell (&table, row, 5, "%u", dst_value);
	}
      else if (entry.bf.dst_type == 3)
	{
	  table_format_cell (&table, row, 4, "port-bitmap");
	  table_format_cell (&table, row, 5, "%U", format_qppe_port_bitmap, dst_value);
	}
      else
	{
	  table_format_cell (&table, row, 4, "Unknown(%u)", entry.bf.dst_type);
	  table_format_cell (&table, row, 5, "0x%x (%u)", dst_value, dst_value);
	}
      table_format_cell (&table, row, 6, "%U", format_qppe_fdb_action, entry.bf.sa_cmd);
      table_format_cell (&table, row, 7, "%U", format_qppe_fdb_action, entry.bf.da_cmd);
      table_format_cell (&table, row, 8, "%u", entry.bf.hit_age);
      table_format_cell (&table, row, 9, "%u", entry.bf.hit_age == 3);
      row++;
    }

  s = format (s, "FDB_TBL:");
  s = format_newline (s, indent + 2);
  if (row)
    s = format (s, "%U", format_table, &table);
  else
    s = format (s, "no valid entries");
  table_free (&table);
  return s;
}
