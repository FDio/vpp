/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/format_table.h>
#include <edma_hw.h>
#include <qppe.h>
#include <ppe_hw.h>

u8 *
format_qppe_port_bitmap (u8 *s, va_list *args)
{
  u32 port_bitmap = va_arg (*args, u32);
  uword *bitmap = clib_bitmap_set_multiple (0, 0, port_bitmap, 32);

  s = format (s, "%U", format_bitmap_list, bitmap);
  clib_bitmap_free (bitmap);
  return s;
}

u8 *
format_qppe_reg_fields (u8 *s, va_list *args)
{
  u32 value = va_arg (*args, u32);
  const qppe_reg_field_t *fields = va_arg (*args, const qppe_reg_field_t *);
  uword n_entries = va_arg (*args, uword);
  table_t table = {};
  u32 offset = 0, row = 0;

  table_add_hdr_col (&table, 1, "");
  for (uword i = 0; i < n_entries; i++)
    {
      u32 n_bits = fields[i].n_bits;
      u32 field_value;

      ASSERT (n_bits > 0 && n_bits <= 32 && offset + n_bits <= 32);
      field_value = n_bits == 32 ? value : (value >> offset) & ((1u << n_bits) - 1);
      offset += n_bits;
      if (fields[i].field_name[0] == '_')
	continue;

      table_format_cell (&table, row, -1, "%s", fields[i].field_name);
      if (n_bits > 4)
	{
	  table_format_cell (&table, row, 0, "0x%x", field_value);
	  table_format_cell (&table, row, 1, "(%u)", field_value);
	  table_set_cell_align (&table, row, 1, TTAA_LEFT);
	}
      else
	table_format_cell (&table, row, 0, "%u", field_value);
      row++;
    }
  table_add_hdr_row (&table, 3, "Field", "Value", "");
  table.row_sizes[0] = clib_max (table.row_sizes[0], 32);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

u8 *
format_qppe_dev_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 indent = format_get_indent (s);

  s = format (s, "platform device %s, device tree node %v", dev->device_id, qd->dt_path);
  s = format_newline (s, indent);
  s = format (s, "register window virtual %p", qd->regs);
  s = format_newline (s, indent);

  if (qd->regs)
    {
      u32 chip_id = qppe_mmio_read32 (qd, 0);
      u32 chip_ver = (chip_id >> 8) & 0xff;
      u32 chip_revision = chip_id & 0xff;
      static const struct
      {
	u8 chip_type;
	const char *chip_name;
      } chip_types[] = {
#define _(type, name) { type, #name },
	foreach_ppe_chip_type
#undef _
      };
      const char *chip_name = "unknown";

      for (u32 i = 0; i < ARRAY_LEN (chip_types); i++)
	if (chip_types[i].chip_type == chip_ver)
	  {
	    chip_name = chip_types[i].chip_name;
	    break;
	  }

      s = format (s, "chip ID 0x%08x (version 0x%02x = %s, revision 0x%02x)", chip_id, chip_ver,
		  chip_name, chip_revision);
      s = format_newline (s, indent);
    }

  s = format (s, "%U", format_qppe_edma_info, a, dev);

  return s;
}
