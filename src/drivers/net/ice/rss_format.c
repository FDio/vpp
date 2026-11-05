/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <ice.h>
#include <vppinfra/format_table.h>

static u8 *
format_ice_rss_hinset (u8 *s, va_list *args)
{
  ice_reg_glqf_hinset_t *values = va_arg (*args, ice_reg_glqf_hinset_t *);
  ice_reg_glqf_hinset_t *symmetric = va_arg (*args, ice_reg_glqf_hinset_t *);
  u32 indent = format_get_indent (s);

  table_t inputs = {};
  u32 row = 0;

  table_add_hdr_row (&inputs, 5, "input", "enabled", "FV selector", "XOR enabled",
		     "XOR FV selector");
  for (u32 first = 0; first < ICE_PROFILE_FV_WORDS; row++)
    {
      ice_reg_input_set_word_t field = values[first / 4].words[first % 4];
      ice_reg_input_set_word_t sym = symmetric[first / 4].words[first % 4];
      u32 last = first;

      while (last + 1 < ICE_PROFILE_FV_WORDS)
	{
	  ice_reg_input_set_word_t next = values[(last + 1) / 4].words[(last + 1) % 4];
	  ice_reg_input_set_word_t next_sym = symmetric[(last + 1) / 4].words[(last + 1) % 4];

	  if (next.valid != field.valid || next.fv_word_index != field.fv_word_index ||
	      next_sym.valid != sym.valid || next_sym.fv_word_index != sym.fv_word_index)
	    break;
	  last++;
	}
      if (first == last)
	table_format_cell (&inputs, row, 0, "%u", first);
      else
	table_format_cell (&inputs, row, 0, "%u-%u", first, last);
      table_format_cell (&inputs, row, 1, "%s", field.valid ? "yes" : "no");
      table_format_cell (&inputs, row, 2, "%u", field.fv_word_index);
      table_format_cell (&inputs, row, 3, "%s", sym.valid ? "yes" : "no");
      table_format_cell (&inputs, row, 4, "%u", sym.fv_word_index);
      first = last + 1;
    }
  s = format (s, "Hash input set:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &inputs);
  table_free (&inputs);
  return s;
}

static vnet_dev_rv_t
ice_rss_dump_selection (vlib_main_t *vm, vnet_dev_port_t *port, u16 **addresses,
			u8 profiles[ICE_PROFILE_COUNT], u8 **s)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_pkg_xlt2_entry_t xlt2 = {
    .count = 1,
    .offset = ip->vsi.num,
  };
  ice_profile_tcam_block_t block;
  u8 xlt1[ICE_PROFILE_PTYPE_COUNT];
  uword *ptypes[256] = {};
  table_t mapping = {};
  u32 row = 0;
  vnet_dev_rv_t rv;

  if ((rv = ice_profile_read_xlt1 (vm, port->dev, ICE_RSS_SECTION_XLT1, xlt1)) ||
      (rv = ice_profile_section (vm, port->dev, ICE_RSS_SECTION_XLT2, &xlt2, sizeof (xlt2), 1)))
    return rv;
  if (xlt2.count != 1 || xlt2.offset != ip->vsi.num)
    return VNET_DEV_ERR_INVALID_DATA;
  *s =
    format (*s, "    VSI %u: group %u, PF %u", ip->vsi.num, xlt2.value & 0x1fff, xlt2.value >> 13);
  *s = format_newline (*s, 4);
  *s = format (*s, "Packet type groups:");
  for (u32 ptype = 0; ptype < ARRAY_LEN (xlt1); ptype++)
    ptypes[xlt1[ptype]] = clib_bitmap_set (ptypes[xlt1[ptype]], ptype, 1);
  table_add_hdr_row (&mapping, 2, "group", "packet types");
  table_set_cell_align (&mapping, -1, 1, TTAA_LEFT);
  for (u32 group = 0; group < ARRAY_LEN (ptypes); group++)
    {
      if (!ptypes[group])
	continue;
      table_format_cell (&mapping, row, 0, "%u", group);
      table_format_cell (&mapping, row, 1, "%U", format_bitmap_list, ptypes[group]);
      table_set_cell_align (&mapping, row, 1, TTAA_LEFT);
      clib_bitmap_free (ptypes[group]);
      row++;
    }
  *s = format_newline (*s, 6);
  *s = format (*s, "%U", format_table, &mapping);
  *s = format_newline (*s, 0);
  table_free (&mapping);

  for (u32 first = 0; first < ICE_PROFILE_TCAM_COUNT; first += ARRAY_LEN (block.entries))
    {
      block = (typeof (block)) {
	.count = ARRAY_LEN (block.entries),
      };
      for (u32 i = 0; i < ARRAY_LEN (block.entries); i++)
	block.entries[i].address = first + i;
      if ((rv =
	     ice_profile_section (vm, port->dev, ICE_RSS_SECTION_TCAM, &block, sizeof (block), 1)))
	return rv;
      if (block.count != ARRAY_LEN (block.entries))
	return VNET_DEV_ERR_INVALID_DATA;
      for (u32 i = 0; i < block.count; i++)
	{
	  ice_profile_tcam_t *entry = block.entries + i;
	  u8 vsig[2] = {
	    xlt2.value,
	    xlt2.value >> 8,
	  };
	  int match = 1;

	  if (entry->address != first + i)
	    return VNET_DEV_ERR_INVALID_DATA;
	  for (u32 j = 0; j < 5; j++)
	    if ((entry->key[j] | entry->key[j + 5]) != 0xff)
	      match = 0;
	  for (u32 j = 0; j < 2; j++)
	    if (((vsig[j] ^ 0xff) & (entry->key[j + 3] ^ 0xff)) ||
		(vsig[j] & (entry->key[j + 8] ^ 0xff)))
	      match = 0;
	  if (!match)
	    continue;
	  if (entry->profile >= ICE_PROFILE_COUNT)
	    return VNET_DEV_ERR_INVALID_DATA;
	  vec_add1 (*addresses, entry->address);
	  profiles[entry->profile] = 1;
	}
    }
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
ice_rss_dump_controls (vlib_main_t *vm, vnet_dev_port_t *port, ice_reg_vsiqf_hash_ctl_t control,
		       u8 **s)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  table_t regions = {}, queues = {};
  ice_aqc_vsi_props_t props = {};
  vnet_dev_rv_t rv = ice_aq_get_vsi (vm, port->dev, ip->vsi.num, &props);
  static const char *schemes[] = {
    "Toeplitz",
    "symmetric Toeplitz",
    "simple XOR",
    "reserved",
  };
  static const char *luts[] = {
    "VSI",
    "reserved",
    "PF",
    "global",
  };

  if (rv)
    return rv;
  *s = format (*s, "    Hash controls:");
  *s = format_newline (*s, 6);
  *s = format (*s, "scheme: %s (%u), lookup table: %s (%u), global table index: %u",
	       schemes[control.hash_scheme], control.hash_scheme, luts[control.lut_select],
	       control.lut_select, control.global_lut);
  *s = format_word_wrap_last_line_with_indent (*s, 100, 2);
  *s = format_newline (*s, 6);
  *s = format (*s, "profile TC override: %s, table index: %u",
	       control.tc_override_enable ? "enabled" : "disabled", control.tc_override_select);
  *s = format_newline (*s, 4);
  *s = format (*s, "Queue regions (within VSI):");
  table_add_hdr_row (&regions, 4, "TC", "base", "size log2", "queue count");
  for (u32 i = 0; i < 4; i++)
    {
      ice_reg_vsiqf_tc_region_t value = {
	.as_u32 = ice_reg_read (port->dev, ICE_VSIQF_TC_REGION (ip->vsi.num, i)),
      };

      for (u32 j = 0; j < 2; j++)
	{
	  u32 row = i * 2 + j;
	  ice_reg_tc_region_t region = value.regions[j];

	  table_format_cell (&regions, row, 0, "%u", row);
	  table_format_cell (&regions, row, 1, "%u", region.base);
	  table_format_cell (&regions, row, 2, "%u", region.size_log2);
	  if (region.size_log2 <= 8)
	    table_format_cell (&regions, row, 3, "%u", 1U << region.size_log2);
	  else
	    table_format_cell (&regions, row, 3, "reserved");
	}
    }
  *s = format_newline (*s, 6);
  *s = format (*s, "%U", format_table, &regions);
  *s = format_newline (*s, 0);
  table_free (&regions);
  *s = format (*s, "    RX queue mapping (%s):",
	       props.mapping_flags.noncontiguous ? "noncontiguous" : "contiguous: base, count");
  table_add_hdr_row (&queues, 2, "entry", "value");
  for (u32 i = 0, row = 0; i < ARRAY_LEN (props.q_mapping); row++)
    {
      u32 last = i;

      while (last + 1 < ARRAY_LEN (props.q_mapping) &&
	     props.q_mapping[last + 1] == props.q_mapping[i])
	last++;
      if (i == last)
	table_format_cell (&queues, row, 0, "%u", i);
      else
	table_format_cell (&queues, row, 0, "%u-%u", i, last);
      table_format_cell (&queues, row, 1, "%u", props.q_mapping[i]);
      i = last + 1;
    }
  *s = format_newline (*s, 6);
  *s = format (*s, "%U", format_table, &queues);
  *s = format_newline (*s, 0);
  table_free (&queues);
  return VNET_DEV_OK;
}

static void
ice_rss_dump_lut (vnet_dev_port_t *port, ice_reg_vsiqf_hash_ctl_t control, u8 **s)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  table_t lut = {};
  u32 count = ICE_RSS_LUT_SIZE;
  u32 entry_mask = 0xf;

  if (control.lut_select == 1)
    {
      *s = format (*s, "    RSS lookup table: reserved selection\n");
      return;
    }
  if (control.lut_select == 2)
    {
      u32 size = ice_reg_read (port->dev, ICE_PFQF_HLUT_SIZE) & 3;
      static const u32 sizes[] = {
	128,
	512,
	2048,
	0,
      };

      count = sizes[size];
      entry_mask = 0xff;
    }
  else if (control.lut_select == 3)
    {
      count = ice_reg_read (port->dev, ICE_GLQF_HLUT_SIZE (control.global_lut)) & 1 ? 512 : 128;
      entry_mask = 0x3f;
    }
  *s = format (*s, "    RSS lookup table (%u entries):", count);
  if (!count)
    {
      *s = format (*s, " reserved size encoding\n");
      return;
    }
  table_add_hdr_row (&lut, 9, "entry", "+0", "+1", "+2", "+3", "+4", "+5", "+6", "+7");
  for (u32 first = 0; first < count; first += 8)
    {
      table_format_cell (&lut, first / 8, 0, "%u", first);
      for (u32 j = 0; j < 8; j += 4)
	{
	  u32 index = (first + j) / 4;
	  u32 value;

	  if (control.lut_select == 0)
	    value = ice_reg_read (port->dev, ICE_VSIQF_HLUT (ip->vsi.num, index));
	  else if (control.lut_select == 2)
	    value = ice_reg_read (port->dev, ICE_PFQF_HLUT (index));
	  else
	    value = ice_reg_read (port->dev, ICE_GLQF_HLUT (control.global_lut, index));
	  for (u32 k = 0; k < 4; k++)
	    table_format_cell (&lut, first / 8, j + k + 1, "%u", (value >> (k * 8)) & entry_mask);
	}
    }
  *s = format_newline (*s, 6);
  *s = format (*s, "%U", format_table, &lut);
  *s = format_newline (*s, 0);
  table_free (&lut);
}

static void
ice_rss_dump_masks (vnet_dev_t *dev, u8 **s)
{
  table_t masks = {};
  ice_reg_glqf_hmask_t values[32];
  u32 row = 0;

  for (u32 i = 0; i < ARRAY_LEN (values); i++)
    values[i].as_u32 = ice_reg_read (dev, ICE_GLQF_HMASK (i));
  table_add_hdr_row (&masks, 3, "mask", "input word", "keep mask");
  for (u32 first = 0; first < ARRAY_LEN (values); row++)
    {
      u32 last = first;

      while (last + 1 < ARRAY_LEN (values) &&
	     values[last + 1].word_index == values[first].word_index &&
	     values[last + 1].mask == values[first].mask)
	last++;
      if (first == last)
	table_format_cell (&masks, row, 0, "%u", first);
      else
	table_format_cell (&masks, row, 0, "%u-%u", first, last);
      table_format_cell (&masks, row, 1, "%u", values[first].word_index);
      table_format_cell (&masks, row, 2, "0x%04x", values[first].mask);
      first = last + 1;
    }
  *s = format (*s, "  Input masks (shared by profiles):");
  *s = format_newline (*s, 4);
  *s = format (*s, "%U", format_table, &masks);
  *s = format_newline (*s, 0);
  table_free (&masks);
}

static void
ice_rss_dump_profile_tc (vnet_dev_t *dev, u32 profile, u8 **s)
{
  table_t overrides = {};
  ice_reg_profile_tc_override_t values[32];
  u32 row = 0;
  int enabled = 0;

  for (u32 group = 0; group < 4; group++)
    {
      u32 value = ice_reg_read (dev, ICE_GLQF_PROF2TC (profile, group));

      for (u32 i = 0; i < 8; i++)
	{
	  values[group * 8 + i].as_u8 = (value >> (i * 4)) & 0xf;
	  enabled |= values[group * 8 + i].enable;
	}
    }
  if (!enabled)
    {
      *s = format (*s, "      Traffic class overrides: none");
      *s = format_newline (*s, 0);
      return;
    }
  table_add_hdr_row (&overrides, 3, "table", "override enabled", "TC");
  for (u32 first = 0; first < ARRAY_LEN (values); row++)
    {
      u32 last = first;

      while (last + 1 < ARRAY_LEN (values) && values[last + 1].as_u8 == values[first].as_u8)
	last++;
      if (first == last)
	table_format_cell (&overrides, row, 0, "%u", first);
      else
	table_format_cell (&overrides, row, 0, "%u-%u", first, last);
      table_format_cell (&overrides, row, 1, "%s", values[first].enable ? "yes" : "no");
      table_format_cell (&overrides, row, 2, "%u", values[first].region);
      first = last + 1;
    }
  *s = format (*s, "      Traffic class overrides:");
  *s = format_newline (*s, 8);
  *s = format (*s, "%U", format_table, &overrides);
  *s = format_newline (*s, 0);
  table_free (&overrides);
}

vnet_dev_rv_t
ice_dump_rss (vlib_main_t *vm, vnet_dev_t *dev, void *data)
{
  u8 **s = data;
  vnet_dev_rv_t rv, release_rv;

  rv = ice_aq_request_resource (vm, dev, ICE_AQ_RES_ID_CHANGE_LOCK, ICE_AQ_RES_ACCESS_WRITE, 1000);
  if (rv)
    return rv;
  ice_rss_dump_masks (dev, s);
  foreach_vnet_dev_port (port, dev)
    {
      ice_port_t *ip = vnet_dev_get_port_data (port);
      ice_aq_rss_key_t key;
      ice_reg_vsiqf_hash_ctl_t control;
      u8 profiles[ICE_PROFILE_COUNT] = {};
      u16 *addresses = 0;

      *s = format (*s, "  port %u RSS:\n", port->port_id);
      if (!ip->vsi.added)
	{
	  *s = format (*s, "    no VSI\n");
	  continue;
	}
      if ((rv = ice_aq_get_rss_key (vm, port, &key)))
	break;
      control.as_u32 = ice_reg_read (dev, ICE_VSIQF_HASH_CTL (ip->vsi.num));
      if ((rv = ice_rss_dump_controls (vm, port, control, s)))
	break;
      *s = format (*s, "    Hash key:");
      *s = format_newline (*s, 6);
      *s =
	format (*s, "standard: %U", format_hex_bytes, key.standard_key, sizeof (key.standard_key));
      *s = format_word_wrap_last_line_with_indent (*s, 100, 2);
      *s = format_newline (*s, 6);
      *s =
	format (*s, "extended: %U", format_hex_bytes, key.extended_key, sizeof (key.extended_key));
      *s = format_newline (*s, 0);
      ice_rss_dump_lut (port, control, s);
      rv = ice_rss_dump_selection (vm, port, &addresses, profiles, s);
      if (!rv)
	rv = ice_profile_dump_tcam (vm, dev, ICE_RSS_SECTION_TCAM, addresses, s);
      vec_free (addresses);
      if (rv)
	break;
      for (u32 profile = 0; profile < ICE_PROFILE_COUNT; profile++)
	{
	  ice_reg_glqf_hinset_t inputs[ICE_PROFILE_FV_WORDS / 4];
	  ice_reg_glqf_hinset_t symmetric[ICE_PROFILE_FV_WORDS / 4];
	  u32 mask_select;

	  if (!profiles[profile])
	    continue;
	  if ((rv = ice_profile_dump (vm, dev, ICE_RSS_SECTION_FV, profile, s)))
	    break;
	  for (u32 i = 0; i < ARRAY_LEN (inputs); i++)
	    {
	      inputs[i].as_u32 = ice_reg_read (dev, ICE_GLQF_HINSET (profile, i));
	      symmetric[i].as_u32 = ice_reg_read (dev, ICE_GLQF_HSYMM (profile, i));
	    }
	  *s = format (*s, "      %U", format_ice_rss_hinset, inputs, symmetric);
	  *s = format_newline (*s, 6);
	  mask_select = ice_reg_read (dev, ICE_GLQF_HMASK_SEL (profile));
	  *s = format (*s, "Selected input masks:");
	  if (!mask_select)
	    *s = format (*s, " none");
	  for (u32 i = 0; i < 32; i++)
	    if (mask_select & (1U << i))
	      *s = format (*s, " %u", i);
	  *s = format_word_wrap_last_line_with_indent (*s, 100, 2);
	  *s = format_newline (*s, 0);
	  ice_rss_dump_profile_tc (dev, profile, s);
	}
      if (rv)
	break;
    }
  release_rv = ice_aq_release_resource (vm, dev, ICE_AQ_RES_ID_CHANGE_LOCK);
  return rv ? rv : release_rv;
}
