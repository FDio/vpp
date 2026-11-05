/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <ice.h>
#include <vppinfra/format_table.h>

static u8 *
format_ice_packet_flag_name (u8 *s, va_list *args)
{
  u32 bit = va_arg (*args, u32);
  static const char *names[64] = {
    [0] = "DSI",
    [1] = "IPsec decrypted",
    [2] = "marker",
    [3] = "from network",
    [4] = "RX",
    [5] = "management",
    [8] = "unicast",
    [9] = "multicast",
    [10] = "broadcast",
    [11] = "second outer MAC",
    [12] = "S-tag",
    [13] = "I-tag",
    [14] = "EVLAN 0x8100",
    [15] = "EVLAN 0x9100",
    [16] = "VLAN 0x8100",
    [17] = "NSH over Ethernet",
    [18] = "outer MPLS 0x8847",
    [19] = "outer MPLS 0x8848",
    [20] = "multiple outer MPLS",
    [21] = "inner MPLS",
    [22] = "tunnel MAC",
    [23] = "tunnel VLAN",
    [24] = "IP fragment",
    [25] = "IPv6 routing/destination extension",
    [26] = "double VLAN",
    [28] = "RoCE",
    [29] = "UDP checksum zero",
    [30] = "ESP",
    [31] = "UDP NAT ESP",
    [32] = "TCP FIN",
    [33] = "TCP SYN",
    [34] = "TCP RST",
    [35] = "TCP PSH",
    [36] = "TCP ACK",
    [37] = "TCP URG",
    [38] = "tunnel type bit 0",
    [39] = "tunnel type bit 1",
    [40] = "tunnel type bit 2",
    [41] = "UDP/GRE tunnel",
    [42] = "OAM",
    [43] = "tunnel NSH",
    [44] = "switch direction bit 0",
    [45] = "switch direction bit 1",
    [46] = "SWPE",
    [47] = "switch command",
    [48] = "MAC error",
    [49] = "parser no offload",
    [50] = "parser abort",
    [51] = "partial analysis",
    [60] = "double VLAN mode",
    [61] = "FDIR match",
    [62] = "FDIR long bucket",
    [63] = "drop",
  };

  if (bit < ARRAY_LEN (names) && names[bit])
    return format (s, "%s", names[bit]);

  return format (s, "unknown packet flag (%u)", bit);
}

static u8 *
format_ice_profile_flag_source (u8 *s, va_list *args)
{
  u32 selector = va_arg (*args, u32);

  if (selector >= ICE_METADATA_PACKET_FLAGS &&
      selector < ICE_METADATA_PACKET_FLAGS + ICE_PROFILE_PACKET_FLAG_COUNT)
    return format (s, "%U", format_ice_packet_flag_name, selector - ICE_METADATA_PACKET_FLAGS);

  if (selector == ICE_METADATA_PACKET_DROP)
    return format (s, "packet drop");

  if (selector == ICE_METADATA_MANAGEMENT_VSI)
    return format (s, "management VSI");

  return format (s, "unknown metadata (ID %u, bit %u)", selector / ICE_PROFILE_METADATA_WORD_BITS,
		 selector % ICE_PROFILE_METADATA_WORD_BITS);
}

static u16
ice_profile_flag_selector (ice_profile_key_builder_t *builder, u32 cd, u32 flag)
{
  u32 start = ICE_PROFILE_FLAG_SELECTOR_START + flag * ICE_PROFILE_FLAG_SELECTOR_BITS;
  u16 selector = 0;

  for (u32 i = 0; i < ICE_PROFILE_FLAG_SELECTOR_BITS; i++)
    selector |= ((builder->entries[cd][(start + i) / 8] >> ((start + i) % 8)) & 1) << i;

  return selector;
}

static u8 *
format_ice_profile_flag_name (u8 *s, va_list *args)
{
  ice_profile_key_builder_t *builder = va_arg (*args, ice_profile_key_builder_t *);
  u32 flag = va_arg (*args, u32);
  u16 selector;
  int same = 1;

  if (flag == ICE_PROFILE_FLAG_MASK_INDEX)
    {
      u64 mask = builder->flag15_mask[0] | ((u64) builder->flag15_mask[1] << 32);
      int separator = 0;

      if (!mask)
	return format (s, "false");

      if (count_set_bits (mask) == 1)
	{
	  u32 bit = min_log2 (mask);

	  return format (s, "%U", format_ice_packet_flag_name, bit);
	}

      s = format (s, "any(");

      for (u32 i = 0; i < 64; i++)
	if (mask & (1ULL << i))
	  {
	    s = format (s, "%s%U", separator ? ", " : "", format_ice_packet_flag_name, i);
	    separator = 1;
	  }

      return format (s, ")");
    }

  selector = ice_profile_flag_selector (builder, 0, flag);

  for (u32 cd = 1; cd < ARRAY_LEN (builder->entries); cd++)
    if (ice_profile_flag_selector (builder, cd, flag) != selector)
      same = 0;

  if (same)
    return format (s, "%U", format_ice_profile_flag_source, selector);

  for (u32 cd = 0; cd < ARRAY_LEN (builder->entries); cd++)
    s = format (s, "%sCD%u: %U", cd ? "; " : "", cd, format_ice_profile_flag_source,
		ice_profile_flag_selector (builder, cd, flag));

  return s;
}

static u8 *
format_ice_tcam_key_field (u8 *s, va_list *args)
{
  u8 *key = va_arg (*args, u8 *);
  u32 start = va_arg (*args, u32);
  u32 width = va_arg (*args, u32);
  u32 value = 0, mask = 0;

  for (u32 i = 0; i < width; i++)
    {
      u32 bit = start + i;
      u32 zero = (key[bit / 8] >> (bit % 8)) & 1;
      u32 one = (key[ICE_PROFILE_KEY_BYTES + bit / 8] >> (bit % 8)) & 1;

      if (!(zero | one))
	return format (s, "never");

      value |= (one & !zero) << i;
      mask |= (zero ^ one) << i;
    }

  if (start == ICE_PROFILE_KEY_FLAGS_START && width == ICE_PROFILE_KEY_FLAGS_BITS)
    {
      ice_profile_key_builder_t *builder = va_arg (*args, ice_profile_key_builder_t *);
      int separator = 0;

      for (u32 i = 0; i < width; i++)
	if (mask & (1U << i))
	  {
	    s = format (s, "%s%s%U", separator ? ", " : "", value & (1U << i) ? "" : "!",
			format_ice_profile_flag_name, builder, i);
	    separator = 1;
	  }

      return separator ? s : format (s, "none");
    }

  if (!mask)
    return format (s, "any");

  if (mask == (1U << width) - 1)
    return format (s, "%u", value);

  s = format (s, "0b");

  for (u32 i = width; i > 0; i--)
    s = format (s, "%c", mask & (1U << (i - 1)) ? '0' + ((value >> (i - 1)) & 1) : '*');

  return s;
}

static u8 *
format_ice_protocol_name_by_id (u8 *s, va_list *args)
{
  u32 id = va_arg (*args, u32);
  static const char *names[] = {
#define _(value, name) [value] = (name),
    foreach_ice_protocol_id
#undef _
  };

  if (id < ARRAY_LEN (names) && names[id])
    return format (s, "%s", names[id]);

  return format (s, "unknown (%u)", id);
}

static vnet_dev_rv_t
ice_profile_dump (vlib_main_t *vm, vnet_dev_t *dev, u16 id, u8 **s)
{
  ice_profile_fv_section_t fv = {
    .count = 1,
    .offset = id,
  };
  table_t fields = {};
  int row = 0;
  u32 indent = format_get_indent (*s) + 4;

  vnet_dev_rv_t rv = ice_rss_section (vm, dev, ICE_RSS_SECTION_FV, &fv, sizeof (fv), 1);
  if (rv)
    return rv;

  if (fv.count != 1 || fv.offset != id)
    return VNET_DEV_ERR_INVALID_DATA;

  table_add_hdr_row (&fields, 4, "word", "protocol ID", "protocol", "offset");
  table_set_cell_align (&fields, -1, 2, TTAA_LEFT);

  for (u32 first = 0; first < ARRAY_LEN (fv.words); row++)
    {
      u32 last = first;

      while (last + 1 < ARRAY_LEN (fv.words) &&
	     fv.words[last + 1].protocol == fv.words[first].protocol &&
	     fv.words[last + 1].offset == fv.words[first].offset)
	last++;

      if (first == last)
	table_format_cell (&fields, row, 0, "%u", first);
      else
	table_format_cell (&fields, row, 0, "%u-%u", first, last);

      table_format_cell (&fields, row, 1, "%u", fv.words[first].protocol);
      table_format_cell (&fields, row, 2, "%U", format_ice_protocol_name_by_id,
			 fv.words[first].protocol);
      table_set_cell_align (&fields, row, 2, TTAA_LEFT);
      table_format_cell (&fields, row, 3, "%u", fv.words[first].offset);
      first = last + 1;
    }

  *s = format (*s, "%UProfile %u:", format_white_space, indent, id);
  *s = format_newline (*s, indent + 2);
  *s = format (*s, "Field vector:");
  *s = format_newline (*s, indent + 4);
  *s = format (*s, "%U", format_table, &fields);
  *s = format_newline (*s, 0);
  table_free (&fields);

  return VNET_DEV_OK;
}

static vnet_dev_rv_t
ice_profile_dump_tcam (vlib_main_t *vm, vnet_dev_t *dev, u16 *addresses, u8 **s)
{
  table_t tcam_table = {};
  ice_profile_key_builder_t builder = {};
  ice_profile_tcam_t *entries = 0;
  int row = 0;
  u32 indent = format_get_indent (*s) + 4;
  u16 *address;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  if (!vec_len (addresses))
    return VNET_DEV_OK;

  rv = ice_rss_section (vm, dev, ICE_RSS_SECTION_KEY_BUILDER, &builder, sizeof (builder), 1);
  if (rv)
    return rv;

  table_add_hdr_row (&tcam_table, 6, "entry", "profile", "ptype", "VSI", "PF", "flags");
  table_add_hdr_row (&tcam_table, 6, "", "", "group", "group", "", "");
  table_set_cell_align (&tcam_table, -2, 5, TTAA_LEFT);

  vec_foreach (address, addresses)
    {
      ice_profile_tcam_entry_section_t tcam = {
	.count = 1,
	.entry.address = *address,
      };

      rv = ice_rss_section (vm, dev, ICE_RSS_SECTION_TCAM, &tcam, sizeof (tcam), 1);
      if (rv)
	goto done;

      if (tcam.count != 1 || tcam.entry.address != *address)
	{
	  rv = VNET_DEV_ERR_INVALID_DATA;
	  goto done;
	}

      vec_add1 (entries, tcam.entry);
    }

  for (u32 first = 0; first < vec_len (entries); row++)
    {
      u32 last = first;
      u8 *key = entries[first].key;

      while (last + 1 < vec_len (entries) &&
	     entries[last + 1].address == entries[last].address + 1 &&
	     entries[last + 1].profile == entries[first].profile &&
	     !clib_memcmp (entries[last + 1].key, entries[first].key, sizeof (entries[first].key)))
	last++;

      if (first == last)
	table_format_cell (&tcam_table, row, 0, "%u", entries[first].address);
      else
	table_format_cell (&tcam_table, row, 0, "%u-%u", entries[first].address,
			   entries[last].address);

      table_format_cell (&tcam_table, row, 1, "%u", entries[first].profile);
      table_format_cell (&tcam_table, row, 2, "%U", format_ice_tcam_key_field, key,
			 ICE_PROFILE_KEY_PTG_START, ICE_PROFILE_KEY_PTG_BITS);
      table_format_cell (&tcam_table, row, 3, "%U", format_ice_tcam_key_field, key,
			 ICE_PROFILE_KEY_VSIG_START, ICE_VSIG_GROUP_BITS);
      table_format_cell (&tcam_table, row, 4, "%U", format_ice_tcam_key_field, key,
			 ICE_PROFILE_KEY_PF_START, ICE_VSIG_PF_BITS);
      table_format_cell (&tcam_table, row, 5, "%U", format_ice_tcam_key_field, key,
			 ICE_PROFILE_KEY_FLAGS_START, ICE_PROFILE_KEY_FLAGS_BITS, &builder);
      table_set_cell_align (&tcam_table, row, 5, TTAA_LEFT);
      first = last + 1;
    }

  *s = format (*s, "%UTCAM:", format_white_space, indent);
  *s = format_newline (*s, indent + 2);
  *s = format (*s, "%U", format_table, &tcam_table);
  *s = format_newline (*s, 0);

done:
  vec_free (entries);
  table_free (&tcam_table);
  return rv;
}

static u8 *
format_ice_rss_hinset (u8 *s, va_list *args)
{
  ice_reg_glqf_hinset_t *values = va_arg (*args, ice_reg_glqf_hinset_t *);
  ice_reg_glqf_hinset_t *symmetric = va_arg (*args, ice_reg_glqf_hinset_t *);
  u32 indent = format_get_indent (s);

  table_t inputs = {};
  int row = 0;

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
  ice_vsig_t vsig_value;
  u8 xlt1[ICE_PROFILE_PTYPE_COUNT];
  uword *ptypes[ICE_PROFILE_PTG_COUNT] = {};
  table_t mapping = {};
  int row = 0;
  vnet_dev_rv_t rv;

  rv = ice_rss_read_xlt1 (vm, port->dev, xlt1);

  if (!rv)
    rv = ice_rss_section (vm, port->dev, ICE_RSS_SECTION_XLT2, &xlt2, sizeof (xlt2), 1);

  if (rv)
    return rv;

  if (xlt2.count != 1 || xlt2.offset != ip->vsi.num)
    return VNET_DEV_ERR_INVALID_DATA;

  vsig_value.as_u16 = xlt2.value;

  *s = format (*s, "    VSI %u: group %u, PF %u", ip->vsi.num, vsig_value.group, vsig_value.pf);
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

      rv = ice_rss_section (vm, port->dev, ICE_RSS_SECTION_TCAM, &block, sizeof (block), 1);
      if (rv)
	return rv;

      if (block.count != ARRAY_LEN (block.entries))
	return VNET_DEV_ERR_INVALID_DATA;

      for (u32 i = 0; i < block.count; i++)
	{
	  ice_profile_tcam_t *entry = block.entries + i;
	  int match = 1;

	  if (entry->address != first + i)
	    return VNET_DEV_ERR_INVALID_DATA;

	  for (u32 j = 0; j < ARRAY_LEN (entry->zero.as_u8); j++)
	    if ((entry->zero.as_u8[j] | entry->one.as_u8[j]) != CLIB_U8_MAX)
	      match = 0;

	  if (((xlt2.value ^ CLIB_U16_MAX) & (entry->zero.vsig.as_u16 ^ CLIB_U16_MAX)) ||
	      (xlt2.value & (entry->one.vsig.as_u16 ^ CLIB_U16_MAX)))
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

  for (int i = 0; i < 4; i++)
    {
      ice_reg_vsiqf_tc_region_t value = {
	.as_u32 = ice_reg_read (port->dev, ICE_VSIQF_TC_REGION (ip->vsi.num, i)),
      };

      for (int j = 0; j < 2; j++)
	{
	  int row = i * 2 + j;
	  ice_reg_tc_region_t region = value.regions[j];

	  table_format_cell (&regions, row, 0, "%u", row);
	  table_format_cell (&regions, row, 1, "%u", region.base);
	  table_format_cell (&regions, row, 2, "%u", region.size_log2);

	  if (region.size_log2 <= ICE_RSS_REGION_MAX_SIZE_LOG2)
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
  int row = 0;

  for (u32 i = 0; i < ARRAY_LEN (props.q_mapping); row++)
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
  u32 entry_mask = ICE_RSS_VSI_LUT_ENTRY_MASK;

  if (control.lut_select == ICE_RSS_LUT_RESERVED)
    {
      *s = format (*s, "    RSS lookup table: reserved selection\n");
      return;
    }

  if (control.lut_select == ICE_RSS_LUT_PF)
    {
      ice_reg_pfqf_hlut_size_t size = {
	.as_u32 = ice_reg_read (port->dev, ICE_PFQF_HLUT_SIZE),
      };
      static const u32 sizes[] = {
	[ICE_RSS_PF_LUT_128] = ICE_RSS_LUT_SIZE_128,
	[ICE_RSS_PF_LUT_512] = ICE_RSS_LUT_SIZE_512,
	[ICE_RSS_PF_LUT_2048] = ICE_RSS_LUT_SIZE_2048,
	[ICE_RSS_PF_LUT_RESERVED] = 0,
      };

      count = sizes[size.size];
      entry_mask = ICE_RSS_PF_LUT_ENTRY_MASK;
    }
  else if (control.lut_select == ICE_RSS_LUT_GLOBAL)
    {
      ice_reg_glqf_hlut_size_t size = {
	.as_u32 = ice_reg_read (port->dev, ICE_GLQF_HLUT_SIZE (control.global_lut)),
      };
      static const u32 sizes[] = {
	[ICE_RSS_GLOBAL_LUT_128] = ICE_RSS_LUT_SIZE_128,
	[ICE_RSS_GLOBAL_LUT_512] = ICE_RSS_LUT_SIZE_512,
      };

      count = sizes[size.size];
      entry_mask = ICE_RSS_GLOBAL_LUT_ENTRY_MASK;
    }

  *s = format (*s, "    RSS lookup table (%u entries):", count);

  if (!count)
    {
      *s = format (*s, " reserved size encoding\n");
      return;
    }

  table_add_hdr_row (&lut, 9, "entry", "+0", "+1", "+2", "+3", "+4", "+5", "+6", "+7");

  for (int first = 0; first < count; first += 8)
    {
      table_format_cell (&lut, first / 8, 0, "%u", first);

      for (int j = 0; j < 8; j += 4)
	{
	  u32 index = (first + j) / 4;
	  u32 value;

	  if (control.lut_select == ICE_RSS_LUT_VSI)
	    value = ice_reg_read (port->dev, ICE_VSIQF_HLUT (ip->vsi.num, index));
	  else if (control.lut_select == ICE_RSS_LUT_PF)
	    value = ice_reg_read (port->dev, ICE_PFQF_HLUT (index));
	  else
	    value = ice_reg_read (port->dev, ICE_GLQF_HLUT (control.global_lut, index));

	  for (int k = 0; k < 4; k++)
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
  ice_reg_glqf_hmask_t values[ICE_PROFILE_MASK_COUNT];
  int row = 0;

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
  ice_reg_profile_tc_override_t values[ICE_PROFILE_TC_OVERRIDE_COUNT];
  ice_reg_glqf_prof2tc_t reg;
  int row = 0;
  int enabled = 0;

  for (u32 group = 0; group < ARRAY_LEN (values) / (2 * ARRAY_LEN (reg.pairs)); group++)
    {
      reg.as_u32 = ice_reg_read (dev, ICE_GLQF_PROF2TC (profile, group));

      for (u32 i = 0; i < ARRAY_LEN (reg.pairs); i++)
	{
	  u32 index = (group * ARRAY_LEN (reg.pairs) + i) * 2;

	  values[index] = (ice_reg_profile_tc_override_t) {
	    .enable = reg.pairs[i].first_enable,
	    .region = reg.pairs[i].first_region,
	  };
	  values[index + 1] = (ice_reg_profile_tc_override_t) {
	    .enable = reg.pairs[i].second_enable,
	    .region = reg.pairs[i].second_region,
	  };
	  enabled |= values[index].enable | values[index + 1].enable;
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

      rv = ice_aq_get_rss_key (vm, port, &key);

      if (rv)
	break;

      control.as_u32 = ice_reg_read (dev, ICE_VSIQF_HASH_CTL (ip->vsi.num));
      rv = ice_rss_dump_controls (vm, port, control, s);

      if (rv)
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
	rv = ice_profile_dump_tcam (vm, dev, addresses, s);

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

	  rv = ice_profile_dump (vm, dev, profile, s);

	  if (rv)
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

	  for (u32 i = 0; i < ICE_PROFILE_MASK_COUNT; i++)
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
