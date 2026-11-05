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

  if (selector >= 320 && selector < 384)
    return format (s, "%U", format_ice_packet_flag_name, selector - 320);
  if (selector == 128)
    return format (s, "packet drop");
  if (selector == 172)
    return format (s, "management VSI");
  return format (s, "unknown metadata (ID %u, bit %u)", selector / 16, selector % 16);
}

static u16
ice_profile_flag_selector (ice_profile_key_builder_t *builder, u32 cd, u32 flag)
{
  u32 start = 38 + flag * 9;
  u16 selector = 0;

  for (u32 i = 0; i < 9; i++)
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

  if (flag == 15)
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
      u32 one = (key[5 + bit / 8] >> (bit % 8)) & 1;

      if (!(zero | one))
	return format (s, "never");
      value |= (one & !zero) << i;
      mask |= (zero ^ one) << i;
    }
  if (start == 0 && width == 16)
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

u8 *
format_ice_protocol_name_by_id (u8 *s, va_list *args)
{
  u32 id = va_arg (*args, u32);
  static const char *names[] = {
#define _(value, name) [value] = name,
    foreach_ice_protocol_id
#undef _
  };

  if (id < ARRAY_LEN (names) && names[id])
    return format (s, "%s", names[id]);
  return format (s, "unknown (%u)", id);
}

vnet_dev_rv_t
ice_profile_dump_xlt2 (vlib_main_t *vm, vnet_dev_t *dev, u32 sid, u16 vsi, u8 **s)
{
  ice_pkg_xlt2_entry_t entry = {
    .count = 1,
    .offset = vsi,
  };
  vnet_dev_rv_t rv = ice_profile_section (vm, dev, sid, &entry, 6, 1);

  if (rv)
    return rv;
  if (entry.count != 1 || entry.offset != vsi)
    return VNET_DEV_ERR_INVALID_DATA;
  *s = format (*s, "    XLT2 VSI %u: VSIG 0x%04x\n", vsi, entry.value);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
ice_profile_dump (vlib_main_t *vm, vnet_dev_t *dev, u32 fv_sid, u16 id, u8 **s)
{
  ice_profile_fv_section_t fv = {
    .count = 1,
    .offset = id,
  };
  table_t fields = {};
  u32 row = 0;
  u32 indent = format_get_indent (*s) + 4;
  vnet_dev_rv_t rv = ice_profile_section (vm, dev, fv_sid, &fv, sizeof (fv), 1);

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

vnet_dev_rv_t
ice_profile_dump_tcam (vlib_main_t *vm, vnet_dev_t *dev, u32 tcam_sid, u16 *addresses, u8 **s)
{
  table_t tcam_table = {};
  ice_profile_key_builder_t builder = {};
  ice_profile_tcam_t *entries = 0;
  u32 row = 0;
  u32 indent = format_get_indent (*s) + 4;
  u16 *address;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  if (!vec_len (addresses))
    return VNET_DEV_OK;
  ASSERT (tcam_sid == ICE_RSS_SECTION_TCAM || tcam_sid == ICE_FDIR_SECTION_TCAM);
  rv = ice_profile_section (vm, dev,
			    tcam_sid == ICE_RSS_SECTION_TCAM ? ICE_RSS_SECTION_KEY_BUILDER :
							       ICE_FDIR_SECTION_KEY_BUILDER,
			    &builder, sizeof (builder), 1);
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

      if (*address == (u16) ~0)
	continue;
      rv = ice_profile_section (vm, dev, tcam_sid, &tcam, sizeof (tcam), 1);
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
      table_format_cell (&tcam_table, row, 2, "%U", format_ice_tcam_key_field, key, 16U, 8U);
      table_format_cell (&tcam_table, row, 3, "%U", format_ice_tcam_key_field, key, 24U, 13U);
      table_format_cell (&tcam_table, row, 4, "%U", format_ice_tcam_key_field, key, 37U, 3U);
      table_format_cell (&tcam_table, row, 5, "%U", format_ice_tcam_key_field, key, 0U, 16U,
			 &builder);
      table_set_cell_align (&tcam_table, row, 5, TTAA_LEFT);
      first = last + 1;
    }
  if (row)
    {
      *s = format (*s, "%UTCAM:", format_white_space, indent);
      *s = format_newline (*s, indent + 2);
      *s = format (*s, "%U", format_table, &tcam_table);
      *s = format_newline (*s, 0);
    }

done:
  vec_free (entries);
  table_free (&tcam_table);
  return rv;
}
