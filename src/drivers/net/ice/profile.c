/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <ice.h>

u32
ice_profile_inset_word (u32 group, u32 n_active, u32 total_words)
{
  u32 inset = 0;

  ASSERT (n_active <= total_words);
  ASSERT (total_words % 4 == 0 && group < total_words / 4);
  for (u32 i = 0; i < 4; i++)
    if (group * 4 + i >= total_words - n_active)
      inset |= 0x9fU << (i * 8);
  return inset;
}

/* Uploads use the same section layout as updates. Keeping the wire size
 * explicit avoids compiler tail padding in these variable length sections. */
vnet_dev_rv_t
ice_profile_section (vlib_main_t *vm, vnet_dev_t *dev, u32 sid, void *section, u16 size, int upload)
{
  u8 buffer[ICE_AQ_BUF_SIZE] = {};
  ice_pkg_buf_hdr_t *hdr = (void *) buffer;
  vnet_dev_rv_t rv;
  u32 data_end = sizeof (*hdr) + size;
  /* Firmware requires at least 28 DMA bytes; section lengths exclude padding. */
  u16 length = clib_max (28, round_pow2 (data_end, 4));

  ASSERT (data_end <= sizeof (buffer));
  *hdr = (ice_pkg_buf_hdr_t) {
    .index_table_size = 1,
    .data_end = data_end,
    .section_type = sid,
    .section_offset = sizeof (*hdr),
    .section_size = size,
  };
  clib_memcpy (buffer + sizeof (*hdr), section, size);
  if (upload)
    rv = ice_aq_upload_section (vm, dev, buffer, length);
  else
    rv = ice_aq_update_package (vm, dev, buffer, length, 1);
  if (rv == VNET_DEV_OK && upload)
    clib_memcpy (section, buffer + sizeof (*hdr), size);
  return rv;
}

vnet_dev_rv_t
ice_profile_map_vsi (vlib_main_t *vm, vnet_dev_t *dev, u32 section_id, u16 vsi, u16 vsig)
{
  ice_pkg_xlt2_entry_t entry = { .count = 1, .offset = vsi, .value = vsig };
  return ice_profile_section (vm, dev, section_id, &entry, 6, 0);
}

vnet_dev_rv_t
ice_profile_read_xlt1 (vlib_main_t *vm, vnet_dev_t *dev, u32 section_id, u8 *values)
{
  ice_profile_xlt1_section_t section = { .count = ICE_PROFILE_PTYPE_COUNT };
  vnet_dev_rv_t rv = ice_profile_section (vm, dev, section_id, &section, sizeof (section), 1);

  if (rv)
    return rv;
  if (section.count != ICE_PROFILE_PTYPE_COUNT || section.offset)
    return VNET_DEV_ERR_INVALID_DATA;
  clib_memcpy (values, section.values, sizeof (section.values));
  return VNET_DEV_OK;
}

vnet_dev_rv_t
ice_profile_find_vsig (vlib_main_t *vm, vnet_dev_t *dev, u32 xlt2_id, u32 tcam_id, u16 vsi,
		       u16 *vsig, u16 *saved_vsig)
{
  ice_dev_t *id = vnet_dev_get_data (dev);
  u8 occupied[ICE_PROFILE_VSI_COUNT] = {};
  ice_profile_xlt2_section_t xlt2 = { .count = ICE_PROFILE_VSI_COUNT };
  ice_profile_tcam_block_t tcam;
  vnet_dev_rv_t rv;

  if (vsi >= ICE_PROFILE_VSI_COUNT)
    return VNET_DEV_ERR_INVALID_ARG;
  rv = ice_profile_section (vm, dev, xlt2_id, &xlt2, sizeof (xlt2), 1);
  if (rv)
    return rv;
  if (xlt2.count != ICE_PROFILE_VSI_COUNT || xlt2.offset)
    return VNET_DEV_ERR_INVALID_DATA;
  *saved_vsig = xlt2.values[vsi];
  for (u32 i = 0; i < ARRAY_LEN (xlt2.values); i++)
    if ((xlt2.values[i] >> 13) == id->pf_id && (xlt2.values[i] & 0x1fff) < ARRAY_LEN (occupied))
      occupied[xlt2.values[i] & 0x1fff] = 1;
  for (u32 first = 0; first < ICE_PROFILE_TCAM_COUNT; first += ARRAY_LEN (tcam.entries))
    {
      tcam = (typeof (tcam)) { .count = ARRAY_LEN (tcam.entries) };
      for (u32 i = 0; i < ARRAY_LEN (tcam.entries); i++)
	tcam.entries[i].address = first + i;
      rv = ice_profile_section (vm, dev, tcam_id, &tcam, sizeof (tcam), 1);
      if (rv)
	return rv;
      if (tcam.count > ARRAY_LEN (tcam.entries))
	return VNET_DEV_ERR_INVALID_DATA;
      for (u32 i = 0; i < tcam.count; i++)
	{
	  ice_profile_tcam_t *entry = tcam.entries + i;
	  u16 value = entry->key[8] | ((u16) entry->key[9] << 8);
	  int valid = 1;
	  for (u32 j = 0; j < 5; j++)
	    if ((entry->key[j] | entry->key[j + 5]) != 0xff)
	      valid = 0;
	  if (valid && (entry->key[3] ^ entry->key[8]) == 0xff &&
	      (entry->key[4] ^ entry->key[9]) == 0xff && (value >> 13) == id->pf_id &&
	      (value & 0x1fff) < ARRAY_LEN (occupied))
	    occupied[value & 0x1fff] = 1;
	}
    }
  for (u32 i = ARRAY_LEN (occupied) - 1; i; i--)
    if (!occupied[i])
      {
	*vsig = i | (id->pf_id << 13);
	return VNET_DEV_OK;
      }
  return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
}

vnet_dev_rv_t
ice_profile_write_tcam (vlib_main_t *vm, vnet_dev_t *dev, u32 section_id, u16 address, u8 profile,
			u8 ptg, u16 vsig, int enable)
{
  ice_profile_tcam_entry_section_t section = {
    .count = 1, .entry = { .address = address, .profile = profile }
  };
  u8 value[5] = {
    0, 0, ptg, vsig, vsig >> 8,
  };

  for (u32 i = 0; i < 5; i++)
    {
      section.entry.key[i] = ~value[i];
      section.entry.key[i + 5] = value[i];
    }
  section.entry.key[0] = section.entry.key[1] = 0xff;
  section.entry.key[5] = section.entry.key[6] = 0xff;
  if (!enable)
    section.entry.key[0] = section.entry.key[5] = 0xfe;
  return ice_profile_section (vm, dev, section_id, &section, sizeof (section), 0);
}

/* The caller owns the Change Lock. Preserve indices on failure so cleanup can
 * resume at the first resource whose release has not been confirmed. */
vnet_dev_rv_t
ice_profile_release_tcam (vlib_main_t *vm, vnet_dev_t *dev, u32 section_id, u16 resource_type,
			  u16 *tcam)
{
  u16 *address;
  vnet_dev_rv_t rv;

  vec_foreach (address, tcam)
    {
      if (*address == (u16) ~0)
	continue;
      rv = ice_profile_write_tcam (vm, dev, section_id, *address, 0, 0, 0, 0);
      if (!rv)
	rv = ice_aq_alloc_free_resource (vm, dev, resource_type, 1, address, 0);
      if (rv)
	return rv;
      *address = ~0;
    }
  return VNET_DEV_OK;
}

vnet_dev_rv_t
ice_profile_release_id (vlib_main_t *vm, vnet_dev_t *dev, u16 resource_type, u16 *id)
{
  vnet_dev_rv_t rv;

  rv = ice_aq_alloc_free_resource (vm, dev, resource_type, 1, id, 0);
  if (rv == VNET_DEV_OK)
    *id = ~0;
  return rv;
}
