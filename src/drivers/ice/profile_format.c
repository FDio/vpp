/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <ice.h>

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
ice_profile_dump (vlib_main_t *vm, vnet_dev_t *dev, u32 fv_sid, u32 tcam_sid, u16 id,
		  u16 *addresses, u8 **s)
{
  ice_profile_fv_section_t fv = {
    .count = 1,
    .offset = id,
  };
  u16 *address;
  vnet_dev_rv_t rv = ice_profile_section (vm, dev, fv_sid, &fv, sizeof (fv), 1);

  if (rv)
    return rv;
  if (fv.count != 1 || fv.offset != id)
    return VNET_DEV_ERR_INVALID_DATA;
  *s = format (*s, "    profile %u field vector (word, protocol, offset):\n", id);
  for (u32 i = 0; i < ARRAY_LEN (fv.words); i++)
    *s = format (*s, "      %2u %3u %3u\n", i, fv.words[i].protocol, fv.words[i].offset);
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
	return rv;
      if (tcam.count != 1 || tcam.entry.address != *address)
	return VNET_DEV_ERR_INVALID_DATA;
      *s = format (*s, "      TCAM %u: profile %u key %U\n", tcam.entry.address, tcam.entry.profile,
		   format_hex_bytes, tcam.entry.key, sizeof (tcam.entry.key));
    }
  return VNET_DEV_OK;
}
