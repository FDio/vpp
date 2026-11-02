/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <ice.h>

vnet_dev_rv_t
ice_dump_rss (vlib_main_t *vm, vnet_dev_t *dev, void *data)
{
  u8 **s = data;
  vnet_dev_rv_t rv, release_rv;

  rv = ice_aq_request_resource (vm, dev, ICE_AQ_RES_ID_CHANGE_LOCK, ICE_AQ_RES_ACCESS_WRITE, 1000);
  if (rv)
    return rv;
  foreach_vnet_dev_port (port, dev)
    {
      ice_port_t *ip = vnet_dev_get_port_data (port);
      ice_rss_profile_resource_t *profile;
      ice_aq_rss_key_t key;
      ice_aq_rss_lut_t lut;

      *s = format (*s, "  port %u RSS:\n", port->port_id);
      if (!ip->vsi.added)
	{
	  *s = format (*s, "    no VSI\n");
	  continue;
	}
      if ((rv = ice_rss_get_config (vm, port, &key, &lut)) ||
	  (rv = ice_profile_dump_xlt2 (vm, dev, ICE_RSS_SECTION_XLT2, ip->vsi.num, s)))
	break;
      *s = format (*s, "    key: %U\n", format_hex_bytes, &key, sizeof (key));
      for (u32 first = 0; first < ICE_RSS_LUT_SIZE; first += 16)
	{
	  *s = format (*s, "    LUT[%2u-%2u]:", first, first + 15);
	  for (u32 i = first; i < first + 16; i++)
	    *s = format (*s, " %u", lut.entries[i]);
	  *s = format (*s, "\n");
	}
      if (!ip->rss)
	continue;
      vec_foreach (profile, ip->rss->profiles)
	{
	  if (!profile->allocated)
	    continue;
	  rv = ice_profile_dump (vm, dev, ICE_RSS_SECTION_FV, ICE_RSS_SECTION_TCAM, profile->id,
				 profile->tcam, s);
	  if (rv)
	    break;
	  for (u32 i = 0; i < ICE_PROFILE_FV_WORDS / 4; i++)
	    *s = format (*s, "      HINSET[%u] 0x%08x\n", i,
			 ice_reg_read (dev, ICE_GLQF_HINSET (profile->id, i)));
	  *s = format (*s, "      HMASK_SEL 0x%08x\n",
		       ice_reg_read (dev, ICE_GLQF_HMASK_SEL (profile->id)));
	}
      if (rv)
	break;
    }
  release_rv = ice_aq_release_resource (vm, dev, ICE_AQ_RES_ID_CHANGE_LOCK);
  return rv ? rv : release_rv;
}
