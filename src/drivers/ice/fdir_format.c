/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <ice.h>

vnet_dev_rv_t
ice_dump_fdir (vlib_main_t *vm, vnet_dev_t *dev, void *data)
{
  u8 **s = data;
  vnet_dev_rv_t rv, release_rv;

  *s = format (*s, "  PFQF_FD_ENA 0x%08x, PFQF_FD_SIZE 0x%08x\n",
	       ice_reg_read (dev, ICE_PFQF_FD_ENA), ice_reg_read (dev, ICE_PFQF_FD_SIZE));
  rv = ice_aq_request_resource (vm, dev, ICE_AQ_RES_ID_CHANGE_LOCK, ICE_AQ_RES_ACCESS_WRITE, 1000);
  if (rv)
    return rv;
  foreach_vnet_dev_port (port, dev)
    {
      ice_port_t *ip = vnet_dev_get_port_data (port);
      ice_fdir_t *fd = ip->fdir;
      ice_fdir_profile_t *profile;

      *s = format (*s, "  port %u FDIR:\n", port->port_id);
      if (!fd)
	{
	  *s = format (*s, "    no allocated resources\n");
	  continue;
	}
      if (fd->mapped &&
	  (rv = ice_profile_dump_xlt2 (vm, dev, ICE_FDIR_SECTION_XLT2, ip->vsi.num, s)))
	break;
      if (fd->vsi_added &&
	  (rv = ice_profile_dump_xlt2 (vm, dev, ICE_FDIR_SECTION_XLT2, fd->vsi, s)))
	break;
      pool_foreach (profile, fd->profiles)
	{
	  if (!profile->allocated)
	    continue;
	  rv = ice_profile_dump (vm, dev, ICE_FDIR_SECTION_FV, ICE_FDIR_SECTION_TCAM, profile->id,
				 profile->tcam, s);
	  if (rv)
	    break;
	  for (u32 i = 0; i < ICE_FDIR_MAX_WORDS / 4; i++)
	    *s = format (*s, "      FDINSET[%u] 0x%08x, FDSWAP[%u] 0x%08x\n", i,
			 ice_reg_read (dev, ICE_GLQF_FDINSET (profile->id, i)), i,
			 ice_reg_read (dev, ICE_GLQF_FDSWAP (profile->id, i)));
	  *s = format (*s, "      FDMASK_SEL 0x%08x\n",
		       ice_reg_read (dev, ICE_GLQF_FDMASK_SEL (profile->id)));
	}
      if (rv)
	break;
      for (u32 i = fd->mask_first; i < fd->mask_first + fd->mask_count; i++)
	*s = format (*s, "    FDMASK[%u] 0x%08x\n", i, ice_reg_read (dev, ICE_GLQF_FDMASK (i)));
      if (fd->counter_allocated)
	for (u32 i = 0; i < ICE_FDIR_COUNTERS; i++)
	  if (fd->counters[i / uword_bits] & ((uword) 1 << (i % uword_bits)))
	    {
	      u16 counter = fd->counter_block * ICE_FDIR_COUNTERS + i;
	      *s = format (*s, "    FD_CNT[%u] %llu packets\n", counter,
			   ice_fdir_counter_read (port, counter));
	    }
    }
  release_rv = ice_aq_release_resource (vm, dev, ICE_AQ_RES_ID_CHANGE_LOCK);
  return rv ? rv : release_rv;
}
