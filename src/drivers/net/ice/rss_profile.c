/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <ice.h>

/* The seven-entry IP families distinguish fragments, payload, UDP, TCP,
 * SCTP and ICMP. Tunnel families select the last IP header, not the outer
 * transport header used to carry it. */
static int
ice_rss_ptype (u16 ptype, u8 *ip, u8 *transport)
{
  static const struct
  {
    u16 base;
    u8 protocol;
  } families[] = {
    {
      22,
      32,
    },
    {
      29,
      33,
    },
    {
      36,
      41,
    },
    {
      44,
      33,
    },
    {
      51,
      41,
    },
    {
      59,
      33,
    },
    {
      66,
      41,
    },
    {
      88,
      40,
    },
    {
      95,
      33,
    },
    {
      102,
      41,
    },
    {
      110,
      33,
    },
    {
      117,
      41,
    },
    {
      125,
      33,
    },
    {
      132,
      41,
    },
  };
  static const struct
  {
    u16 base;
    u8 protocol;
    u8 count;
  } compact[] = {
    {
      302,
      32,
      6,
    },
    {
      308,
      40,
      6,
    },
    {
      331,
      33,
      5,
    },
    {
      336,
      33,
      5,
    },
    {
      341,
      41,
      5,
    },
    {
      346,
      41,
      5,
    },
    {
      402,
      33,
      6,
    },
    {
      408,
      41,
      6,
    },
    {
      414,
      33,
      6,
    },
    {
      420,
      41,
      6,
    },
  };

  *transport = 0;
  for (u32 i = 0; i < ARRAY_LEN (families); i++)
    if (ptype >= families[i].base && ptype < families[i].base + 7)
      {
	u32 offset = ptype - families[i].base;
	if (offset == 3)
	  return 0;
	*ip = families[i].protocol;
	if (offset == 2)
	  *transport = 53;
	else if (offset == 4)
	  *transport = 49;
	else if (offset == 5)
	  *transport = 96;
	return 1;
      }
  for (u32 i = 0; i < ARRAY_LEN (compact); i++)
    if (ptype >= compact[i].base && ptype < compact[i].base + compact[i].count)
      {
	u32 offset = ptype - compact[i].base;
	*ip = compact[i].protocol;
	if (offset == 2)
	  *transport = 53;
	else if (offset == 3)
	  *transport = 49;
	else if (offset == 4 && compact[i].count == 6)
	  *transport = 96;
	return 1;
      }
  if ((ptype >= 160 && ptype <= 169) || (ptype >= 325 && ptype <= 330) ||
      (ptype >= 360 && ptype <= 361) || (ptype >= 396 && ptype <= 401))
    {
      if ((ptype >= 160 && ptype <= 169) || ptype >= 396)
	*ip = ptype & 1 ? 40 : 32;
      else if (ptype >= 325 && ptype <= 330)
	*ip = ptype & 1 ? 32 : 40;
      else
	*ip = ptype == 361 ? 40 : 32;
      return 1;
    }
  if (ptype == 43 || ptype == 58 || ptype == 109 || ptype == 124 || (ptype >= 351 && ptype <= 354))
    {
      *ip = ptype == 43 || ptype == 58 || ptype == 351 || ptype == 352 ? 32 : 40;
      return 1;
    }
  return 0;
}

static void
ice_rss_profile_words (ice_rss_profile_plan_t *profile, u8 ip, u8 transport)
{
  u32 address_words = ip == 40 || ip == 41 ? 16 : 4;
  u32 offset = address_words == 16 ? 8 : 12;

  *profile = (ice_rss_profile_plan_t) {};
  for (u32 i = 0; i < ICE_PROFILE_FV_WORDS; i++)
    profile->words[i] = (ice_profile_fv_t) { .protocol = 255, .offset = 511 };
  for (u32 i = 0; i < address_words; i++)
    profile->words[ICE_PROFILE_FV_WORDS - 1 - profile->n_words++] =
      (ice_profile_fv_t) { .protocol = ip, .offset = offset + i * 2 };
  if (transport)
    for (u32 i = 0; i < 2; i++)
      profile->words[ICE_PROFILE_FV_WORDS - 1 - profile->n_words++] =
	(ice_profile_fv_t) { .protocol = transport, .offset = i * 2 };
}

vnet_dev_rv_t
ice_rss_make_plan (const u8 *xlt1, ice_rss_plan_t *plan)
{
  u8 ip_by_group[256] = {}, transport_by_group[256] = {}, l3_only[256] = {};

  *plan = (ice_rss_plan_t) {};
  for (u32 ptype = 0; ptype < ICE_PROFILE_PTYPE_COUNT; ptype++)
    {
      u8 ip, transport, group = xlt1[ptype];
      if (!group || !ice_rss_ptype (ptype, &ip, &transport))
	continue;
      if (ip_by_group[group] && ip_by_group[group] != ip)
	return VNET_DEV_ERR_NOT_SUPPORTED;
      if (ip_by_group[group] && transport_by_group[group] != transport)
	l3_only[group] = 1;
      ip_by_group[group] = ip;
      transport_by_group[group] = transport;
    }
  for (u32 group = 1; group < 256; group++)
    {
      ice_rss_profile_plan_t candidate;
      u32 index;
      if (!ip_by_group[group])
	continue;
      /* Some packages group SCTP or other IP payload with fragments. Such
       * a group can safely hash addresses, but cannot always extract ports. */
      if (l3_only[group])
	transport_by_group[group] = 0;
      ice_rss_profile_words (&candidate, ip_by_group[group], transport_by_group[group]);
      for (index = 0; index < plan->n_profiles; index++)
	if (!clib_memcmp (candidate.words, plan->profiles[index].words, sizeof (candidate.words)))
	  break;
      if (index == plan->n_profiles)
	{
	  if (index == ARRAY_LEN (plan->profiles))
	    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
	  plan->profiles[plan->n_profiles++] = candidate;
	}
      plan->profiles[index].groups[group / uword_bits] |= (uword) 1 << (group % uword_bits);
    }
  return plan->n_profiles ? VNET_DEV_OK : VNET_DEV_ERR_NOT_SUPPORTED;
}

vnet_dev_rv_t
ice_rss_prepare_lut (const u8 *queues, u16 n_queues, const vnet_dev_rss_config_t *saved, u8 *lut)
{
  u8 enabled[ICE_RSS_MAX_QUEUES] = {};
  int preserve = saved->set_lut && saved->lut_len == ICE_RSS_LUT_SIZE;

  if (!n_queues)
    return VNET_DEV_ERR_NOT_READY;
  if (n_queues > ICE_RSS_MAX_QUEUES)
    return VNET_DEV_ERR_INVALID_ARG;
  for (u32 i = 0; i < n_queues; i++)
    {
      if (queues[i] >= ARRAY_LEN (enabled) || enabled[queues[i]])
	return VNET_DEV_ERR_INVALID_ARG;
      enabled[queues[i]] = 1;
    }
  if (preserve)
    for (u32 i = 0; i < ICE_RSS_LUT_SIZE; i++)
      if (saved->lut[i] >= ARRAY_LEN (enabled) || !enabled[saved->lut[i]])
	{
	  preserve = 0;
	  break;
	}
  for (u32 i = 0; i < ICE_RSS_LUT_SIZE; i++)
    lut[i] = preserve ? saved->lut[i] : queues[i % n_queues];
  return VNET_DEV_OK;
}
