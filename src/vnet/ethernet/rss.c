/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vnet/ethernet/ethernet.h>
#include <string.h>
#include <strings.h>

typedef struct
{
  vnet_eth_rss_hash_t hash_bit;
  const char *name;
} vnet_eth_rss_hash_desc_t;

static const vnet_eth_rss_hash_desc_t vnet_eth_rss_hash_desc[] = {
#define _(idx, sym, txt)                                                                           \
  {                                                                                                \
    .hash_bit = VNET_ETH_RSS_T_##sym,                                                              \
    .name = txt,                                                                                   \
  },
  foreach_vnet_eth_rss_hash
#undef _
};

u8
vnet_eth_rss_hash_is_valid (vnet_eth_rss_hash_t hash)
{
  const vnet_eth_rss_hash_t valid_bits =
#define _(idx, sym, txt) VNET_ETH_RSS_T_##sym |
    foreach_vnet_eth_rss_hash 0;
#undef _
  const vnet_eth_rss_hash_t exclusion_groups[] = {
    VNET_ETH_RSS_T_IPV4_SRC_ONLY | VNET_ETH_RSS_T_IPV4_DST_ONLY | VNET_ETH_RSS_T_IPV4,
    VNET_ETH_RSS_T_IPV6_SRC_ONLY | VNET_ETH_RSS_T_IPV6_DST_ONLY | VNET_ETH_RSS_T_IPV6,
  };
  u32 i;

  if ((hash & ~valid_bits) != 0)
    return 0;

  for (i = 0; i < ARRAY_LEN (exclusion_groups); i++)
    if (count_set_bits (hash & exclusion_groups[i]) > 1)
      return 0;

  return 1;
}

u8 *
format_vnet_eth_rss_types (u8 *s, va_list *args)
{
  vnet_eth_rss_hash_t hash = va_arg (*args, vnet_eth_rss_hash_t);
  vnet_eth_rss_hash_t rem = hash;
  u32 i;
  u8 first = 1;

  if (hash == VNET_ETH_RSS_HASH_NOT_SET)
    return format (s, "not-set");

  if (hash == 0)
    return format (s, "none");

  for (i = 0; i < ARRAY_LEN (vnet_eth_rss_hash_desc); i++)
    if (hash & vnet_eth_rss_hash_desc[i].hash_bit)
      {
	s = format (s, "%s%s", first ? "" : ",", vnet_eth_rss_hash_desc[i].name);
	first = 0;
	rem &= ~vnet_eth_rss_hash_desc[i].hash_bit;
      }

  if (rem)
    s = format (s, "%sunknown(0x%x)", first ? "" : ",", rem);

  return s;
}

uword
unformat_vnet_eth_rss_hash (unformat_input_t *input, va_list *args)
{
  vnet_eth_rss_hash_t *hash = va_arg (*args, vnet_eth_rss_hash_t *);
  u8 *value = 0;
  char *next;
  char *tok;
  u8 matched;
  u32 i;

  if (!unformat (input, "%s", &value))
    return 0;

  if (!strcasecmp ((char *) value, "not-set"))
    {
      *hash = VNET_ETH_RSS_HASH_NOT_SET;
      vec_free (value);
      return 1;
    }

  if (!strcasecmp ((char *) value, "disabled"))
    {
      *hash = 0;
      vec_free (value);
      return 1;
    }

  *hash = 0;
  next = (char *) value;
  while ((tok = strsep (&next, "+")))
    {
      matched = 0;
      for (i = 0; i < ARRAY_LEN (vnet_eth_rss_hash_desc); i++)
	if (!strcasecmp (tok, vnet_eth_rss_hash_desc[i].name))
	  {
	    *hash |= vnet_eth_rss_hash_desc[i].hash_bit;
	    matched = 1;
	    break;
	  }

      if (!matched)
	{
	  vec_free (value);
	  return 0;
	}
    }

  if (!vnet_eth_rss_hash_is_valid (*hash))
    {
      vec_free (value);
      return 0;
    }

  vec_free (value);
  return 1;
}

clib_error_t *
vnet_eth_set_rss_config (vnet_main_t *vnm, u32 hw_if_index, vnet_eth_rss_config_t *cfg)
{
  ethernet_main_t *em = vnet_get_ethernet_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface_or_null (vnm, hw_if_index);
  ethernet_interface_t *ei;

  if (cfg == 0)
    return clib_error_return (0, "invalid rss config");

  if (hi == 0)
    return clib_error_return (0, "unknown hw_if_index %u", hw_if_index);

  ei = ethernet_get_interface (em, hw_if_index);
  if (ei == 0 || ei->cb.set_rss_config == 0)
    return vnet_error (VNET_ERR_UNSUPPORTED, "not supported");

  return ei->cb.set_rss_config (vnm, hi, cfg);
}
