/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vnet/ethernet/ethernet.h>
#include <strings.h>

static const char *const vnet_eth_rss_type_strings[VNET_ETH_RSS_N_TYPES] = {
#define _(sym, str) [VNET_ETH_RSS_TYPE_##sym] = str,
  foreach_vnet_eth_rss_type
#undef _
};

u8 *
format_vnet_eth_rss_type (u8 *s, va_list *args)
{
  vnet_eth_rss_type_t type = (vnet_eth_rss_type_t) va_arg (*args, int);
  const char *name = 0;

  if ((u32) type < ARRAY_LEN (vnet_eth_rss_type_strings))
    name = vnet_eth_rss_type_strings[type];

  if (!name)
    return format (s, "unknown(%u)", (u32) type);

  return format (s, "%s", name);
}

uword
unformat_vnet_eth_rss_type (unformat_input_t *input, va_list *args)
{
  vnet_eth_rss_type_t *type = va_arg (*args, vnet_eth_rss_type_t *);
  u8 *value = 0;

  if (!unformat (input, "%s", &value))
    return 0;

  for (u32 i = 0; i < ARRAY_LEN (vnet_eth_rss_type_strings); i++)
    if (vnet_eth_rss_type_strings[i] && !strcasecmp ((char *) value, vnet_eth_rss_type_strings[i]))
      {
	*type = (vnet_eth_rss_type_t) i;
	vec_free (value);
	return 1;
      }

  vec_free (value);
  return 0;
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
