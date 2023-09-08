// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2023 Cisco Systems, Inc.

/*
 * npt66.c: NPT66 plugin
 * An implementation of Network Prefix Translation for IPv6-to-IPv6 (NPTv6) as
 * specified in RFC6296.
 */

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <vppinfra/pool.h>
#include "npt66.h"

static int
npt66_feature_enable_disable (u32 sw_if_index, bool is_add)
{
  if (vnet_feature_enable_disable ("ip6-unicast", "npt66-input", sw_if_index,
				   is_add, 0, 0) != 0)
    return -1;
  if (vnet_feature_enable_disable ("ip6-output", "npt66-output", sw_if_index,
				   is_add, 0, 0) != 0)
    return -1;
  return 0;
}

static void
ipv6_prefix_zero (ip6_address_t *address, int prefix_len)
{
  int byte_index = prefix_len / 8;
  int bit_offset = prefix_len % 8;
  uint8_t mask = (1 << (8 - bit_offset)) - 1;
  if (byte_index < 16)
    {
      address->as_u8[byte_index] &= mask;
      for (int i = byte_index + 1; i < 16; i++)
	{
	  address->as_u8[i] = 0;
	}
    }
}

int
npt66_binding_add_del (u32 sw_if_index, ip6_address_t *internal,
		       int internal_plen, ip6_address_t *external,
		       int external_plen, bool is_add)
{
  npt66_main_t *nm = &npt66_main;
  int rv = 0;

  /* Currently limited to a single binding per interface */
  npt66_binding_t *b = npt66_interface_by_sw_if_index (sw_if_index);

  if (is_add)
    {
      bool configure_feature = false;
      /* Ensure prefix lengths are less than or equal to a /64 */
      if (internal_plen > 64 || external_plen > 64)
	return VNET_API_ERROR_INVALID_VALUE;

      /* Create a binding entry (or update existing) */
      if (!b)
	{
	  pool_get_zero (nm->bindings, b);
	  configure_feature = true;
	}
      b->internal = *internal;
      b->internal_plen = internal_plen;
      b->external = *external;
      b->external_plen = external_plen;
      b->sw_if_index = sw_if_index;

      ipv6_prefix_zero (&b->internal, internal_plen);
      ipv6_prefix_zero (&b->external, external_plen);
      vec_validate_init_empty (nm->interface_by_sw_if_index, sw_if_index, ~0);
      nm->interface_by_sw_if_index[sw_if_index] = b - nm->bindings;

      uword delta = 0;
      delta = ip_csum_add_even (delta, b->external.as_u64[0]);
      delta = ip_csum_add_even (delta, b->external.as_u64[1]);
      delta = ip_csum_sub_even (delta, b->internal.as_u64[0]);
      delta = ip_csum_sub_even (delta, b->internal.as_u64[1]);
      delta = ip_csum_fold (delta);
      b->delta = delta;

      if (configure_feature)
	rv = npt66_feature_enable_disable (sw_if_index, is_add);
    }
  else
    {
      /* Delete a binding entry */
      npt66_binding_t *b = npt66_interface_by_sw_if_index (sw_if_index);
      if (!b)
	return VNET_API_ERROR_NO_SUCH_ENTRY;
      nm->interface_by_sw_if_index[sw_if_index] = ~0;
      pool_put (nm->bindings, b);
      rv = npt66_feature_enable_disable (sw_if_index, is_add);
    }

  return rv;
}

/*
 * Do a lookup in the interface vector (interface_by_sw_if_index)
 * and return pool entry.
 */
npt66_binding_t *
npt66_interface_by_sw_if_index (u32 sw_if_index)
{
  npt66_main_t *nm = &npt66_main;

  if (!nm->interface_by_sw_if_index ||
      sw_if_index > (vec_len (nm->interface_by_sw_if_index) - 1))
    return 0;
  u32 index = nm->interface_by_sw_if_index[sw_if_index];
  if (index == ~0)
    return 0;
  if (pool_is_free_index (nm->bindings, index))
    return 0;
  return pool_elt_at_index (nm->bindings, index);
}
