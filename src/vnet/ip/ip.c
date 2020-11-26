/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vnet/ip/ip.h>
#include <vnet/fib/fib_table.h>

u8
ip_is_zero (ip46_address_t * ip46_address, u8 is_ip4)
{
  if (is_ip4)
    return (ip46_address->ip4.as_u32 == 0);
  else
    return (ip46_address->as_u64[0] == 0 && ip46_address->as_u64[1] == 0);
}

u8
ip_is_local_host (ip46_address_t * ip46_address, u8 is_ip4)
{
  if (is_ip4)
    return (ip46_address->ip4.as_u8[0] == 127);
  else
    return (ip46_address->as_u64[0] == 0 &&
	    clib_net_to_host_u64 (ip46_address->as_u64[1]) == 1);
}

u8
ip4_is_local_host (ip4_address_t * ip4_address)
{
  return (ip4_address->as_u8[0] == 127);
}

u8
ip6_is_local_host (ip6_address_t * ip6_address)
{
  return (ip6_address->as_u64[0] == 0 &&
	  clib_net_to_host_u64 (ip6_address->as_u64[1]) == 1);
}

/**
 * Checks that an ip is local to the requested fib
 */
u8
ip_is_local (u32 fib_index, ip46_address_t * ip46_address, u8 is_ip4)
{
  fib_node_index_t fei;
  fib_entry_flag_t flags;
  fib_prefix_t prefix;

  /* Check if requester is local */
  if (is_ip4)
    {
      prefix.fp_len = 32;
      prefix.fp_proto = FIB_PROTOCOL_IP4;
    }
  else
    {
      prefix.fp_len = 128;
      prefix.fp_proto = FIB_PROTOCOL_IP6;
    }

  clib_memcpy_fast (&prefix.fp_addr, ip46_address, sizeof (ip46_address_t));
  fei = fib_table_lookup (fib_index, &prefix);
  flags = fib_entry_get_flags (fei);

  return (flags & FIB_ENTRY_FLAG_LOCAL);
}

void
ip_copy (ip46_address_t * dst, ip46_address_t * src, u8 is_ip4)
{
  if (is_ip4)
    {
      ip46_address_mask_ip4 (dst);
      dst->ip4.as_u32 = src->ip4.as_u32;
    }
  else
    clib_memcpy_fast (&dst->ip6, &src->ip6, sizeof (ip6_address_t));
}

void
ip_set (ip46_address_t * dst, void *src, u8 is_ip4)
{
  if (is_ip4)
    {
      ip46_address_mask_ip4 (dst);
      dst->ip4.as_u32 = ((ip4_address_t *) src)->as_u32;
    }
  else
    clib_memcpy_fast (&dst->ip6, (ip6_address_t *) src,
		      sizeof (ip6_address_t));
}

/* *INDENT-OFF* */
static const char *ip_arc_names[N_IP_FEATURE_LOCATIONS][N_AF][N_SAFI] = {
  [IP_FEATURE_INPUT] = {
    [AF_IP4] = {
      [SAFI_UNICAST] = "ip4-unicast",
      [SAFI_MULTICAST] = "ip4-multicast",
    },
    [AF_IP6] = {
      [SAFI_UNICAST] = "ip6-unicast",
      [SAFI_MULTICAST] = "ip6-multicast",
    },
  },
  [IP_FEATURE_OUTPUT] = {
    [AF_IP4] = {
      [SAFI_UNICAST] = "ip4-output",
      [SAFI_MULTICAST] = "ip4-output",
    },
    [AF_IP6] = {
      [SAFI_UNICAST] = "ip6-output",
      [SAFI_MULTICAST] = "ip6-output",
    },
  },
  [IP_FEATURE_LOCAL] = {
    [AF_IP4] = {
      [SAFI_UNICAST] = "ip4-local",
      [SAFI_MULTICAST] = "ip4-local",
    },
    [AF_IP6] = {
      [SAFI_UNICAST] = "ip6-local",
      [SAFI_MULTICAST] = "ip6-local",
    },
  },
  [IP_FEATURE_PUNT] = {
    [AF_IP4] = {
      [SAFI_UNICAST] = "ip4-punt",
      [SAFI_MULTICAST] = "ip4-punt",
    },
    [AF_IP6] = {
      [SAFI_UNICAST] = "ip6-punt",
      [SAFI_MULTICAST] = "ip6-punt",
    },
  },
  [IP_FEATURE_DROP] = {
    [AF_IP4] = {
      [SAFI_UNICAST] = "ip4-drop",
      [SAFI_MULTICAST] = "ip4-drop",
    },
    [AF_IP6] = {
      [SAFI_UNICAST] = "ip6-drop",
      [SAFI_MULTICAST] = "ip6-drop",
    },
  },
};
/* *INDENT-ON* */

void
ip_feature_enable_disable (ip_address_family_t af,
			   ip_sub_address_family_t safi,
			   ip_feature_location_t loc,
			   const char *feature_name,
			   u32 sw_if_index, int enable,
			   void *feature_config, u32 n_feature_config_bytes)
{
  if (IP_FEATURE_INPUT == loc)
    {
      if (N_SAFI == safi)
	FOR_EACH_IP_ADDRESS_SUB_FAMILY (safi)
	  vnet_feature_enable_disable (ip_arc_names[loc][af][safi],
				       feature_name, sw_if_index,
				       enable, feature_config,
				       n_feature_config_bytes);
      else
	vnet_feature_enable_disable (ip_arc_names[loc][af][safi],
				     feature_name, sw_if_index,
				     enable, feature_config,
				     n_feature_config_bytes);
    }
  else
    vnet_feature_enable_disable (ip_arc_names[loc][af][SAFI_UNICAST],
				 feature_name, sw_if_index,
				 enable, feature_config,
				 n_feature_config_bytes);
}



u8 *
format_ip_address_family (u8 * s, va_list * args)
{
  ip_address_family_t af = va_arg (*args, int);	// int promo ip_address_family_t);

  switch (af)
    {
    case AF_IP4:
      return (format (s, "ip4"));
    case AF_IP6:
      return (format (s, "ip6"));
    }

  return (format (s, "unknown"));
}

uword
unformat_ip_address_family (unformat_input_t * input, va_list * args)
{
  ip_address_family_t *af = va_arg (*args, ip_address_family_t *);

  if (unformat (input, "ip4") || unformat (input, "ipv4") ||
      unformat (input, "IP4") || unformat (input, "IPv4"))
    {
      *af = AF_IP4;
      return (1);
    }
  else if (unformat (input, "ip6") || unformat (input, "ipv6") ||
	   unformat (input, "IP6") || unformat (input, "IPv6"))
    {
      *af = AF_IP6;
      return (1);
    }
  return (0);
}

u8 *
format_ip_sub_address_family (u8 * s, va_list * args)
{
  ip_sub_address_family_t safi = va_arg (*args, int);	// int promo ip_sub_address_family_t);

  switch (safi)
    {
    case SAFI_UNICAST:
      return (format (s, "unicast"));
    case SAFI_MULTICAST:
      return (format (s, "multicast"));
    }

  return (format (s, "unknown"));
}

uword
unformat_ip_sub_address_family (unformat_input_t * input, va_list * args)
{
  ip_sub_address_family_t *safi = va_arg (*args, ip_sub_address_family_t *);

  if (unformat (input, "unicast") || unformat (input, "uni"))
    {
      *safi = SAFI_UNICAST;
      return (1);
    }
  else if (unformat (input, "multicast") || unformat (input, "multi"))
    {
      *safi = SAFI_MULTICAST;
      return (1);
    }
  return (0);
}

u8 *
format_ip_dscp (u8 * s, va_list * va)
{
  ip_dscp_t dscp = va_arg (*va, u32);	// int promotion of u8

  switch (dscp)
    {
#define _(n,v)                                                  \
    case IP_DSCP_##v:                                           \
      return (format (s, "%s", #v));
      foreach_ip_dscp
#undef _
    }

  return (format (s, "unknown"));
}

uword
unformat_ip_dscp (unformat_input_t * input, va_list * args)
{
  ip_dscp_t *dscp = va_arg (*args, ip_dscp_t *);

  if (0)
    ;
#define _(n,v)                                                  \
  else if (unformat (input, #v))                                \
    *dscp = IP_DSCP_##v;
  foreach_ip_dscp
#undef _
    else
    return 0;

  return 1;
}

u8 *
format_ip_ecn (u8 * s, va_list * va)
{
  ip_ecn_t ecn = va_arg (*va, u32);	// int promotion of u8

  switch (ecn)
    {
#define _(n,v)                                                  \
    case IP_ECN_##v:                                           \
      return (format (s, "%s", #v));
      foreach_ip_ecn
#undef _
    }

  return (format (s, "unknown"));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
