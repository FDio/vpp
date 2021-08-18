/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vnet/ip/ip.h>

#include <npol/npol.h>
#include <npol/npol_match.h>

always_inline u8
ip_ipset_contains_ip4 (npol_ipset_t *ipset, ip4_address_t *addr)
{
  ASSERT (ipset->type == IPSET_TYPE_IP);
  npol_ipset_member_t *member;
  pool_foreach (member, ipset->members)
    {
      if (member->address.version != AF_IP4)
	continue;
      if (!ip4_address_compare (addr, &ip_addr_v4 (&member->address)))
	return 1;
    }
  return 0;
}

always_inline u8
ip_ipset_contains_ip6 (npol_ipset_t *ipset, ip6_address_t *addr)
{
  ASSERT (ipset->type == IPSET_TYPE_IP);
  npol_ipset_member_t *member;
  pool_foreach (member, ipset->members)
    {
      if (member->address.version != AF_IP6)
	continue;
      if (!ip6_address_compare (addr, &ip_addr_v6 (&member->address)))
	return 1;
    }
  return 0;
}

always_inline u8
net_ipset_contains_ip4 (npol_ipset_t *ipset, ip4_address_t *addr)
{
  ASSERT (ipset->type == IPSET_TYPE_NET);
  npol_ipset_member_t *member;
  pool_foreach (member, ipset->members)
    {
      if (member->prefix.addr.version != AF_IP4)
	continue;
      if (ip4_destination_matches_route (&ip4_main, addr,
					 &ip_addr_v4 (&member->prefix.addr),
					 member->prefix.len))
	{
	  return 1;
	}
    }
  return 0;
}

always_inline u8
net_ipset_contains_ip6 (npol_ipset_t *ipset, ip6_address_t *addr)
{
  ASSERT (ipset->type == IPSET_TYPE_NET);
  npol_ipset_member_t *member;
  pool_foreach (member, ipset->members)
    {
      if (member->prefix.addr.version != AF_IP6)
	continue;
      if (ip6_destination_matches_route (&ip6_main, addr,
					 &ip_addr_v6 (&member->prefix.addr),
					 member->prefix.len))
	{
	  return 1;
	}
    }
  return 0;
}

always_inline u8
ipset_contains_ip4 (npol_ipset_t *ipset, ip4_address_t *addr)
{
  switch (ipset->type)
    {
    case IPSET_TYPE_IP:
      return ip_ipset_contains_ip4 (ipset, addr);
    case IPSET_TYPE_NET:
      return net_ipset_contains_ip4 (ipset, addr);
    default:
      clib_warning ("Wrong ipset type");
    }
  return 0;
}

always_inline u8
ipset_contains_ip6 (npol_ipset_t *ipset, ip6_address_t *addr)
{
  switch (ipset->type)
    {
    case IPSET_TYPE_IP:
      return ip_ipset_contains_ip6 (ipset, addr);
    case IPSET_TYPE_NET:
      return net_ipset_contains_ip6 (ipset, addr);
    default:
      clib_warning ("Wrong ipset type");
    }
  return 0;
}

always_inline u8
ipport_ipset_contains_ip4 (npol_ipset_t *ipset, ip4_address_t *addr,
			   u8 l4proto, u16 port)
{
  ASSERT (ipset->type == IPSET_TYPE_IPPORT);
  npol_ipset_member_t *member;
  pool_foreach (member, ipset->members)
    {
      if (member->ipport.addr.version != AF_IP4)
	continue;
      if (l4proto == member->ipport.l4proto && port == member->ipport.port &&
	  !ip4_address_compare (addr, &ip_addr_v4 (&member->ipport.addr)))
	{
	  return 1;
	}
    }
  return 0;
}

always_inline u8
ipport_ipset_contains_ip6 (npol_ipset_t *ipset, ip6_address_t *addr,
			   u8 l4proto, u16 port)
{
  ASSERT (ipset->type == IPSET_TYPE_IPPORT);
  npol_ipset_member_t *member;
  pool_foreach (member, ipset->members)
    {
      if (member->ipport.addr.version != AF_IP6)
	continue;
      if (l4proto == member->ipport.l4proto && port == member->ipport.port &&
	  !ip6_address_compare (addr, &ip_addr_v6 (&member->ipport.addr)))
	{
	  return 1;
	}
    }
  return 0;
}

always_inline int
npol_match_rule (npol_rule_t *rule, u32 is_ip6, fa_5tuple_t *pkt_5tuple)
{
  ip4_address_t *src_ip4 = &pkt_5tuple->ip4_addr[SRC];
  ip4_address_t *dst_ip4 = &pkt_5tuple->ip4_addr[DST];
  ip6_address_t *src_ip6 = &pkt_5tuple->ip6_addr[SRC];
  ip6_address_t *dst_ip6 = &pkt_5tuple->ip6_addr[DST];
  u8 l4proto = pkt_5tuple->l4.proto;
  u16 src_port = pkt_5tuple->l4.port[SRC];
  u16 dst_port = pkt_5tuple->l4.port[DST];
  u16 type = pkt_5tuple->l4.port[0];
  u16 code = pkt_5tuple->l4.port[1];

  npol_rule_filter_t *filter;
  vec_foreach (filter, rule->filters)
    {
      switch (filter->type)
	{
	case NPOL_RULE_FILTER_NONE_TYPE:
	  break;
	case NPOL_RULE_FILTER_L4_PROTO:
	  if (filter->should_match && filter->value != l4proto)
	    return -1;
	  if (!filter->should_match && filter->value == l4proto)
	    return -2;
	  break;
	case NPOL_RULE_FILTER_ICMP_TYPE:
	  if (l4proto == IP_PROTOCOL_ICMP || l4proto == IP_PROTOCOL_ICMP6)
	    {
	      if (filter->should_match && filter->value != type)
		return -3;
	      if (!filter->should_match && filter->value == type)
		return -4;
	    }
	  else
	    /* A rule with an ICMP type / code specified doesn't match a
	     * non-icmp packet
	     */
	    return -5;
	  break;
	case NPOL_RULE_FILTER_ICMP_CODE:
	  if (l4proto == IP_PROTOCOL_ICMP || l4proto == IP_PROTOCOL_ICMP6)
	    {
	      if (filter->should_match && filter->value != code)
		return -6;
	      if (!filter->should_match && filter->value == code)
		return -7;
	    }
	  else
	    /* A rule with an ICMP type / code specified doesn't match a
	     * non-icmp packet
	     */
	    return -8;
	  break;
	default:
	  break;
	}
    }

  /* prefixes */
  if (rule->prefixes[NPOL_SRC])
    {
      ip_prefix_t *prefix;
      u8 found = 0;
      vec_foreach (prefix, rule->prefixes[NPOL_SRC])
	{
	  u8 pfx_af = ip_prefix_version (prefix);
	  if (is_ip6 && pfx_af == AF_IP6)
	    {
	      if (ip6_destination_matches_route (&ip6_main, src_ip6,
						 &ip_addr_v6 (&prefix->addr),
						 prefix->len))
		{
		  found = 1;
		  break;
		}
	    }
	  else if (!is_ip6 && pfx_af == AF_IP4)
	    {
	      if (ip4_destination_matches_route (&ip4_main, src_ip4,
						 &ip_addr_v4 (&prefix->addr),
						 prefix->len))
		{
		  found = 1;
		  break;
		}
	    }
	}
      if (!found)
	{
	  return -9;
	}
    }

  if (rule->prefixes[NPOL_NOT_SRC])
    {
      ip_prefix_t *prefix;
      vec_foreach (prefix, rule->prefixes[NPOL_NOT_SRC])
	{
	  u8 pfx_af = ip_prefix_version (prefix);
	  if (is_ip6 && pfx_af == AF_IP6)
	    {
	      if (ip6_destination_matches_route (&ip6_main, src_ip6,
						 &ip_addr_v6 (&prefix->addr),
						 prefix->len))
		{
		  return -10;
		}
	    }
	  else if (!is_ip6 && pfx_af == AF_IP4)
	    {
	      if (ip4_destination_matches_route (&ip4_main, src_ip4,
						 &ip_addr_v4 (&prefix->addr),
						 prefix->len))
		{
		  return -11;
		}
	    }
	}
    }

  if (rule->prefixes[NPOL_DST])
    {
      ip_prefix_t *prefix;
      u8 found = 0;
      vec_foreach (prefix, rule->prefixes[NPOL_DST])
	{
	  u8 pfx_af = ip_prefix_version (prefix);
	  if (is_ip6 && pfx_af == AF_IP6)
	    {
	      if (ip6_destination_matches_route (&ip6_main, dst_ip6,
						 &ip_addr_v6 (&prefix->addr),
						 prefix->len))
		{
		  found = 1;
		  break;
		}
	    }
	  else if (!is_ip6 && pfx_af == AF_IP4)
	    {
	      if (ip4_destination_matches_route (&ip4_main, dst_ip4,
						 &ip_addr_v4 (&prefix->addr),
						 prefix->len))
		{
		  found = 1;
		  break;
		}
	    }
	}
      if (!found)
	{
	  return -12;
	}
    }

  if (rule->prefixes[NPOL_NOT_DST])
    {
      ip_prefix_t *prefix;
      vec_foreach (prefix, rule->prefixes[NPOL_NOT_DST])
	{
	  u8 pfx_af = ip_prefix_version (prefix);
	  if (is_ip6 && pfx_af == AF_IP6)
	    {
	      if (ip6_destination_matches_route (&ip6_main, dst_ip6,
						 &ip_addr_v6 (&prefix->addr),
						 prefix->len))
		{
		  return -13;
		}
	    }
	  else if (!is_ip6 && pfx_af == AF_IP4)
	    {
	      if (ip4_destination_matches_route (&ip4_main, dst_ip4,
						 &ip_addr_v4 (&prefix->addr),
						 prefix->len))
		{
		  return -14;
		}
	    }
	}
    }

  /* IP ipsets */
  if (rule->ip_ipsets[NPOL_SRC])
    {
      u32 *ipset;
      u8 found = 0;
      vec_foreach (ipset, rule->ip_ipsets[NPOL_SRC])
	{
	  if (is_ip6)
	    {
	      if (ipset_contains_ip6 (&npol_ipsets[*ipset], src_ip6))
		{
		  found = 1;
		  break;
		}
	    }
	  else
	    {
	      if (ipset_contains_ip4 (&npol_ipsets[*ipset], src_ip4))
		{
		  found = 1;
		  break;
		}
	    }
	}
      if (!found)
	{
	  return -15;
	}
    }

  if (rule->ip_ipsets[NPOL_NOT_SRC])
    {
      u32 *ipset;
      vec_foreach (ipset, rule->ip_ipsets[NPOL_NOT_SRC])
	{
	  if (is_ip6)
	    {
	      if (ipset_contains_ip6 (&npol_ipsets[*ipset], src_ip6))
		{
		  return -16;
		}
	    }
	  else
	    {
	      if (ipset_contains_ip4 (&npol_ipsets[*ipset], src_ip4))
		{
		  return -17;
		}
	    }
	}
    }

  if (rule->ip_ipsets[NPOL_DST])
    {
      u32 *ipset;
      u8 found = 0;
      vec_foreach (ipset, rule->ip_ipsets[NPOL_DST])
	{
	  if (is_ip6)
	    {
	      if (ipset_contains_ip6 (&npol_ipsets[*ipset], dst_ip6))
		{
		  found = 1;
		  break;
		}
	    }
	  else
	    {
	      if (ipset_contains_ip4 (&npol_ipsets[*ipset], dst_ip4))
		{
		  found = 1;
		  break;
		}
	    }
	}
      if (!found)
	{
	  return -18;
	}
    }

  if (rule->ip_ipsets[NPOL_NOT_DST])
    {
      u32 *ipset;
      vec_foreach (ipset, rule->ip_ipsets[NPOL_NOT_DST])
	{
	  if (is_ip6)
	    {
	      if (ipset_contains_ip6 (&npol_ipsets[*ipset], dst_ip6))
		{
		  return -19;
		}
	    }
	  else
	    {
	      if (ipset_contains_ip4 (&npol_ipsets[*ipset], dst_ip4))
		{
		  return -20;
		}
	    }
	}
    }

  /* Special treatment for src / dst ports: they need to be in either the port
     ranges or the port + ip ipsets / */
  u8 src_port_found = 0;
  u8 dst_port_found = 0;

  /* port ranges */
  if (rule->port_ranges[NPOL_SRC])
    {
      npol_port_range_t *range;
      vec_foreach (range, rule->port_ranges[NPOL_SRC])
	{
	  if (range->start <= src_port && src_port <= range->end)
	    {
	      src_port_found = 1;
	      break;
	    }
	}
    }

  if (rule->port_ranges[NPOL_NOT_SRC])
    {
      npol_port_range_t *range;
      vec_foreach (range, rule->port_ranges[NPOL_NOT_SRC])
	{
	  if (range->start <= src_port && src_port <= range->end)
	    {
	      return -21;
	    }
	}
    }

  if (rule->port_ranges[NPOL_DST])
    {
      npol_port_range_t *range;
      vec_foreach (range, rule->port_ranges[NPOL_DST])
	{
	  if (range->start <= dst_port && dst_port <= range->end)
	    {
	      dst_port_found = 1;
	      break;
	    }
	}
    }

  if (rule->port_ranges[NPOL_NOT_DST])
    {
      npol_port_range_t *range;
      vec_foreach (range, rule->port_ranges[NPOL_NOT_DST])
	{
	  if (range->start <= dst_port && dst_port <= range->end)
	    {
	      return -22;
	    }
	}
    }

  /* ipport ipsets */
  if (rule->ipport_ipsets[NPOL_SRC])
    {
      u32 *ipset;
      vec_foreach (ipset, rule->ipport_ipsets[NPOL_SRC])
	{
	  if (is_ip6)
	    {
	      if (ipport_ipset_contains_ip6 (&npol_ipsets[*ipset], src_ip6,
					     l4proto, src_port))
		{
		  src_port_found = 1;
		  break;
		}
	    }
	  else
	    {
	      if (ipport_ipset_contains_ip4 (&npol_ipsets[*ipset], src_ip4,
					     l4proto, src_port))
		{
		  src_port_found = 1;
		  break;
		}
	    }
	}
    }

  if (rule->ipport_ipsets[NPOL_NOT_SRC])
    {
      u32 *ipset;
      vec_foreach (ipset, rule->ipport_ipsets[NPOL_NOT_SRC])
	{
	  if (is_ip6)
	    {
	      if (ipport_ipset_contains_ip6 (&npol_ipsets[*ipset], src_ip6,
					     l4proto, src_port))
		{
		  return -23;
		}
	    }
	  else
	    {
	      if (ipport_ipset_contains_ip4 (&npol_ipsets[*ipset], src_ip4,
					     l4proto, src_port))
		{
		  return -24;
		}
	    }
	}
    }

  if (rule->ipport_ipsets[NPOL_DST])
    {
      u32 *ipset;
      vec_foreach (ipset, rule->ipport_ipsets[NPOL_DST])
	{
	  if (is_ip6)
	    {
	      if (ipport_ipset_contains_ip6 (&npol_ipsets[*ipset], dst_ip6,
					     l4proto, dst_port))
		{
		  dst_port_found = 1;
		  break;
		}
	    }
	  else
	    {
	      if (ipport_ipset_contains_ip4 (&npol_ipsets[*ipset], dst_ip4,
					     l4proto, dst_port))
		{
		  dst_port_found = 1;
		  break;
		}
	    }
	}
    }

  if (rule->ipport_ipsets[NPOL_NOT_DST])
    {
      u32 *ipset;
      vec_foreach (ipset, rule->ipport_ipsets[NPOL_NOT_DST])
	{
	  if (is_ip6)
	    {
	      if (ipport_ipset_contains_ip6 (&npol_ipsets[*ipset], dst_ip6,
					     l4proto, dst_port))
		{
		  return -25;
		}
	    }
	  else
	    {
	      if (ipport_ipset_contains_ip4 (&npol_ipsets[*ipset], dst_ip4,
					     l4proto, dst_port))
		{
		  return -26;
		}
	    }
	}
    }

  if ((rule->port_ranges[NPOL_SRC] || rule->ipport_ipsets[NPOL_SRC]) &&
      (!src_port_found))
    {
      return -27;
    }
  if ((rule->port_ranges[NPOL_DST] || rule->ipport_ipsets[NPOL_DST]) &&
      (!dst_port_found))
    {
      return -28;
    }

  return rule->action;
}

always_inline int
npol_match_policy (npol_policy_t *policy, u32 is_inbound, u32 is_ip6,
		   fa_5tuple_t *pkt_5tuple)
{
  /* packets RX/TX from VPP perspective */
  u32 *rules =
    is_inbound ? policy->rule_ids[VLIB_RX] : policy->rule_ids[VLIB_TX];
  u32 *rule_id;
  npol_rule_t *rule;
  int r;

  vec_foreach (rule_id, rules)
    {
      rule = &npol_rules[*rule_id];
      r = npol_match_rule (rule, is_ip6, pkt_5tuple);
      if (r >= 0)
	{
	  return r;
	}
    }
  return -1;
}

/*
 * npol_match_func evalutes policies on the packet for which the 5tuple is
 * passed This packet can be :
 * - is_inbound = 1 : received on interface sw_if_index
 * - is_inbound = 0 : to be txed on interface sw_if_index
 * The function sets r_action to NPOL_ACTION_ALLOW or NPOL_ACTION_DENY
 * It returns 1 if a rule was matched, 0 otherwise
 */
CLIB_MARCH_FN (npol_match, int, u32 sw_if_index, u32 is_inbound,
	       fa_5tuple_t *pkt_5tuple, int is_ip6, u8 *r_action)
{
  npol_interface_config_t *if_config;
  npol_policy_t *policy;
  u32 *policies;
  int r;
  u32 i;
  u8 policy_default;
  u8 profile_default;

  if_config = vec_elt_at_index (npol_interface_configs, sw_if_index);
  if (!if_config->enabled)
    {
      /* no config for this interface found, allow */
      *r_action = NPOL_ACTION_ALLOW;
      return 0;
    }
  policies = is_inbound ^ if_config->invert_rx_tx ? if_config->rx_policies :
						    if_config->tx_policies;
  policy_default =
    is_inbound ? if_config->policy_default_rx : if_config->policy_default_tx;
  profile_default =
    is_inbound ? if_config->profile_default_rx : if_config->profile_default_tx;

  vec_foreach_index (i, policies)
    {
      policy = &npol_policies[policies[i]];
      r = npol_match_policy (policy, is_inbound ^ if_config->invert_rx_tx,
			     is_ip6, pkt_5tuple);
      switch (r)
	{
	case NPOL_ALLOW:
	  *r_action = NPOL_ACTION_ALLOW; /* allow */
	  return 1;
	case NPOL_DENY:
	  *r_action = NPOL_ACTION_DENY;
	  return 1;
	case NPOL_PASS:
	  goto profiles;
	case NPOL_LOG:
	  /* TODO: support LOG action */
	  break;
	default:
	  break;
	}
    };
  /* nothing matched, or no policies */
  switch (policy_default)
    {
    case NPOL_ALLOW:
      *r_action = NPOL_ACTION_ALLOW;
      return 1;
    case NPOL_DEFAULT_DENY:
      *r_action = NPOL_ACTION_DENY;
      return 1;
    case NPOL_DEFAULT_PASS:
      goto profiles;
    default:
      break;
    }

profiles:

  vec_foreach_index (i, if_config->profiles)
    {
      policy = &npol_policies[if_config->profiles[i]];
      r = npol_match_policy (policy, is_inbound ^ if_config->invert_rx_tx,
			     is_ip6, pkt_5tuple);
      switch (r)
	{
	case NPOL_ALLOW:
	  *r_action = NPOL_ACTION_ALLOW;
	  return 1;
	case NPOL_DENY:
	  *r_action = NPOL_ACTION_DENY;
	  return 1;
	case NPOL_PASS:
	  clib_warning ("error: pass in profile %u", if_config->profiles[i]);
	  return 1;
	case NPOL_LOG:
	  /* TODO: support LOG action */
	  break;
	default:
	  break;
	}
    };

  /* nothing matched, or no profiles */
  switch (profile_default)
    {
    case NPOL_ALLOW:
      *r_action = NPOL_ACTION_ALLOW;
      return 1;
    case NPOL_DEFAULT_DENY:
      *r_action = NPOL_ACTION_DENY;
      return 1;
    case NPOL_DEFAULT_PASS:
      clib_warning ("error: default pass in profile %u",
		    if_config->profiles[i]);
      return 1;
    default:
      break;
    }
  return 1;
}

#ifndef CLIB_MARCH_VARIANT
int
npol_match_func (u32 sw_if_index, u32 is_inbound, fa_5tuple_t *pkt_5tuple,
		 int is_ip6, u8 *r_action)
{
  return CLIB_MARCH_FN_SELECT (npol_match) (sw_if_index, is_inbound,
					    pkt_5tuple, is_ip6, r_action);
}

#endif /* CLIB_MARCH_VARIANT */
