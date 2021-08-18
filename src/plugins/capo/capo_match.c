/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <capo/capo.h>
#include <capo/capo_match.h>

/* for our bihash 8_24 */
#include <vppinfra/bihash_template.c>

int
capo_match_func (void *p_acl_main, u32 sw_if_index, u32 is_inbound,
		 fa_5tuple_opaque_t *opaque_5tuple, int is_ip6, u8 *r_action,
		 u32 *trace_bitmap)
{
  fa_5tuple_t *pkt_5tuple = (fa_5tuple_t *) opaque_5tuple;
  clib_bihash_kv_8_24_t conf_kv;
  capo_interface_config_t *if_config;
  capo_policy_t *policy;
  u32 *policies;
  int r;
  u32 i;

  conf_kv.key = sw_if_index;
  if (clib_bihash_search_8_24 (&capo_main.if_config, &conf_kv, &conf_kv) != 0)
    {
      /* no config for this interface found, allow */
      *r_action = 2;
      return 0;
    }
  if_config = (capo_interface_config_t *) conf_kv.value;
  policies =
    is_inbound ? if_config->egress_policies : if_config->ingress_policies;

  if (vec_len (policies) == 0)
    goto profiles; /* no policies, jump to profiles */

  *r_action = 0; /* drop by default */

  vec_foreach_index (i, policies)
    {
      policy = &capo_policies[policies[i]];
      r = capo_match_policy (policy, is_inbound, is_ip6, pkt_5tuple);
      switch (r)
	{
	case CAPO_ALLOW:
	  *r_action = 2; /* allow */
	  return 1;
	case CAPO_DENY:
	  return 1;
	case CAPO_PASS:
	  goto profiles;
	case CAPO_LOG:
	  /* TODO: support LOG action */
	  break;
	default:
	  break;
	}
    };
  /* nothing matched, deny */
  return 1;

profiles:
  if (vec_len (if_config->profiles) == 0)
    {
      *r_action = 2; /* no profiles, allow */
      return 1;
    }

  vec_foreach_index (i, if_config->profiles)
    {
      policy = &capo_policies[if_config->profiles[i]];
      r = capo_match_policy (policy, is_inbound, is_ip6, pkt_5tuple);
      switch (r)
	{
	case CAPO_ALLOW:
	  *r_action = 2; /* allow */
	  return 1;
	case CAPO_DENY:
	  return 1;
	case CAPO_PASS:
	  clib_warning ("error: pass in profile %u", if_config->profiles[i]);
	  return 1;
	case CAPO_LOG:
	  /* TODO: support LOG action */
	  break;
	default:
	  break;
	}
    };
  /* nothing matched, deny */
  return 1;
}

int
capo_match_policy (capo_policy_t *policy, u32 is_inbound, u32 is_ip6,
		   fa_5tuple_t *pkt_5tuple)
{
  /* inbound packet from VPP pov is outbound from container pov - need to match
     it against TX policies */
  u32 *rules =
    is_inbound ? policy->rule_ids[VLIB_TX] : policy->rule_ids[VLIB_RX];
  u32 *rule_id;
  capo_rule_t *rule;
  int r;

  vec_foreach (rule_id, rules)
    {
      rule = &capo_rules[*rule_id];
      r = capo_match_rule (rule, is_ip6, pkt_5tuple);
      if (r >= 0)
	{
	  return r;
	}
    }
  return -1;
}

#define SRC 0
#define DST 1

int
capo_match_rule (capo_rule_t *rule, u32 is_ip6, fa_5tuple_t *pkt_5tuple)
{
  //   if (is_ip6 != (rule->af == AF_IP6)) {
  //       return -1;
  //   }

  ip4_address_t *src_ip4 = &pkt_5tuple->ip4_addr[SRC];
  ip4_address_t *dst_ip4 = &pkt_5tuple->ip4_addr[DST];
  ip6_address_t *src_ip6 = &pkt_5tuple->ip6_addr[SRC];
  ip6_address_t *dst_ip6 = &pkt_5tuple->ip6_addr[DST];
  u8 l4proto = pkt_5tuple->l4.proto;
  u16 src_port = pkt_5tuple->l4.port[SRC];
  u16 dst_port = pkt_5tuple->l4.port[DST];
  u16 type = pkt_5tuple->l4.port[0];
  u16 code = pkt_5tuple->l4.port[1];

  capo_rule_filter_t *filter;
  vec_foreach (filter, rule->filters)
    {
      switch (filter->type)
	{
	case CAPO_RULE_FILTER_NONE_TYPE:
	  break;
	case CAPO_RULE_FILTER_L4_PROTO:
	  if (filter->should_match && filter->value != l4proto)
	    return -1;
	  if (!filter->should_match && filter->value == l4proto)
	    return -1;
	  break;
	case CAPO_RULE_FILTER_ICMP_TYPE:
	  if (l4proto == IP_PROTOCOL_ICMP || l4proto == IP_PROTOCOL_ICMP6)
	    {
	      if (filter->should_match && filter->value != type)
		return -1;
	      if (!filter->should_match && filter->value == type)
		return -1;
	    }
	  else
	    // A rule with an ICMP type / code specified doesn't match a
	    // non-icmp packet
	    return -1;
	  break;
	case CAPO_RULE_FILTER_ICMP_CODE:
	  if (l4proto == IP_PROTOCOL_ICMP || l4proto == IP_PROTOCOL_ICMP6)
	    {
	      if (filter->should_match && filter->value != code)
		return -1;
	      if (!filter->should_match && filter->value == code)
		return -1;
	    }
	  else
	    // A rule with an ICMP type / code specified doesn't match a
	    // non-icmp packet
	    return -1;
	  break;
	default:
	  // clib_warning ("unimplemented capo filter!");
	  break;
	}
    }

  /* prefixes */
  if (rule->prefixes[CAPO_SRC])
    {
      ip_prefix_t *prefix;
      u8 found = 0;
      vec_foreach (prefix, rule->prefixes[CAPO_SRC])
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
	  return -1;
	}
    }

  if (rule->prefixes[CAPO_NOT_SRC])
    {
      ip_prefix_t *prefix;
      vec_foreach (prefix, rule->prefixes[CAPO_NOT_SRC])
	{
	  u8 pfx_af = ip_prefix_version (prefix);
	  if (is_ip6 && pfx_af == AF_IP6)
	    {
	      if (ip6_destination_matches_route (&ip6_main, src_ip6,
						 &ip_addr_v6 (&prefix->addr),
						 prefix->len))
		{
		  return -1;
		}
	    }
	  else if (!is_ip6 && pfx_af == AF_IP4)
	    {
	      if (ip4_destination_matches_route (&ip4_main, src_ip4,
						 &ip_addr_v4 (&prefix->addr),
						 prefix->len))
		{
		  return -1;
		}
	    }
	}
    }

  if (rule->prefixes[CAPO_DST])
    {
      ip_prefix_t *prefix;
      u8 found = 0;
      vec_foreach (prefix, rule->prefixes[CAPO_DST])
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
	  return -1;
	}
    }

  if (rule->prefixes[CAPO_NOT_DST])
    {
      ip_prefix_t *prefix;
      vec_foreach (prefix, rule->prefixes[CAPO_NOT_DST])
	{
	  u8 pfx_af = ip_prefix_version (prefix);
	  if (is_ip6 && pfx_af == AF_IP6)
	    {
	      if (ip6_destination_matches_route (&ip6_main, dst_ip6,
						 &ip_addr_v6 (&prefix->addr),
						 prefix->len))
		{
		  return -1;
		}
	    }
	  else if (!is_ip6 && pfx_af == AF_IP4)
	    {
	      if (ip4_destination_matches_route (&ip4_main, dst_ip4,
						 &ip_addr_v4 (&prefix->addr),
						 prefix->len))
		{
		  return -1;
		}
	    }
	}
    }

  /* IP ipsets */
  if (rule->ip_ipsets[CAPO_SRC])
    {
      u32 *ipset;
      u8 found = 0;
      vec_foreach (ipset, rule->ip_ipsets[CAPO_SRC])
	{
	  if (is_ip6)
	    {
	      if (ipset_contains_ip6 (&capo_ipsets[*ipset], src_ip6))
		{
		  found = 1;
		  break;
		}
	    }
	  else
	    {
	      if (ipset_contains_ip4 (&capo_ipsets[*ipset], src_ip4))
		{
		  found = 1;
		  break;
		}
	    }
	}
      if (!found)
	{
	  return -1;
	}
    }

  if (rule->ip_ipsets[CAPO_NOT_SRC])
    {
      u32 *ipset;
      vec_foreach (ipset, rule->ip_ipsets[CAPO_NOT_SRC])
	{
	  if (is_ip6)
	    {
	      if (ipset_contains_ip6 (&capo_ipsets[*ipset], src_ip6))
		{
		  return -1;
		}
	    }
	  else
	    {
	      if (ipset_contains_ip4 (&capo_ipsets[*ipset], src_ip4))
		{
		  return -1;
		}
	    }
	}
    }

  if (rule->ip_ipsets[CAPO_DST])
    {
      u32 *ipset;
      u8 found = 0;
      vec_foreach (ipset, rule->ip_ipsets[CAPO_DST])
	{
	  if (is_ip6)
	    {
	      if (ipset_contains_ip6 (&capo_ipsets[*ipset], dst_ip6))
		{
		  found = 1;
		  break;
		}
	    }
	  else
	    {
	      if (ipset_contains_ip4 (&capo_ipsets[*ipset], dst_ip4))
		{
		  found = 1;
		  break;
		}
	    }
	}
      if (!found)
	{
	  return -1;
	}
    }

  if (rule->ip_ipsets[CAPO_NOT_DST])
    {
      u32 *ipset;
      vec_foreach (ipset, rule->ip_ipsets[CAPO_NOT_DST])
	{
	  if (is_ip6)
	    {
	      if (ipset_contains_ip6 (&capo_ipsets[*ipset], dst_ip6))
		{
		  return -1;
		}
	    }
	  else
	    {
	      if (ipset_contains_ip4 (&capo_ipsets[*ipset], dst_ip4))
		{
		  return -1;
		}
	    }
	}
    }

  /* Special treatment for src / dst ports: they need to be in either the port
     ranges or the port + ip ipsets / */
  u8 src_port_found = 0;
  u8 dst_port_found = 0;

  /* port ranges */
  if (rule->port_ranges[CAPO_SRC])
    {
      capo_port_range_t *range;
      vec_foreach (range, rule->port_ranges[CAPO_SRC])
	{
	  if (range->start <= src_port && src_port <= range->end)
	    {
	      src_port_found = 1;
	      break;
	    }
	}
    }

  if (rule->port_ranges[CAPO_NOT_SRC])
    {
      capo_port_range_t *range;
      vec_foreach (range, rule->port_ranges[CAPO_NOT_SRC])
	{
	  if (range->start <= src_port && src_port <= range->end)
	    {
	      return -1;
	    }
	}
    }

  if (rule->port_ranges[CAPO_DST])
    {
      capo_port_range_t *range;
      vec_foreach (range, rule->port_ranges[CAPO_DST])
	{
	  if (range->start <= dst_port && dst_port <= range->end)
	    {
	      dst_port_found = 1;
	      break;
	    }
	}
    }

  if (rule->port_ranges[CAPO_NOT_DST])
    {
      capo_port_range_t *range;
      vec_foreach (range, rule->port_ranges[CAPO_NOT_DST])
	{
	  if (range->start <= dst_port && dst_port <= range->end)
	    {
	      return -1;
	    }
	}
    }

  /* ipport ipsets */
  if (rule->ipport_ipsets[CAPO_SRC])
    {
      u32 *ipset;
      vec_foreach (ipset, rule->ipport_ipsets[CAPO_SRC])
	{
	  if (is_ip6)
	    {
	      if (ipport_ipset_contains_ip6 (&capo_ipsets[*ipset], src_ip6,
					     l4proto, src_port))
		{
		  src_port_found = 1;
		  break;
		}
	    }
	  else
	    {
	      if (ipport_ipset_contains_ip4 (&capo_ipsets[*ipset], src_ip4,
					     l4proto, src_port))
		{
		  src_port_found = 1;
		  break;
		}
	    }
	}
    }

  if (rule->ipport_ipsets[CAPO_NOT_SRC])
    {
      u32 *ipset;
      vec_foreach (ipset, rule->ipport_ipsets[CAPO_NOT_SRC])
	{
	  if (is_ip6)
	    {
	      if (ipport_ipset_contains_ip6 (&capo_ipsets[*ipset], src_ip6,
					     l4proto, src_port))
		{
		  return -1;
		}
	    }
	  else
	    {
	      if (ipport_ipset_contains_ip4 (&capo_ipsets[*ipset], src_ip4,
					     l4proto, src_port))
		{
		  return -1;
		}
	    }
	}
    }

  if (rule->ipport_ipsets[CAPO_DST])
    {
      u32 *ipset;
      vec_foreach (ipset, rule->ipport_ipsets[CAPO_DST])
	{
	  if (is_ip6)
	    {
	      if (ipport_ipset_contains_ip6 (&capo_ipsets[*ipset], dst_ip6,
					     l4proto, dst_port))
		{
		  dst_port_found = 1;
		  break;
		}
	    }
	  else
	    {
	      if (ipport_ipset_contains_ip4 (&capo_ipsets[*ipset], dst_ip4,
					     l4proto, dst_port))
		{
		  dst_port_found = 1;
		  break;
		}
	    }
	}
    }

  if (rule->ipport_ipsets[CAPO_NOT_DST])
    {
      u32 *ipset;
      vec_foreach (ipset, rule->ipport_ipsets[CAPO_NOT_DST])
	{
	  if (is_ip6)
	    {
	      if (ipport_ipset_contains_ip6 (&capo_ipsets[*ipset], dst_ip6,
					     l4proto, dst_port))
		{
		  return -1;
		}
	    }
	  else
	    {
	      if (ipport_ipset_contains_ip4 (&capo_ipsets[*ipset], dst_ip4,
					     l4proto, dst_port))
		{
		  return -1;
		}
	    }
	}
    }

  if ((rule->port_ranges[CAPO_SRC] || rule->ipport_ipsets[CAPO_SRC]) &&
      (!src_port_found))
    {
      return -1;
    }
  if ((rule->port_ranges[CAPO_DST] || rule->ipport_ipsets[CAPO_DST]) &&
      (!dst_port_found))
    {
      return -1;
    }

  return rule->action;
}

u8
ip_ipset_contains_ip4 (capo_ipset_t *ipset, ip4_address_t *addr)
{
  ASSERT (ipset->type == IPSET_TYPE_IP);
  capo_ipset_member_t *member;
  pool_foreach (member, ipset->members)
    {
      if (member->address.version != AF_IP4)
	continue;
      if (!ip4_address_compare (addr, &ip_addr_v4 (&member->address)))
	return 1;
    }
  return 0;
}

u8
ip_ipset_contains_ip6 (capo_ipset_t *ipset, ip6_address_t *addr)
{
  ASSERT (ipset->type == IPSET_TYPE_IP);
  capo_ipset_member_t *member;
  pool_foreach (member, ipset->members)
    {
      if (member->address.version != AF_IP6)
	continue;
      if (!ip6_address_compare (addr, &ip_addr_v6 (&member->address)))
	return 1;
    }
  return 0;
}

u8
net_ipset_contains_ip4 (capo_ipset_t *ipset, ip4_address_t *addr)
{
  ASSERT (ipset->type == IPSET_TYPE_NET);
  capo_ipset_member_t *member;
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

u8
net_ipset_contains_ip6 (capo_ipset_t *ipset, ip6_address_t *addr)
{
  ASSERT (ipset->type == IPSET_TYPE_NET);
  capo_ipset_member_t *member;
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

u8
ipset_contains_ip4 (capo_ipset_t *ipset, ip4_address_t *addr)
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

u8
ipset_contains_ip6 (capo_ipset_t *ipset, ip6_address_t *addr)
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

u8
ipport_ipset_contains_ip4 (capo_ipset_t *ipset, ip4_address_t *addr,
			   u8 l4proto, u16 port)
{
  ASSERT (ipset->type == IPSET_TYPE_IPPORT);
  capo_ipset_member_t *member;
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

u8
ipport_ipset_contains_ip6 (capo_ipset_t *ipset, ip6_address_t *addr,
			   u8 l4proto, u16 port)
{
  ASSERT (ipset->type == IPSET_TYPE_IPPORT);
  capo_ipset_member_t *member;
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
