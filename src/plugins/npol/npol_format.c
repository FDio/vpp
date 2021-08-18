/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <npol/npol.h>
#include <npol/npol_rule.h>
#include <npol/npol_policy.h>
#include <npol/npol_ipset.h>

u8 *
format_npol_action (u8 *s, va_list *args)
{
  int action = va_arg (*args, int);
  switch (action)
    {
    case NPOL_ACTION_ALLOW:
      return format (s, "ALLOW");
    case NPOL_ACTION_DENY:
      return format (s, "DENY");
    default:
      return format (s, "unknown type %d", action);
    }
}

u8 *
format_npol_ipport (u8 *s, va_list *args)
{
  npol_ipport_t *ipport = va_arg (*args, npol_ipport_t *);
  return format (s, "%U %U;%u", format_ip_protocol, ipport->l4proto,
		 format_ip_address, &ipport->addr, ipport->port);
}

u8 *
format_npol_ipset_member (u8 *s, va_list *args)
{
  npol_ipset_member_t *member = va_arg (*args, npol_ipset_member_t *);
  npol_ipset_type_t type = va_arg (*args, npol_ipset_type_t);
  switch (type)
    {
    case IPSET_TYPE_IP:
      return format (s, "%U", format_ip_address, &member->address);
    case IPSET_TYPE_IPPORT:
      return format (s, "%U", format_npol_ipport, &member->ipport);
    case IPSET_TYPE_NET:
      return format (s, "%U", format_ip_prefix, &member->prefix);
    default:
      return format (s, "unknown type");
    }
}

uword
unformat_npol_ipport (unformat_input_t *input, va_list *args)
{
  npol_ipport_t *ipport = va_arg (*args, npol_ipport_t *);
  u32 proto;
  u32 port;
  if (unformat (input, "%U %U %d", unformat_ip_protocol, &proto,
		unformat_ip_address, &ipport->addr, &port))
    ;
  else
    return 0;

  ipport->port = port;
  ipport->l4proto = (u8) proto;
  return 1;
}

u8 *
format_npol_ipset_type (u8 *s, va_list *args)
{
  npol_ipset_type_t type = va_arg (*args, npol_ipset_type_t);
  switch (type)
    {
    case IPSET_TYPE_IP:
      return format (s, "ip");
    case IPSET_TYPE_IPPORT:
      return format (s, "ip+port");
    case IPSET_TYPE_NET:
      return format (s, "prefix");
    default:
      return format (s, "unknownipsettype");
    }
}

uword
unformat_npol_ipset_member (unformat_input_t *input, va_list *args)
{
  npol_ipset_member_t *member = va_arg (*args, npol_ipset_member_t *);
  npol_ipset_type_t *type = va_arg (*args, npol_ipset_type_t *);
  if (unformat_user (input, unformat_ip_prefix, &member->prefix))
    *type = IPSET_TYPE_NET;
  else if (unformat_user (input, unformat_ip_address, &member->address))
    *type = IPSET_TYPE_IP;
  else if (unformat_user (input, unformat_npol_ipport, &member->ipport))
    *type = IPSET_TYPE_IPPORT;
  else
    return 0;

  return 1;
}

u8 *
format_npol_ipset (u8 *s, va_list *args)
{
  npol_ipset_t *ipset = va_arg (*args, npol_ipset_t *);
  npol_ipset_member_t *member;

  if (ipset == NULL)
    return format (s, "deleted ipset");

  s = format (s, "[ipset#%d;%U;", ipset - npol_ipsets, format_npol_ipset_type,
	      ipset->type);

  pool_foreach (member, ipset->members)
    s = format (s, "%U,", format_npol_ipset_member, member, ipset->type);

  s = format (s, "]");

  return (s);
}

u8 *
format_npol_rule_action (u8 *s, va_list *args)
{
  npol_rule_action_t action = va_arg (*args, int);
  switch (action)
    {
    case NPOL_ALLOW:
      return format (s, "allow");
    case NPOL_DENY:
      return format (s, "deny");
    case NPOL_LOG:
      return format (s, "log");
    case NPOL_PASS:
      return format (s, "pass");
    default:
      return format (s, "unknownaction");
    }
}

uword
unformat_npol_rule_action (unformat_input_t *input, va_list *args)
{
  npol_rule_action_t *action = va_arg (*args, npol_rule_action_t *);
  if (unformat (input, "allow"))
    *action = NPOL_ALLOW;
  else if (unformat (input, "deny"))
    *action = NPOL_DENY;
  else if (unformat (input, "log"))
    *action = NPOL_LOG;
  else if (unformat (input, "pass"))
    *action = NPOL_PASS;
  else
    return 0;
  return 1;
}

u8 *
format_npol_rule_port_range (u8 *s, va_list *args)
{
  npol_port_range_t *port_range = va_arg (*args, npol_port_range_t *);

  if (port_range->start != port_range->end)
    s = format (s, "[%u-%u]", port_range->start, port_range->end);
  else
    s = format (s, "%u", port_range->start);

  return (s);
}

u8 *
format_npol_rule_entry (u8 *s, va_list *args)
{
  npol_rule_entry_t *entry = va_arg (*args, npol_rule_entry_t *);
  npol_ipset_t *ipset;

  s = format (s, "%s", entry->flags & NPOL_IS_SRC ? "src" : "dst");
  s = format (s, "%s", entry->flags & NPOL_IS_NOT ? "!=" : "==");
  switch (entry->type)
    {
    case NPOL_CIDR:
      s = format (s, "%U", format_ip_prefix, &entry->data.cidr);
      break;
    case NPOL_PORT_RANGE:
      s =
	format (s, "%U", format_npol_rule_port_range, &entry->data.port_range);
      break;
    case NPOL_IP_SET:
      ipset = npol_ipsets_get_if_exists (entry->data.set_id);
      s = format (s, "%U", format_npol_ipset, ipset);
      break;
    case NPOL_PORT_IP_SET:
      ipset = npol_ipsets_get_if_exists (entry->data.set_id);
      s = format (s, "%U", format_npol_ipset, ipset);
      break;
    default:
      s = format (s, "unknown");
      break;
    }
  return (s);
}

uword
unformat_rule_key_flag (unformat_input_t *input, va_list *args)
{
  npol_rule_key_flag_t *flags = va_arg (*args, npol_rule_key_flag_t *);
  if (unformat (input, "src=="))
    *flags = NPOL_IS_SRC;
  else if (unformat (input, "src!="))
    *flags = NPOL_IS_SRC | NPOL_IS_NOT;
  else if (unformat (input, "dst!="))
    *flags = NPOL_IS_NOT;
  else if (unformat (input, "dst=="))
    *flags = 0;
  else
    return 0;
  return 1;
}

uword
unformat_npol_port_range (unformat_input_t *input, va_list *args)
{
  npol_port_range_t *port_range = va_arg (*args, npol_port_range_t *);
  u32 start, end;
  if (unformat (input, "[%d-%d]", &start, &end))
    {
      port_range->start = (u16) start;
      port_range->end = (u16) end;
    }
  else
    return 0;
  return 1;
}

uword
unformat_npol_rule_entry (unformat_input_t *input, va_list *args)
{
  npol_rule_entry_t *entry = va_arg (*args, npol_rule_entry_t *);
  if (unformat (input, "%U %U", unformat_rule_key_flag, &entry->flags,
		unformat_ip_prefix, &entry->data.cidr))
    entry->type = NPOL_CIDR;
  else if (unformat (input, "%U %U", unformat_rule_key_flag, &entry->flags,
		     unformat_npol_port_range, &entry->data.port_range))
    entry->type = NPOL_PORT_RANGE;
  else if (unformat (input, "%Uset %u", unformat_rule_key_flag, &entry->flags,
		     &entry->data.set_id))
    entry->type = NPOL_PORT_IP_SET;
  else
    return 0;
  return 1;
}

u8 *
format_npol_rule_filter (u8 *s, va_list *args)
{
  npol_rule_filter_t *filter = va_arg (*args, npol_rule_filter_t *);
  switch (filter->type)
    {
    case NPOL_RULE_FILTER_NONE_TYPE:
      return format (s, "<no filter>");
    case NPOL_RULE_FILTER_ICMP_TYPE:
      return format (s, "icmp-type%s=%d", filter->should_match ? "=" : "!",
		     filter->value);
    case NPOL_RULE_FILTER_ICMP_CODE:
      return format (s, "icmp-code%s=%d", filter->should_match ? "=" : "!",
		     filter->value);
    case NPOL_RULE_FILTER_L4_PROTO:
      return format (s, "proto%s=%U", filter->should_match ? "=" : "!",
		     format_ip_protocol, filter->value);
    default:
      return format (s, "unknown");
    }
}

uword
unformat_npol_should_match (unformat_input_t *input, va_list *args)
{
  u8 *should_match = va_arg (*args, u8 *);
  if (unformat (input, "=="))
    *should_match = 1;
  else if (unformat (input, "!="))
    *should_match = 0;
  else
    return 0;
  return 1;
}

uword
unformat_npol_rule_filter (unformat_input_t *input, va_list *args)
{
  u8 tmp_value;
  npol_rule_filter_t *filter = va_arg (*args, npol_rule_filter_t *);
  if (unformat (input, "icmp-type%U%d", unformat_npol_should_match,
		&filter->should_match, &filter->value))
    filter->type = NPOL_RULE_FILTER_ICMP_TYPE;
  else if (unformat (input, "icmp-code%U%d", unformat_npol_should_match,
		     &filter->should_match, &filter->value))
    filter->type = NPOL_RULE_FILTER_ICMP_CODE;
  else if (unformat (input, "proto%U%U", unformat_npol_should_match,
		     &filter->should_match, unformat_ip_protocol, &tmp_value))
    {
      filter->value = tmp_value;
      filter->type = NPOL_RULE_FILTER_L4_PROTO;
    }
  else
    return 0;
  return 1;
}

u8 *
format_npol_rule (u8 *s, va_list *args)
{
  npol_rule_t *rule = va_arg (*args, npol_rule_t *);
  npol_rule_filter_t *filter;
  npol_rule_entry_t *entry, *entries;

  if (rule == NULL)
    return format (s, "deleted rule");

  s = format (s, "[rule#%d;%U][", rule - npol_rules, format_npol_rule_action,
	      rule->action);

  /* filters */
  vec_foreach (filter, rule->filters)
    {
      if (filter->type != NPOL_RULE_FILTER_NONE_TYPE)
	s = format (s, "%U,", format_npol_rule_filter, filter);
    }

  entries = npol_rule_get_entries (rule);
  vec_foreach (entry, entries)
    s = format (s, "%U,", format_npol_rule_entry, entry);
  vec_free (entries);
  s = format (s, "]");

  return (s);
}

u8 *
format_npol_policy (u8 *s, va_list *args)
{
  npol_policy_t *policy = va_arg (*args, npol_policy_t *);
  int indent = va_arg (*args, int);
  int verbose = va_arg (*args, int);
  int invert_rx_tx = va_arg (*args, int);
  u32 *rule_id;

  if (policy == NULL)
    return format (s, "deleted policy");

  if (verbose)
    {
      s = format (s, "[policy#%u]\n", policy - npol_policies);
      npol_rule_t *rule;
      if (verbose != NPOL_POLICY_ONLY_RX)
	vec_foreach (rule_id, policy->rule_ids[VLIB_TX ^ invert_rx_tx])
	  {
	    rule = npol_rule_get_if_exists (*rule_id);
	    s = format (s, "%Utx:%U\n", format_white_space, indent + 2,
			format_npol_rule, rule);
	  }
      if (verbose != NPOL_POLICY_ONLY_TX)
	vec_foreach (rule_id, policy->rule_ids[VLIB_RX ^ invert_rx_tx])
	  {
	    rule = npol_rule_get_if_exists (*rule_id);
	    s = format (s, "%Urx:%U\n", format_white_space, indent + 2,
			format_npol_rule, rule);
	  }
    }
  else
    {
      s = format (s, "[policy#%u] rx-rules:%d tx-rules:%d\n",
		  policy - npol_policies,
		  vec_len (policy->rule_ids[VLIB_RX ^ invert_rx_tx]),
		  vec_len (policy->rule_ids[VLIB_TX ^ invert_rx_tx]));
    }

  return (s);
}

u8 *
format_npol_interface (u8 *s, va_list *args)
{
  u32 sw_if_index = va_arg (*args, u32);
  npol_interface_config_t *conf = va_arg (*args, npol_interface_config_t *);
  vnet_main_t *vnm = vnet_get_main ();
  npol_policy_t *policy = NULL;
  u32 *rx_policies = conf->rx_policies;
  u32 *tx_policies = conf->tx_policies;
  u32 i;

  s = format (s, "[%U sw_if_index=%u ", format_vnet_sw_if_index_name, vnm,
	      sw_if_index, sw_if_index);
  if (conf->invert_rx_tx)
    {
      s = format (s, "inverted");
      rx_policies = conf->tx_policies;
      tx_policies = conf->rx_policies;
    }
  ip4_address_t *ip4 = 0;
  ip4 = ip4_interface_first_address (&ip4_main, sw_if_index, 0);
  if (ip4)
    s = format (s, " addr=%U", format_ip4_address, ip4);
  ip6_address_t *ip6 = 0;
  ip6 = ip6_interface_first_address (&ip6_main, sw_if_index);
  if (ip6)
    s = format (s, " addr6=%U", format_ip6_address, ip6);
  s = format (s, "]\n");
  if (vec_len (rx_policies))
    {
      s = format (s, "  rx:\n");
    }
  s = format (s, "   rx-policy-default:%d rx-profile-default:%d \n",
	      conf->policy_default_rx, conf->profile_default_rx);
  vec_foreach_index (i, rx_policies)
    {
      policy = npol_policy_get_if_exists (rx_policies[i]);
      s = format (s, "    %U", format_npol_policy, policy, 4 /* indent */,
		  NPOL_POLICY_ONLY_RX, conf->invert_rx_tx);
    }
  if (vec_len (tx_policies))
    {
      s = format (s, "  tx:\n");
    }
  s = format (s, "   tx-policy-default:%d tx-profile-default:%d \n",
	      conf->policy_default_tx, conf->profile_default_tx);
  vec_foreach_index (i, tx_policies)
    {
      policy = npol_policy_get_if_exists (tx_policies[i]);
      s = format (s, "    %U", format_npol_policy, policy, 4 /* indent */,
		  NPOL_POLICY_ONLY_TX, conf->invert_rx_tx);
    }
  if (vec_len (conf->profiles))
    s = format (s, "  profiles:\n");
  vec_foreach_index (i, conf->profiles)
    {
      policy = npol_policy_get_if_exists (conf->profiles[i]);
      s = format (s, "    %U", format_npol_policy, policy, 4 /* indent */,
		  NPOL_POLICY_VERBOSE, conf->invert_rx_tx);
    }
  return s;
}
