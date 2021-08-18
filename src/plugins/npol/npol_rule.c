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

#include <npol/npol.h>
#include <npol/npol_rule.h>
#include <npol/npol_ipset.h>

npol_rule_t *npol_rules;

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

static npol_rule_entry_t *
npol_rule_get_entries (npol_rule_t *rule)
{
  npol_rule_entry_t *entries = NULL, *entry;
  npol_port_range_t *pr;
  ip_prefix_t *pfx;
  u32 *set_id;
  for (int i = 0; i < NPOL_RULE_MAX_FLAGS; i++)
    {
      vec_foreach (pfx, rule->prefixes[i])
	{
	  vec_add2 (entries, entry, 1);
	  entry->type = NPOL_CIDR;
	  entry->flags = i;
	  clib_memcpy (&entry->data.cidr, pfx, sizeof (*pfx));
	}
      vec_foreach (pr, rule->port_ranges[i])
	{
	  vec_add2 (entries, entry, 1);
	  entry->type = NPOL_PORT_RANGE;
	  entry->flags = i;
	  clib_memcpy (&entry->data.port_range, pr, sizeof (*pr));
	}
      vec_foreach (set_id, rule->ip_ipsets[i])
	{
	  vec_add2 (entries, entry, 1);
	  entry->type = NPOL_IP_SET;
	  entry->flags = i;
	  entry->data.set_id = *set_id;
	}
      vec_foreach (set_id, rule->ipport_ipsets[i])
	{
	  vec_add2 (entries, entry, 1);
	  entry->type = NPOL_PORT_IP_SET;
	  entry->flags = i;
	  entry->data.set_id = *set_id;
	}
    }
  return entries;
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

npol_rule_t *
npol_rule_alloc ()
{
  npol_rule_t *rule;
  pool_get_zero (npol_rules, rule);
  return rule;
}

npol_rule_t *
npol_rule_get_if_exists (u32 index)
{
  if (pool_is_free_index (npol_rules, index))
    return (NULL);
  return pool_elt_at_index (npol_rules, index);
}

static void
npol_rule_cleanup (npol_rule_t *rule)
{
  int i;
  vec_free (rule->filters);
  for (i = 0; i < NPOL_RULE_MAX_FLAGS; i++)
    {
      vec_free (rule->prefixes[i]);
      vec_free (rule->port_ranges[i]);
      vec_free (rule->ip_ipsets[i]);
      vec_free (rule->ipport_ipsets[i]);
    }
}

int
npol_rule_update (u32 *id, npol_rule_action_t action, ip_address_family_t af,
		  npol_rule_filter_t *filters, npol_rule_entry_t *entries)
{
  npol_rule_filter_t *filter;
  npol_rule_entry_t *entry;
  npol_rule_t *rule;
  int rv;

  rule = npol_rule_get_if_exists (*id);
  if (rule)
    npol_rule_cleanup (rule);
  else
    rule = npol_rule_alloc ();

  rule->af = -1;
  rule->action = action;
  vec_foreach (filter, filters)
    vec_add1 (rule->filters, *filter);

  vec_foreach (entry, entries)
    {
      u8 flags = entry->flags;
      switch (entry->type)
	{
	case NPOL_CIDR:
	  vec_add1 (rule->prefixes[flags], entry->data.cidr);
	  break;
	case NPOL_PORT_RANGE:
	  vec_add1 (rule->port_ranges[flags], entry->data.port_range);
	  break;
	case NPOL_PORT_IP_SET:
	  vec_add1 (rule->ipport_ipsets[flags], entry->data.set_id);
	  break;
	case NPOL_IP_SET:
	  vec_add1 (rule->ip_ipsets[flags], entry->data.set_id);
	  break;
	default:
	  rv = 1;
	  goto error;
	}
    }
  *id = rule - npol_rules;
  return 0;
error:
  npol_rule_cleanup (rule);
  pool_put (npol_rules, rule);
  return rv;
}

int
npol_rule_delete (u32 id)
{
  npol_rule_t *rule;
  rule = npol_rule_get_if_exists (id);
  if (NULL == rule)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  npol_rule_cleanup (rule);
  pool_put (npol_rules, rule);

  return 0;
}

static clib_error_t *
npol_rules_show_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  npol_rule_t *rule;

  pool_foreach (rule, npol_rules)
    {
      vlib_cli_output (vm, "%U", format_npol_rule, rule);
    }

  return 0;
}

VLIB_CLI_COMMAND (npol_rules_show_cmd, static) = {
  .path = "show npol rules",
  .function = npol_rules_show_cmd_fn,
  .short_help = "show npol rules",
};

static clib_error_t *
npol_rules_add_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  npol_rule_filter_t tmp_filter, *filters = 0;
  npol_rule_entry_t tmp_entry, *entries = 0;
  clib_error_t *error = 0;
  npol_rule_action_t action;
  ip_address_family_t af = AF_IP4;
  u32 id = NPOL_INVALID_INDEX;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "update %u", &id))
	;
      else if (unformat_user (line_input, unformat_ip_address_family, &af))
	;
      else if (unformat_user (line_input, unformat_npol_rule_action, &action))
	;
      else if (unformat_user (line_input, unformat_npol_rule_entry,
			      &tmp_entry))
	vec_add1 (entries, tmp_entry);
      else if (unformat_user (line_input, unformat_npol_rule_filter,
			      &tmp_filter))
	{
	  vec_add1 (filters, tmp_filter);
	  vlib_cli_output (vm, "%U", format_npol_rule_filter, &tmp_filter);
	}
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  rv = npol_rule_update (&id, action, af, filters, entries);
  if (rv)
    error = clib_error_return (0, "npol_rule_update error %d", rv);
  else
    vlib_cli_output (vm, "npol rule %d added", id);

done:
  vec_free (filters);
  vec_free (entries);
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (npol_rules_add_cmd, static) = {
  .path = "npol rule add",
  .function = npol_rules_add_cmd_fn,
  .short_help = "npol rule add [ip4|ip6] [allow|deny|log|pass]"
		"[filter[==|!=]value]"
		"[[src|dst][==|!=][prefix|set ID|[port-port]]]",
  .long_help = "Add a rule, with given filters and entries\n"
	       "filters can be `icmp-type`, `icmp-code` and `proto`",
};

static clib_error_t *
npol_rules_del_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 id = NPOL_INVALID_INDEX;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "missing rule id");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%u", &id))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (NPOL_INVALID_INDEX == id)
    {
      error = clib_error_return (0, "missing rule id");
      goto done;
    }

  rv = npol_rule_delete (id);
  if (rv)
    error = clib_error_return (0, "npol_rule_delete errored with %d", rv);

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (npol_rules_del_cmd, static) = {
  .path = "npol rule del",
  .function = npol_rules_del_cmd_fn,
  .short_help = "npol rule del [id]",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
