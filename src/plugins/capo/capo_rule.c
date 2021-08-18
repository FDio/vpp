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

#include <capo/capo.h>
#include <capo/capo_rule.h>

capo_rule_t *capo_rules;

u8 *
format_capo_rule_action (u8 *s, va_list *args)
{
  capo_rule_action_t action = va_arg (*args, int);
  switch (action)
    {
    case CAPO_ALLOW:
      return format (s, "allow");
    case CAPO_DENY:
      return format (s, "deny");
    case CAPO_LOG:
      return format (s, "log");
    case CAPO_PASS:
      return format (s, "pass");
    default:
      return format (s, "unknown");
    }
}

uword
unformat_capo_rule_action (unformat_input_t *input, va_list *args)
{
  capo_rule_action_t *action = va_arg (*args, capo_rule_action_t *);
  if (unformat (input, "allow"))
    *action = CAPO_ALLOW;
  else if (unformat (input, "deny"))
    *action = CAPO_DENY;
  else if (unformat (input, "log"))
    *action = CAPO_LOG;
  else if (unformat (input, "pass"))
    *action = CAPO_PASS;
  else
    return 0;
  return 1;
}

u8 *
format_capo_rule_entry (u8 *s, va_list *args)
{
  capo_rule_entry_t *entry = va_arg (*args, capo_rule_entry_t *);
  s = format (s, "%s ", entry->flags & CAPO_IS_SRC ? "src" : "dst");
  s = format (s, "%s ", entry->flags & CAPO_IS_NOT ? "!=" : "==");
  switch (entry->type)
    {
    case CAPO_CIDR:
      s = format (s, "%U", format_ip_prefix, &entry->data.cidr);
      break;
    case CAPO_PORT_RANGE:
      s = format (s, "[%u-%u]", entry->data.port_range.start,
		  entry->data.port_range.end);
      break;
    case CAPO_IP_SET:
      s = format (s, "ip set[%u]", entry->data.set_id);
      break;
    case CAPO_PORT_IP_SET:
      s = format (s, "port+ip set[%u]", entry->data.set_id);
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
  capo_rule_key_flag_t *flags = va_arg (*args, capo_rule_key_flag_t *);
  if (unformat (input, "src=="))
    *flags = CAPO_IS_SRC;
  else if (unformat (input, "src!="))
    *flags = CAPO_IS_SRC | CAPO_IS_NOT;
  else if (unformat (input, "dst!="))
    *flags = CAPO_IS_NOT;
  else if (unformat (input, "dst=="))
    *flags = 0;
  else
    return 0;
  return 1;
}

uword
unformat_capo_port_range (unformat_input_t *input, va_list *args)
{
  capo_port_range_t *port_range = va_arg (*args, capo_port_range_t *);
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
unformat_capo_rule_entry (unformat_input_t *input, va_list *args)
{
  capo_rule_entry_t *entry = va_arg (*args, capo_rule_entry_t *);
  if (unformat (input, "%U %U", unformat_rule_key_flag, &entry->flags,
		unformat_ip_prefix, &entry->data.cidr))
    entry->type = CAPO_CIDR;
  else if (unformat (input, "%U %U", unformat_rule_key_flag, &entry->flags,
		     unformat_capo_port_range, &entry->data.port_range))
    entry->type = CAPO_PORT_RANGE;
  else if (unformat (input, "%Uset %u", unformat_rule_key_flag, &entry->flags,
		     &entry->data.set_id))
    entry->type = CAPO_PORT_IP_SET;
  else
    return 0;
  return 1;
}

u8 *
format_capo_rule_filter (u8 *s, va_list *args)
{
  capo_rule_filter_t *filter = va_arg (*args, capo_rule_filter_t *);
  switch (filter->type)
    {
    case CAPO_RULE_FILTER_NONE_TYPE:
      return format (s, "<no filter>");
    case CAPO_RULE_FILTER_ICMP_TYPE:
      return format (s, "icmp-type %s= %d", filter->should_match ? "=" : "!",
		     filter->value);
    case CAPO_RULE_FILTER_ICMP_CODE:
      return format (s, "icmp-code %s= %d", filter->should_match ? "=" : "!",
		     filter->value);
    case CAPO_RULE_FILTER_L4_PROTO:
      return format (s, "proto %s= %U", filter->should_match ? "=" : "!",
		     format_ip_protocol, filter->value);
    default:
      return format (s, "unknown");
    }
}

uword
unformat_capo_should_match (unformat_input_t *input, va_list *args)
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
unformat_capo_rule_filter (unformat_input_t *input, va_list *args)
{
  u8 tmp_value;
  capo_rule_filter_t *filter = va_arg (*args, capo_rule_filter_t *);
  if (unformat (input, "icmp-type%U%d", unformat_capo_should_match,
		&filter->should_match, &filter->value))
    filter->type = CAPO_RULE_FILTER_ICMP_TYPE;
  else if (unformat (input, "icmp-code%U%d", unformat_capo_should_match,
		     &filter->should_match, &filter->value))
    filter->type = CAPO_RULE_FILTER_ICMP_CODE;
  else if (unformat (input, "proto%U%U", unformat_capo_should_match,
		     &filter->should_match, unformat_ip_protocol, &tmp_value))
    {
      filter->value = tmp_value;
      filter->type = CAPO_RULE_FILTER_L4_PROTO;
    }
  else
    return 0;
  return 1;
}

static capo_rule_entry_t *
capo_rule_get_entries (capo_rule_t *rule)
{
  capo_rule_entry_t *entries = NULL, *entry;
  capo_port_range_t *pr;
  ip_prefix_t *pfx;
  u32 *set_id;
  for (int i = 0; i < CAPO_RULE_MAX_FLAGS; i++)
    {
      vec_foreach (pfx, rule->prefixes[i])
	{
	  vec_add2 (entries, entry, 1);
	  entry->type = CAPO_CIDR;
	  entry->flags = i;
	  clib_memcpy (&entry->data.cidr, pfx, sizeof (*pfx));
	}
      vec_foreach (pr, rule->port_ranges[i])
	{
	  vec_add2 (entries, entry, 1);
	  entry->type = CAPO_PORT_RANGE;
	  entry->flags = i;
	  clib_memcpy (&entry->data.port_range, pr, sizeof (*pr));
	}
      vec_foreach (set_id, rule->ip_ipsets[i])
	{
	  vec_add2 (entries, entry, 1);
	  entry->type = CAPO_IP_SET;
	  entry->flags = i;
	  entry->data.set_id = *set_id;
	}
      vec_foreach (set_id, rule->ipport_ipsets[i])
	{
	  vec_add2 (entries, entry, 1);
	  entry->type = CAPO_PORT_IP_SET;
	  entry->flags = i;
	  entry->data.set_id = *set_id;
	}
    }
  return entries;
}

static_always_inline int
capo_rule_n_filters (capo_rule_t *rule)
{
  capo_rule_filter_t *filter;
  int n_filters = 0;

  vec_foreach (filter, rule->filters)
    if (filter->type != CAPO_RULE_FILTER_NONE_TYPE)
      n_filters++;

  return n_filters;
}

u8 *
format_capo_rule (u8 *s, va_list *args)
{
  capo_rule_t *rule = va_arg (*args, capo_rule_t *);
  capo_rule_filter_t *filter;
  capo_rule_entry_t *entry, *entries;

  s = format (s, "[%d] action:%U\n", rule - capo_rules,
	      format_capo_rule_action, rule->action);

  if (capo_rule_n_filters (rule))
    s = format (s, "filters\n");
  vec_foreach (filter, rule->filters)
    {
      if (filter->type != CAPO_RULE_FILTER_NONE_TYPE)
	s = format (s, "  %U\n", format_capo_rule_filter, filter);
    }

  s = format (s, "entries\n");
  entries = capo_rule_get_entries (rule);
  vec_foreach (entry, entries)
    s = format (s, "  %U\n", format_capo_rule_entry, entry);
  vec_free (entries);
  return (s);
}

capo_rule_t *
capo_rule_alloc ()
{
  capo_rule_t *rule;
  pool_get_zero (capo_rules, rule);
  return rule;
}

capo_rule_t *
capo_rule_get_if_exists (u32 index)
{
  if (pool_is_free_index (capo_rules, index))
    return (NULL);
  return pool_elt_at_index (capo_rules, index);
}

static void
capo_rule_cleanup (capo_rule_t *rule)
{
  int i;
  vec_free (rule->filters);
  for (i = 0; i < CAPO_RULE_MAX_FLAGS; i++)
    {
      vec_free (rule->prefixes[i]);
      vec_free (rule->port_ranges[i]);
      vec_free (rule->ip_ipsets[i]);
      vec_free (rule->ipport_ipsets[i]);
    }
}

int
capo_rule_update (u32 *id, capo_rule_action_t action, ip_address_family_t af,
		  capo_rule_filter_t *filters, capo_rule_entry_t *entries)
{
  capo_rule_filter_t *filter;
  capo_rule_entry_t *entry;
  capo_rule_t *rule;
  int rv;

  rule = capo_rule_get_if_exists (*id);
  if (rule)
    capo_rule_cleanup (rule);
  else
    rule = capo_rule_alloc ();

  rule->af = -1;
  rule->action = action;
  vec_foreach (filter, filters)
    vec_add1 (rule->filters, *filter);

  vec_foreach (entry, entries)
    {
      u8 flags = entry->flags;
      switch (entry->type)
	{
	case CAPO_CIDR:
	  vec_add1 (rule->prefixes[flags], entry->data.cidr);
	  break;
	case CAPO_PORT_RANGE:
	  vec_add1 (rule->port_ranges[flags], entry->data.port_range);
	  break;
	case CAPO_PORT_IP_SET:
	  vec_add1 (rule->ipport_ipsets[flags], entry->data.set_id);
	  break;
	case CAPO_IP_SET:
	  vec_add1 (rule->ip_ipsets[flags], entry->data.set_id);
	  break;
	default:
	  rv = 1;
	  goto error;
	}
    }
  *id = rule - capo_rules;
  return 0;
error:
  capo_rule_cleanup (rule);
  pool_put (capo_rules, rule);
  return rv;
}

int
capo_rule_delete (u32 id)
{
  capo_rule_t *rule;
  rule = capo_rule_get_if_exists (id);
  if (NULL == rule)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  capo_rule_cleanup (rule);
  pool_put (capo_rules, rule);

  return 0;
}

static clib_error_t *
capo_rules_show_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  capo_rule_t *rule;

  pool_foreach (rule, capo_rules)
    {
      vlib_cli_output (vm, "%U", format_capo_rule, rule);
    }

  return 0;
}

VLIB_CLI_COMMAND (capo_rules_show_cmd, static) = {
  .path = "show capo rules",
  .function = capo_rules_show_cmd_fn,
  .short_help = "show capo rules",
};

static clib_error_t *
capo_rules_add_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  capo_rule_filter_t tmp_filter, *filters = 0;
  capo_rule_entry_t tmp_entry, *entries = 0;
  clib_error_t *error = 0;
  capo_rule_action_t action;
  ip_address_family_t af = AF_IP4;
  u32 id = CAPO_INVALID_INDEX;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "update %u", &id))
	;
      else if (unformat_user (line_input, unformat_ip_address_family, &af))
	;
      else if (unformat_user (line_input, unformat_capo_rule_action, &action))
	;
      else if (unformat_user (line_input, unformat_capo_rule_entry,
			      &tmp_entry))
	vec_add1 (entries, tmp_entry);
      else if (unformat_user (line_input, unformat_capo_rule_filter,
			      &tmp_filter))
	{
	  vec_add1 (filters, tmp_filter);
	  vlib_cli_output (vm, "%U", format_capo_rule_filter, &tmp_filter);
	}
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  rv = capo_rule_update (&id, action, af, filters, entries);
  if (rv)
    error = clib_error_return (0, "capo_rule_update error %d", rv);
  else
    vlib_cli_output (vm, "capo rule %d added", id);

done:
  vec_free (filters);
  vec_free (entries);
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (capo_rules_add_cmd, static) = {
  .path = "capo rule add",
  .function = capo_rules_add_cmd_fn,
  .short_help = "capo rule add [ip4|ip6] [allow|deny|log|pass]"
		"[filter[==|!=]value]"
		"[[src|dst][==|!=][prefix|set ID|[port-port]]]",
  .long_help = "Add a rule, with given filters and entries\n"
	       "filters can be `icmp-type`, `icmp-code` and `proto`",
};

static clib_error_t *
capo_rules_del_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 id = CAPO_INVALID_INDEX;
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

  if (CAPO_INVALID_INDEX == id)
    {
      error = clib_error_return (0, "missing rule id");
      goto done;
    }

  rv = capo_rule_delete (id);
  if (rv)
    error = clib_error_return (0, "capo_rule_delete errored with %d", rv);

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (capo_rules_del_cmd, static) = {
  .path = "capo rule del",
  .function = capo_rules_del_cmd_fn,
  .short_help = "capo rule del [id]",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
