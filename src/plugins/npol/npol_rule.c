/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <npol/npol.h>
#include <npol/npol_rule.h>
#include <npol/npol_ipset.h>
#include <npol/npol_format.h>

npol_rule_t *npol_rules;

npol_rule_entry_t *
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
npol_rule_update (u32 *id, npol_rule_action_t action,
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
  npol_rule_filter_t tmp_filter, *filters = 0;
  npol_rule_entry_t tmp_entry, *entries = 0;
  clib_error_t *error = 0;
  npol_rule_action_t action;
  u32 id = NPOL_INVALID_INDEX;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "update %u", &id))
	;
      else if (unformat_user (input, unformat_npol_rule_action, &action))
	;
      else if (unformat_user (input, unformat_npol_rule_entry, &tmp_entry))
	vec_add1 (entries, tmp_entry);
      else if (unformat_user (input, unformat_npol_rule_filter, &tmp_filter))
	{
	  vec_add1 (filters, tmp_filter);
	  vlib_cli_output (vm, "%U", format_npol_rule_filter, &tmp_filter);
	}
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  rv = npol_rule_update (&id, action, filters, entries);
  if (rv)
    error = clib_error_return (0, "npol_rule_update error %d", rv);
  else
    vlib_cli_output (vm, "npol rule %d added", id);

done:
  vec_free (filters);
  vec_free (entries);
  return error;
}

VLIB_CLI_COMMAND (npol_rules_add_cmd, static) = {
  .path = "npol rule add",
  .function = npol_rules_add_cmd_fn,
  .short_help = "npol rule add [allow|deny|log|pass]"
		"[filter[==|!=]value]"
		"[[src|dst][==|!=][prefix|set ID|[port-port]]]",
  .long_help = "Add a rule, with given filters and entries\n"
	       "filters can be `icmp-type`, `icmp-code` and `proto`",
};

static clib_error_t *
npol_rules_del_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  clib_error_t *error = 0;
  u32 id = NPOL_INVALID_INDEX;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%u", &id))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, input);
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
  return error;
}

VLIB_CLI_COMMAND (npol_rules_del_cmd, static) = {
  .path = "npol rule del",
  .function = npol_rules_del_cmd_fn,
  .short_help = "npol rule del [id]",
};
