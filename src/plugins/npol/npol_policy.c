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
#include <npol/npol_policy.h>
#include <npol/npol_rule.h>

npol_policy_t *npol_policies;

static npol_policy_t *
npol_policy_alloc ()
{
  npol_policy_t *policy;
  pool_get_zero (npol_policies, policy);
  return policy;
}

npol_policy_t *
npol_policy_get_if_exists (u32 index)
{
  if (pool_is_free_index (npol_policies, index))
    return (NULL);
  return pool_elt_at_index (npol_policies, index);
}

static void
npol_policy_cleanup (npol_policy_t *policy)
{
  for (int i = 0; i < VLIB_N_RX_TX; i++)
    vec_free (policy->rule_ids[i]);
}

int
npol_policy_update (u32 *id, npol_policy_rule_t *rules)
{
  npol_policy_t *policy;
  npol_policy_rule_t *rule;

  policy = npol_policy_get_if_exists (*id);
  if (policy)
    npol_policy_cleanup (policy);
  else
    policy = npol_policy_alloc ();

  vec_foreach (rule, rules)
    vec_add1 (policy->rule_ids[rule->direction], rule->rule_id);

  *id = policy - npol_policies;
  return 0;
}

int
npol_policy_delete (u32 id)
{
  npol_policy_t *policy;
  policy = npol_policy_get_if_exists (id);
  if (NULL == policy)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  npol_policy_cleanup (policy);
  pool_put (npol_policies, policy);

  return 0;
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

static clib_error_t *
npol_policies_show_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  npol_policy_t *policy;
  u8 verbose = 0, has_input = 0;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      has_input = 1;
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "verbose"))
	    verbose = 1;
	  else
	    {
	      error = clib_error_return (0, "unknown input '%U'",
					 format_unformat_error, line_input);
	      goto done;
	    }
	}
    }

  pool_foreach (policy, npol_policies)
    vlib_cli_output (vm, "%U", format_npol_policy, policy, 0, /* indent */
		     verbose, 0 /* invert_rx_tx */);

done:
  if (has_input)
    unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (npol_policies_show_cmd, static) = {
  .path = "show npol policies",
  .function = npol_policies_show_cmd_fn,
  .short_help = "show npol policies [verbose]",
};

static clib_error_t *
npol_policies_add_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 id = NPOL_INVALID_INDEX, rule_id;
  npol_policy_rule_t *policy_rules = 0, *policy_rule;
  int direction = VLIB_RX;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "missing parameters");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "update %u", &id))
	;
      else if (unformat (line_input, "%U", unformat_vlib_rx_tx, &direction))
	;
      else if (unformat (line_input, "%u", &rule_id))
	{
	  vec_add2 (policy_rules, policy_rule, 1);
	  policy_rule->rule_id = rule_id;
	  policy_rule->direction = direction;
	}
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  rv = npol_policy_update (&id, policy_rules);
  if (rv)
    error = clib_error_return (0, "npol_policy_delete errored with %d", rv);
  else
    vlib_cli_output (vm, "npol policy %d added", id);

done:
  vec_free (policy_rules);
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (npol_policies_add_cmd, static) = {
  .path = "npol policy add",
  .function = npol_policies_add_cmd_fn,
  .short_help = "npol policy add [rx rule_id rule_id ...] [tx rule_id rule_id "
		"...] [update [id]]",
};

static clib_error_t *
npol_policies_del_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 id = NPOL_INVALID_INDEX;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "missing policy id");

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
      error = clib_error_return (0, "missing policy id");
      goto done;
    }

  rv = npol_policy_delete (id);
  if (rv)
    error = clib_error_return (0, "npol_policy_delete errored with %d", rv);

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (npol_policies_del_cmd, static) = {
  .path = "npol policy del",
  .function = npol_policies_del_cmd_fn,
  .short_help = "npol policy del [id]",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
