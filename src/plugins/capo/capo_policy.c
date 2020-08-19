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
#include <capo/capo_policy.h>

capo_policy_t *capo_policies;

static capo_policy_t *
capo_policy_alloc ()
{
  capo_policy_t *policy;
  pool_get_zero (capo_policies, policy);
  return policy;
}

static capo_policy_t *
capo_policy_get_if_exists (u32 index)
{
  if (pool_is_free_index (capo_policies, index))
    return (NULL);
  return pool_elt_at_index (capo_policies, index);
}

static void
capo_policy_cleanup (capo_policy_t * policy)
{
  for (int i = 0; i < VLIB_N_RX_TX; i++)
    vec_free (policy->rule_ids[i]);
}

int
capo_policy_update (u32 * id, capo_policy_rule_t * rules)
{
  capo_policy_t *policy;
  capo_policy_rule_t *rule;

  policy = capo_policy_get_if_exists (*id);
  if (policy)
    capo_policy_cleanup (policy);
  else
    policy = capo_policy_alloc ();

  vec_foreach (rule, rules)
    vec_add1 (policy->rule_ids[rule->direction], rule->rule_id);

  *id = policy - capo_policies;
  return 0;
}

int
capo_policy_delete (u32 id)
{
  capo_policy_t *policy;
  policy = capo_policy_get_if_exists (id);
  if (NULL == policy)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  capo_policy_cleanup (policy);
  pool_put (capo_policies, policy);

  return 0;
}

u8 *
format_capo_policy (u8 * s, va_list * args)
{
  capo_policy_t *policy = va_arg (*args, capo_policy_t *);
  int verbose = va_arg (*args, int);
  u32 *rule_id;

  s = format (s, "[%d] rx:%d tx:%d\n", policy - capo_policies,
	      vec_len (policy->rule_ids[VLIB_RX]),
	      vec_len (policy->rule_ids[VLIB_TX]));
  if (verbose)
    {
      s = format (s, "RX rules\n");
      vec_foreach (rule_id, policy->rule_ids[VLIB_RX]) s = format (s, "  %d\n", *rule_id);	// todo : format_capo_rule
      s = format (s, "TX rules\n");
      vec_foreach (rule_id, policy->rule_ids[VLIB_TX]) s = format (s, "  %d\n", *rule_id);	// todo : format_capo_rule
    }

  return (s);
}

static clib_error_t *
capo_policies_show_cmd_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  capo_policy_t *policy;
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

  /* *INDENT-OFF* */
  pool_foreach (policy, capo_policies, ({
    vlib_cli_output (vm, "%U", format_capo_policy, policy, verbose);
  }));
  /* *INDENT-ON* */

done:
  if (has_input)
    unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (capo_policies_show_cmd, static) = {
  .path = "show capo policies",
  .function = capo_policies_show_cmd_fn,
  .short_help = "show capo policies [verbose]",
};
/* *INDENT-ON* */

static clib_error_t *
capo_policies_add_cmd_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 id = CAPO_INVALID_INDEX, rule_id;
  capo_policy_rule_t *policy_rules = 0, *policy_rule;
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

  rv = capo_policy_update (&id, policy_rules);
  if (rv)
    error = clib_error_return (0, "capo_policy_delete errored with %d", rv);
  else
    vlib_cli_output (vm, "capo policy %d added", id);


done:
  vec_free (policy_rules);
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (capo_policies_add_cmd, static) = {
  .path = "capo policy add",
  .function = capo_policies_add_cmd_fn,
  .short_help = "capo policy add [rx rule_id rule_id ...] [tx rule_id rule_id ...] [update [id]]",
};
/* *INDENT-ON* */


static clib_error_t *
capo_policies_del_cmd_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 id = CAPO_INVALID_INDEX;
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

  if (CAPO_INVALID_INDEX == id)
    {
      error = clib_error_return (0, "missing policy id");
      goto done;
    }

  rv = capo_policy_delete (id);
  if (rv)
    error = clib_error_return (0, "capo_policy_delete errored with %d", rv);

done:
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (capo_policies_del_cmd, static) = {
  .path = "capo policy del",
  .function = capo_policies_del_cmd_fn,
  .short_help = "capo policy del [id]",
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
