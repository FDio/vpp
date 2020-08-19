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
#include <capo/capo_match.h>

uword unformat_sw_if_index (unformat_input_t * input, va_list * args);



int
capo_configure_policies (u32 sw_if_index, u32 pass_policy_id,
                         u32 num_policies, u32 *policy_ids)
{
  clib_bihash_kv_8_16_t kv = { sw_if_index, {0} };
  capo_interface_config_t *conf = (capo_interface_config_t *) &kv.value;
  capo_interface_config_t *old_conf;
  u32 found = 0, i = 0;

  if (clib_bihash_search_8_16 (&capo_main.if_config, &kv, &kv) >= 0)
    {
      old_conf = (capo_interface_config_t *) &kv.value;
      vec_free (old_conf->policies);
      found = 1;
    }

  clib_warning("configuring policies for if %u", sw_if_index);

  conf->pass_id = pass_policy_id;
  vec_resize (conf->policies, num_policies);
  for (i = 0; i < num_policies; i ++)
    {
      conf->policies[i] = policy_ids[i];
    }

  clib_bihash_add_del_8_16 (&capo_main.if_config, &kv, 1 /* is_add */);

  if (!found) {
    capo_main.acl_plugin.wip_add_del_custom_access_io_policy (1 /* is_add */,
              sw_if_index, 0 /* is_input */, capo_match_func);   
    capo_main.acl_plugin.wip_add_del_custom_access_io_policy (1 /* is_add */,
              sw_if_index, 1 /* is_input */, capo_match_func);
  }

  return 0;
}

u8 *
format_capo_interface (u8 * s, va_list * args)
{
  u32 i;
  u32 sw_if_index = va_arg (*args, u32);
  capo_interface_config_t *conf = va_arg (*args, capo_interface_config_t *);

  s = format (s, "[%d] policies:", sw_if_index);
  vec_foreach_index (i, conf->policies) {
    if (i == conf->pass_id)
      s = format(s, " profiles:");
    s = format(s, " %d", conf->policies[i]);
  }
  return s;
}

int
print_capo_interface (clib_bihash_kv_8_16_t * kv, void * arg)
{
  vlib_main_t *vm = (vlib_main_t *) arg;
  u32 sw_if_index = kv->key;
  capo_interface_config_t *conf = (capo_interface_config_t *) kv->value;
  vlib_cli_output (vm, "%U", format_capo_interface, sw_if_index, conf);
  return BIHASH_WALK_CONTINUE;
}

static clib_error_t *
capo_interface_show_cmd_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_cli_output (vm, "Interfaces with policies configured:");
  clib_bihash_foreach_key_value_pair_8_16 (&capo_main.if_config,
                                           print_capo_interface, vm);
  return NULL;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (capo_policies_show_cmd, static) = {
  .path = "show capo interfaces",
  .function = capo_interface_show_cmd_fn,
  .short_help = "show capo interfaces",
};
/* *INDENT-ON* */


static clib_error_t *
capo_interface_clear_cmd_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 sw_if_index = CAPO_INVALID_INDEX;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "missing parameters");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_sw_if_index, NULL, &sw_if_index))
	;
      else if (unformat (line_input, "sw_if_index %d", &sw_if_index))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (sw_if_index == CAPO_INVALID_INDEX)
    {
      error = clib_error_return (0, "interface not specified");
      goto done;
    }

  rv = capo_remove_policies (sw_if_index);
  if (rv)
    error = clib_error_return (0, "capo_remove_policies errored with %d", rv);
  else
    vlib_cli_output (vm, "capo interface %d cleared", sw_if_index);


done:
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (capo_interface_clear_cmd, static) = {
  .path = "capo interface clear",
  .function = capo_interface_clear_cmd_fn,
  .short_help = "capo interface clear [interface | sw_if_index N]",
};
/* *INDENT-ON* */



static clib_error_t *
capo_interface_configure_cmd_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 sw_if_index = CAPO_INVALID_INDEX;
  u32 pass_id = CAPO_INVALID_INDEX;
  u32 policy_id;
  u32 *policy_list = NULL;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "missing parameters");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_sw_if_index, NULL, &sw_if_index))
	;
      else if (unformat (line_input, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (line_input, "pass %d", &pass_id))
	;
      else if (unformat (line_input, "%d", &policy_id))
        {
          vec_add1 (policy_list, policy_id);
        }
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (sw_if_index == CAPO_INVALID_INDEX || pass_id == CAPO_INVALID_INDEX)
    {
      error = clib_error_return (0, "interface or pass id not specified");
      goto done;
    }
  if (!vec_len (policy_list))
    {
      error = clib_error_return (0, "no policies specified");
      goto done;
    }
  
  rv = capo_configure_policies (sw_if_index, pass_id, vec_len (policy_list),
                                policy_list);

  if (rv)
    error = clib_error_return (0, "capo_remove_policies errored with %d", rv);
  else
    vlib_cli_output (vm, "capo interface %d configured", sw_if_index);

done:
  unformat_free (line_input);
  vec_free (policy_list);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (capo_interface_configure_cmd, static) = {
  .path = "capo interface configure",
  .function = capo_interface_configure_cmd_fn,
  .short_help = "capo interface configure [interface | sw_if_index N] [pass N] <policy_id> ...",
};
/* *INDENT-ON* */





/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
