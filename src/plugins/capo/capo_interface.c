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

uword unformat_sw_if_index (unformat_input_t *input, va_list *args);

int
capo_configure_policies (u32 sw_if_index, u32 num_ingress, u32 num_egress,
			 u32 num_profiles, u32 *policy_ids)
{
  clib_bihash_kv_8_24_t kv = { sw_if_index, { 0 } };
  capo_interface_config_t *conf = (capo_interface_config_t *) &kv.value;
  capo_interface_config_t *old_conf;
  u32 found = 0, i = 0;

  if (pool_is_free_index (vnet_get_main ()->interface_main.sw_interfaces,
			  sw_if_index))
    {
      clib_warning (
	"configuring policies for interface %u which doesn't exist",
	sw_if_index);
      return VNET_API_ERROR_INVALID_SW_IF_INDEX;
    }

  if (clib_bihash_search_8_24 (&capo_main.if_config, &kv, &kv) >= 0)
    {
      old_conf = (capo_interface_config_t *) &kv.value;
      vec_free (old_conf->ingress_policies);
      vec_free (old_conf->egress_policies);
      vec_free (old_conf->profiles);
      found = 1;
    }

  clib_warning ("configuring policies for if %u", sw_if_index);

  for (i = 0; i < num_ingress + num_egress + num_profiles; i++)
    if (pool_is_free_index (capo_policies, policy_ids[i]))
      goto error;

  vec_resize (conf->ingress_policies, num_ingress);
  for (i = 0; i < num_ingress; i++)
    conf->ingress_policies[i] = policy_ids[i];
  vec_resize (conf->egress_policies, num_egress);
  for (i = 0; i < num_egress; i++)
    conf->egress_policies[i] = policy_ids[num_ingress + i];
  vec_resize (conf->profiles, num_profiles);
  for (i = 0; i < num_profiles; i++)
    conf->profiles[i] = policy_ids[num_ingress + num_egress + i];

  clib_bihash_add_del_8_24 (&capo_main.if_config, &kv, 1 /* is_add */);

  if (!found)
    {
      capo_main.acl_plugin.wip_add_del_custom_access_io_policy (
	1 /* is_add */, sw_if_index, 0 /* is_input */, capo_match_func);
      capo_main.acl_plugin.wip_add_del_custom_access_io_policy (
	1 /* is_add */, sw_if_index, 1 /* is_input */, capo_match_func);
    }

  capo_main.acl_plugin.wip_clear_sessions (sw_if_index);
  return 0;

error:
  clib_warning ("error configuring policies for %u", sw_if_index);
  vec_resize (conf->ingress_policies, 0);
  vec_resize (conf->egress_policies, 0);
  vec_resize (conf->profiles, 0);
  return 1;
}

static clib_error_t *
capo_sw_interface_add_del (vnet_main_t *vnm, u32 sw_if_index, u32 is_add)
{
  clib_bihash_kv_8_24_t kv = { sw_if_index, { 0 } };
  capo_interface_config_t *conf = (capo_interface_config_t *) &kv.value;
  int rv = 0;

  if (is_add)
    return NULL;

  if (clib_bihash_search_8_24 (&capo_main.if_config, &kv, &kv) >= 0)
    {
      conf = (capo_interface_config_t *) &kv.value;
      vec_free (conf->ingress_policies);
      vec_free (conf->egress_policies);
      vec_free (conf->profiles);
    }

  clib_warning ("unconfiguring policies for if %u deleted", sw_if_index);
  clib_bihash_add_del_8_24 (&capo_main.if_config, &kv, 0 /* is_add */);
  rv = capo_main.acl_plugin.wip_add_del_custom_access_io_policy (
    0 /* is_add */, sw_if_index, 0 /* is_input */
    ,
    capo_match_func);
  if (rv)
    clib_warning ("error deleting caiop (output): %d", rv);
  rv = capo_main.acl_plugin.wip_add_del_custom_access_io_policy (
    0 /* is_add */, sw_if_index, 1 /* is_input */
    ,
    capo_match_func);
  if (rv)
    clib_warning ("error deleting caiop (input): %d", rv);
  return NULL;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (capo_sw_interface_add_del);

u8 *
format_capo_interface (u8 *s, va_list *args)
{
  u32 i;
  u32 sw_if_index = va_arg (*args, u32);
  capo_interface_config_t *conf = va_arg (*args, capo_interface_config_t *);

  s = format (s, "[%d] ingress: [", sw_if_index);
  vec_foreach_index (i, conf->ingress_policies)
    s = format (s, "%d,", conf->ingress_policies[i]);
  s = format (s, "] egress: [");
  vec_foreach_index (i, conf->egress_policies)
    s = format (s, "%d,", conf->egress_policies[i]);
  s = format (s, "] profiles: [");
  vec_foreach_index (i, conf->profiles)
    s = format (s, "%d,", conf->profiles[i]);
  s = format (s, "]");
  return s;
}

int
print_capo_interface (clib_bihash_kv_8_24_t *kv, void *arg)
{
  vlib_main_t *vm = (vlib_main_t *) arg;
  u32 sw_if_index = kv->key;
  capo_interface_config_t *conf = (capo_interface_config_t *) kv->value;
  vlib_cli_output (vm, "%U", format_capo_interface, sw_if_index, conf);
  return BIHASH_WALK_CONTINUE;
}

static clib_error_t *
capo_interface_show_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  vlib_cli_output (vm, "Interfaces with policies configured:");
  clib_bihash_foreach_key_value_pair_8_24 (&capo_main.if_config,
					   print_capo_interface, vm);
  return NULL;
}

VLIB_CLI_COMMAND (capo_policies_show_cmd, static) = {
  .path = "show capo interfaces",
  .function = capo_interface_show_cmd_fn,
  .short_help = "show capo interfaces",
};

static clib_error_t *
capo_interface_clear_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 sw_if_index = CAPO_INVALID_INDEX;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "missing parameters");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_sw_if_index, NULL,
		    &sw_if_index))
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

  rv = capo_configure_policies (sw_if_index, 0, 0, 0, NULL);
  if (rv)
    error =
      clib_error_return (0, "capo_configure_policies errored with %d", rv);
  else
    vlib_cli_output (vm, "capo interface %d cleared", sw_if_index);

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (capo_interface_clear_cmd, static) = {
  .path = "capo interface clear",
  .function = capo_interface_clear_cmd_fn,
  .short_help = "capo interface clear [interface | sw_if_index N]",
};

static clib_error_t *
capo_interface_configure_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 sw_if_index = CAPO_INVALID_INDEX;
  u32 num_ingress = 0;
  u32 num_egress = 0;
  u32 policy_id;
  u32 *policy_list = NULL;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "missing parameters");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_sw_if_index, NULL,
		    &sw_if_index))
	;
      else if (unformat (line_input, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (line_input, "in %d", &num_ingress))
	;
      else if (unformat (line_input, "out %d", &num_egress))
	;
      else if (unformat (line_input, "%d", &policy_id))
	vec_add1 (policy_list, policy_id);
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
  if (!vec_len (policy_list))
    {
      error = clib_error_return (0, "no policies specified");
      goto done;
    }

  rv = capo_configure_policies (
    sw_if_index, num_ingress, num_egress,
    vec_len (policy_list) - num_ingress - num_egress, policy_list);

  if (rv)
    error =
      clib_error_return (0, "capo_configure_policies errored with %d", rv);
  else
    vlib_cli_output (vm, "capo interface %d configured", sw_if_index);

done:
  unformat_free (line_input);
  vec_free (policy_list);
  return error;
}

VLIB_CLI_COMMAND (capo_interface_configure_cmd, static) = {
  .path = "capo interface configure",
  .function = capo_interface_configure_cmd_fn,
  .short_help = "capo interface configure [interface | sw_if_index N] in "
		"<num_ingress> out <num_egress> <policy_id> ...",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
