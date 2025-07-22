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
#include <capo/capo_policy.h>

uword unformat_sw_if_index (unformat_input_t *input, va_list *args);

static int
print_capo_interface2 (clib_bihash_kv_8_32_t *kv, void *arg)
{
  u8 **s = (u8 **) arg;
  u32 sw_if_index = kv->key;
  capo_interface_config_t *conf = (capo_interface_config_t *) kv->value;
  *s = format (*s, "%U", format_capo_interface, sw_if_index, conf);
  return BIHASH_WALK_CONTINUE;
}

void
capo_interface_print_current_state ()
{
  u8 *s = 0;
  clib_bihash_foreach_key_value_pair_8_32 (&capo_main.if_config,
					   print_capo_interface2, (void *) &s);
#if CAPO_DEBUG > 0
  clib_warning ("Current interface state:\n%s", s);
#endif
  vec_free (s);
}

int
capo_configure_policies (u32 sw_if_index, u32 num_rx_policies,
			 u32 num_tx_policies, u32 num_profiles,
			 u32 *policy_ids, u8 invert_rx_tx, u8 user_defined_rx,
			 u8 user_defined_tx)
{
  clib_bihash_kv_8_32_t kv = { sw_if_index, { 0 } };
  capo_interface_config_t *conf = (capo_interface_config_t *) &kv.value;
  capo_interface_config_t *old_conf;
  u32 found = 0, i = 0;

  if (pool_is_free_index (vnet_get_main ()->interface_main.sw_interfaces,
			  sw_if_index))
    {
#if CAPO_DEBUG > 0
      clib_warning (
	"configuring policies for interface %u which doesn't exist",
	sw_if_index);
#endif
      return VNET_API_ERROR_INVALID_SW_IF_INDEX;
    }

  if (clib_bihash_search_8_32 (&capo_main.if_config, &kv, &kv) >= 0)
    {
      old_conf = (capo_interface_config_t *) &kv.value;
      vec_free (old_conf->rx_policies);
      vec_free (old_conf->tx_policies);
      vec_free (old_conf->profiles);
      found = 1;
    }

  for (i = 0; i < num_rx_policies + num_tx_policies + num_profiles; i++)
    if (pool_is_free_index (capo_policies, policy_ids[i]))
      goto error;

  conf->invert_rx_tx = invert_rx_tx;
  conf->user_defined_rx = user_defined_rx;
  conf->user_defined_tx = user_defined_tx;
  vec_resize (conf->rx_policies, num_rx_policies);
  for (i = 0; i < num_rx_policies; i++)
    conf->rx_policies[i] = policy_ids[i];
  vec_resize (conf->tx_policies, num_tx_policies);
  for (i = 0; i < num_tx_policies; i++)
    conf->tx_policies[i] = policy_ids[num_rx_policies + i];
  vec_resize (conf->profiles, num_profiles);
  for (i = 0; i < num_profiles; i++)
    conf->profiles[i] = policy_ids[num_rx_policies + num_tx_policies + i];

  clib_bihash_add_del_8_32 (&capo_main.if_config, &kv, 1 /* is_add */);

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
#if CAPO_DEBUG > 0
  clib_warning ("error configuring policies for %u", sw_if_index);
#endif
  vec_resize (conf->rx_policies, 0);
  vec_resize (conf->tx_policies, 0);
  vec_resize (conf->profiles, 0);
  return 1;
}

static clib_error_t *
capo_sw_interface_add_del (vnet_main_t *vnm, u32 sw_if_index, u32 is_add)
{
  clib_bihash_kv_8_32_t kv = { sw_if_index, { 0 } };
  capo_interface_config_t *conf = (capo_interface_config_t *) &kv.value;
  int __clib_unused rv = 0;

  if (is_add)
    return NULL;

  if (clib_bihash_search_8_32 (&capo_main.if_config, &kv, &kv) >= 0)
    {
      conf = (capo_interface_config_t *) &kv.value;
      vec_free (conf->rx_policies);
      vec_free (conf->tx_policies);
      vec_free (conf->profiles);
    }

#if CAPO_DEBUG > 0
  clib_warning ("unconfiguring policies for if %u deleted", sw_if_index);
#endif
  clib_bihash_add_del_8_32 (&capo_main.if_config, &kv, 0 /* is_add */);
  rv = capo_main.acl_plugin.wip_add_del_custom_access_io_policy (
    0 /* is_add */, sw_if_index, 0 /* is_input */
    ,
    capo_match_func);
#if CAPO_DEBUG > 0
  if (rv)
    clib_warning ("error deleting caiop (output): %d", rv);
#endif
  rv = capo_main.acl_plugin.wip_add_del_custom_access_io_policy (
    0 /* is_add */, sw_if_index, 1 /* is_input */
    ,
    capo_match_func);
#if CAPO_DEBUG > 0
  if (rv)
    clib_warning ("error deleting caiop (input): %d", rv);
#endif
  return NULL;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (capo_sw_interface_add_del);

u8 *
format_capo_interface (u8 *s, va_list *args)
{
  u32 sw_if_index = va_arg (*args, u32);
  capo_interface_config_t *conf = va_arg (*args, capo_interface_config_t *);
  vnet_main_t *vnm = vnet_get_main ();
  capo_policy_t *policy = NULL;
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
    s = format (s, "  rx:\n");
  vec_foreach_index (i, rx_policies)
    {
      policy = capo_policy_get_if_exists (rx_policies[i]);
      s = format (s, "    %U", format_capo_policy, policy, 4 /* indent */,
		  CAPO_POLICY_ONLY_RX, conf->invert_rx_tx);
    }
  if (vec_len (tx_policies))
    s = format (s, "  tx:\n");
  vec_foreach_index (i, tx_policies)
    {
      policy = capo_policy_get_if_exists (tx_policies[i]);
      s = format (s, "    %U", format_capo_policy, policy, 4 /* indent */,
		  CAPO_POLICY_ONLY_TX, conf->invert_rx_tx);
    }
  if (vec_len (conf->profiles))
    s = format (s, "  profiles:\n");
  vec_foreach_index (i, conf->profiles)
    {
      policy = capo_policy_get_if_exists (conf->profiles[i]);
      s = format (s, "    %U", format_capo_policy, policy, 4 /* indent */,
		  CAPO_POLICY_VERBOSE, conf->invert_rx_tx);
    }
  return s;
}

int
print_capo_interface (clib_bihash_kv_8_32_t *kv, void *arg)
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
  clib_bihash_foreach_key_value_pair_8_32 (&capo_main.if_config,
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

  rv = capo_configure_policies (sw_if_index, 0, 0, 0, NULL, 0, 0, 0);
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
  u32 num_rx_policies = 0;
  u32 num_tx_policies = 0;
  u32 policy_id;
  u32 *policy_list = NULL;
  u8 invert_rx_tx = 0;
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
      else if (unformat (line_input, "rx %d", &num_rx_policies))
	;
      else if (unformat (line_input, "tx %d", &num_tx_policies))
	;
      else if (unformat (line_input, "invert"))
	invert_rx_tx = 1;
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

  rv = capo_configure_policies (sw_if_index, num_rx_policies, num_tx_policies,
				vec_len (policy_list) - num_rx_policies -
				  num_tx_policies,
				policy_list, invert_rx_tx, 1, 1);

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
  .short_help = "capo interface configure [interface | sw_if_index N] rx "
		"<num_rx> tx <num_tx> <policy_id> ...",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
