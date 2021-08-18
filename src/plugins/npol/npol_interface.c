/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <npol/npol.h>
#include <npol/npol_match.h>
#include <npol/npol_policy.h>
#include <npol/npol_format.h>

uword unformat_sw_if_index (unformat_input_t *input, va_list *args);

npol_interface_config_t *npol_interface_configs;

int
npol_unconfigure_policies (u32 sw_if_index)
{
  npol_interface_config_t *conf;
  conf = vec_elt_at_index (npol_interface_configs, sw_if_index);
  if (!conf->enabled)
    return 0;

  conf = vec_elt_at_index (npol_interface_configs, sw_if_index);
  vec_free (conf->rx_policies);
  vec_free (conf->tx_policies);
  vec_free (conf->profiles);

  conf->enabled = 0;
  return 0;
}

int
npol_configure_policies (u32 sw_if_index, npol_interface_config_t *new_conf)
{
  npol_interface_config_t *conf;
  u32 *idx;

  if (!vnet_sw_interface_is_valid (vnet_get_main (), sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vec_validate_init_empty (npol_interface_configs, sw_if_index,
			   (npol_interface_config_t){ 0 });
  conf = vec_elt_at_index (npol_interface_configs, sw_if_index);

  vec_foreach (idx, new_conf->rx_policies)
    if (pool_is_free_index (npol_policies, *idx))
      goto error;
  vec_foreach (idx, new_conf->tx_policies)
    if (pool_is_free_index (npol_policies, *idx))
      goto error;
  vec_foreach (idx, new_conf->profiles)
    if (pool_is_free_index (npol_policies, *idx))
      goto error;

  if (conf->enabled)
    {
      vec_free (conf->rx_policies);
      vec_free (conf->tx_policies);
      vec_free (conf->profiles);
    }
  *conf = *new_conf;
  conf->enabled = 1;
  return 0;

error:
  vec_free (new_conf->rx_policies);
  vec_free (new_conf->tx_policies);
  vec_free (new_conf->profiles);
  return 1;
}

static clib_error_t *
npol_sw_interface_add_del (vnet_main_t *vnm, u32 sw_if_index, u32 is_add)
{
  int rv;
  if (is_add)
    vec_validate_init_empty (npol_interface_configs, sw_if_index,
			     (npol_interface_config_t){ 0 });
  else
    {
      rv = npol_unconfigure_policies (sw_if_index);
      if (rv)
	return clib_error_return (
	  0, "Error calling npol_unconfigure_policies %d", rv);
    }
  return NULL;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (npol_sw_interface_add_del);

static clib_error_t *
npol_interface_show_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  u32 sw_if_index;
  npol_interface_config_t *conf;
  vlib_cli_output (vm, "Interfaces with policies configured:");
  vec_foreach_index (sw_if_index, npol_interface_configs)
    {
      conf = &npol_interface_configs[sw_if_index];
      if (conf->enabled)
	{
	  vlib_cli_output (vm, "%U", format_npol_interface, sw_if_index, conf);
	}
    }
  return NULL;
}

VLIB_CLI_COMMAND (npol_policies_show_cmd, static) = {
  .path = "show npol interfaces",
  .function = npol_interface_show_cmd_fn,
  .short_help = "show npol interfaces",
};

static clib_error_t *
npol_interface_clear_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  u32 sw_if_index = NPOL_INVALID_INDEX;
  clib_error_t *error = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_sw_if_index, NULL, &sw_if_index))
	;
      else if (unformat (input, "sw_if_index %d", &sw_if_index))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  if (sw_if_index == NPOL_INVALID_INDEX)
    {
      error = clib_error_return (0, "interface not specified");
      goto done;
    }

  rv = npol_unconfigure_policies (sw_if_index);
  if (rv)
    error =
      clib_error_return (0, "npol_unconfigure_policies errored with %d", rv);
  else
    vlib_cli_output (vm, "npol interface %d cleared", sw_if_index);

done:
  return error;
}

VLIB_CLI_COMMAND (npol_interface_clear_cmd, static) = {
  .path = "npol interface clear",
  .function = npol_interface_clear_cmd_fn,
  .short_help = "npol interface clear [interface | sw_if_index N]",
};

static clib_error_t *
npol_interface_configure_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  npol_interface_config_t _conf = { 0 }, *conf = &_conf;
  clib_error_t *error = 0;
  u32 sw_if_index = NPOL_INVALID_INDEX;
  u32 tmp;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_sw_if_index, NULL, &sw_if_index))
	;
      else if (unformat (input, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (input, "rx %d", &tmp))
	vec_add1 (conf->rx_policies, tmp);
      else if (unformat (input, "tx %d", &tmp))
	vec_add1 (conf->tx_policies, tmp);
      else if (unformat (input, "profiles %d", &tmp))
	vec_add1 (conf->profiles, tmp);
      else if (unformat (input, "rx-policy-def %d", &tmp))
	conf->policy_default_rx = tmp;
      else if (unformat (input, "rx-profile-def %d", &tmp))
	conf->profile_default_rx = tmp;
      else if (unformat (input, "tx-policy-def %d", &tmp))
	conf->policy_default_tx = tmp;
      else if (unformat (input, "tx-profile-def %d", &tmp))
	conf->profile_default_tx = tmp;
      else if (unformat (input, "invert"))
	conf->invert_rx_tx = 1;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  if (sw_if_index == NPOL_INVALID_INDEX)
    {
      error = clib_error_return (0, "interface not specified");
      goto done;
    }

  rv = npol_configure_policies (sw_if_index, conf);
  if (rv)
    error =
      clib_error_return (0, "npol_configure_policies errored with %d", rv);
  else
    vlib_cli_output (vm, "npol interface %d configured", sw_if_index);

done:
  return error;
}

VLIB_CLI_COMMAND (npol_interface_configure_cmd, static) = {
  .path = "npol interface configure",
  .function = npol_interface_configure_cmd_fn,
  .short_help = "npol interface configure [interface | sw_if_index N] rx "
		"<num_rx> tx <num_tx> rx-policy-def <rx-policy-def> "
		"tx-policy-def <tx-policy-def> "
		"rx-profile-def <rx-profile-def> tx-profile-def "
		"<tx-profile-def> [invert] <policy_id> ...",
};
