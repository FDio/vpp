/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <sfdp_services/base/classifier_input/classifier_input.h>
#include <vnet/classify/vnet_classify.h>

static clib_error_t *
sfdp_classifier_input_set_table_fn (vlib_main_t *vm, unformat_input_t *input,
				    vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  u32 table_index = ~0;
  u8 is_del = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "Expected arguments");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "table %d", &table_index))
	;
      else if (unformat (line_input, "del"))
	is_del = 1;
      else
	{
	  err = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (!is_del && table_index == ~0)
    {
      err = clib_error_return (0, "Table index is required");
      goto done;
    }

  int rv = sfdp_classifier_input_set_table (table_index, is_del);

  if (rv)
    err = clib_error_return (0, "Failed to set classifier table");

done:
  unformat_free (line_input);
  return err;
}

VLIB_CLI_COMMAND (sfdp_classifier_input_set_table_cmd, static) = {
  .path = "set sfdp classifier-input",
  .short_help = "set sfdp classifier-input table <table-index> [del]",
  .function = sfdp_classifier_input_set_table_fn,
};

static clib_error_t *
sfdp_classifier_input_add_del_session_fn (vlib_main_t *vm, unformat_input_t *input,
					  vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  vnet_classify_main_t *vcm = &vnet_classify_main;
  sfdp_classifier_input_main_t *scim = &sfdp_classifier_input_main;
  clib_error_t *err = 0;
  u32 tenant_id = ~0;
  u8 *match = 0;
  u8 is_del = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "Expected arguments");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "tenant %d", &tenant_id))
	;
      else if (unformat (line_input, "del"))
	is_del = 1;
      else if (unformat (line_input, "match %U", unformat_classify_match, vcm, &match,
			 scim->classify_table_index))
	;
      else
	{
	  err = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (tenant_id == ~0)
    {
      err = clib_error_return (0, "Tenant ID is required");
      goto done;
    }

  if (vec_len (match) == 0)
    {
      err = clib_error_return (0, "Match is required");
      goto done;
    }

  int rv = sfdp_classifier_input_add_del_session (tenant_id, match, vec_len (match), is_del);
  if (rv)
    err = clib_error_return (0, "Failed to add/del session");

done:
  vec_free (match);
  unformat_free (line_input);
  return err;
}

VLIB_CLI_COMMAND (sfdp_classifier_input_add_del_session_cmd, static) = {
  .path = "sfdp classifier-input session",
  .short_help = "sfdp classifier-input session tenant <tenant-id> match <match> [del]",
  .function = sfdp_classifier_input_add_del_session_fn,
};

static clib_error_t *
sfdp_classifier_input_enable_disable_fn (vlib_main_t *vm, unformat_input_t *input,
					 vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  u32 sw_if_index = ~0;
  u8 is_disable = 0;
  u8 is_ip6 = 0;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "Expected arguments");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_sw_interface, vnet_get_main (), &sw_if_index))
	;
      else if (unformat (line_input, "disable"))
	is_disable = 1;
      else if (unformat (line_input, "ip6"))
	is_ip6 = 1;
      else if (unformat (line_input, "ip4"))
	is_ip6 = 0;
      else
	{
	  err = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (sw_if_index == ~0)
    {
      err = clib_error_return (0, "Interface is required");
      goto done;
    }

  rv = sfdp_classifier_input_enable_disable_interface (sw_if_index, !is_disable, is_ip6);

  if (rv)
    err =
      clib_error_return (0, "Failed to %s feature on interface", is_disable ? "disable" : "enable");

done:
  unformat_free (line_input);
  return err;
}

VLIB_CLI_COMMAND (sfdp_classifier_input_enable_disable_cmd, static) = {
  .path = "set sfdp classifier-input interface",
  .short_help = "set sfdp classifier-input interface <interface> [ip4|ip6] [disable]",
  .function = sfdp_classifier_input_enable_disable_fn,
};

static clib_error_t *
show_sfdp_classifier_input_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  CLIB_UNUSED (unformat_input_t * _input) = input;
  CLIB_UNUSED (vlib_cli_command_t * _cmd) = cmd;
  sfdp_classifier_input_main_t *scim = &sfdp_classifier_input_main;
  vnet_classify_main_t *vcm = &vnet_classify_main;

  vlib_cli_output (vm, "SFDP Classifier Input Configuration:");

  if (scim->classify_table_index == ~0)
    {
      vlib_cli_output (vm, "  Classifier table: not configured");
    }
  else
    {
      vnet_classify_table_t *t = pool_elt_at_index (vcm->tables, scim->classify_table_index);
      vlib_cli_output (vm, "  Classifier table: %d", scim->classify_table_index);
      vlib_cli_output (vm, "    skip_n_vectors: %d", t->skip_n_vectors);
      vlib_cli_output (vm, "    match_n_vectors: %d", t->match_n_vectors);
      vlib_cli_output (vm, "    active_elements: %d", t->active_elements);
    }

  return 0;
}

VLIB_CLI_COMMAND (show_sfdp_classifier_input_cmd, static) = {
  .path = "show sfdp classifier-input",
  .short_help = "show sfdp classifier-input",
  .function = show_sfdp_classifier_input_fn,
};
