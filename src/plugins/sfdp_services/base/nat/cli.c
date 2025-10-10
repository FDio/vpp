/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <sfdp_services/base/nat/nat.h>

static clib_error_t *
sfdp_nat_external_interface_set_unset_fn (vlib_main_t *vm,
					  unformat_input_t *input,
					  vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;

  clib_error_t *err = 0;
  u32 sw_if_index = ~0;
  u32 tenant_id = ~0;
  u8 unset = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "tenant %d", &tenant_id))
	;
      else if (unformat (line_input, "disable"))
	unset = 1;
      else if (unformat (line_input, "%U", unformat_vnet_sw_interface,
			 vnet_get_main (), &sw_if_index))
	;
      else
	{
	  err = unformat_parse_error (line_input);
	  goto done;
	}
    }
  err = nat_external_interface_set_tenant (&nat_main, sw_if_index, tenant_id,
					   unset);
done:
  unformat_free (line_input);
  return err;
}

VLIB_CLI_COMMAND (sfdp_nat_external_interface_set_unset, static) = {
  .path = "set sfdp nat external-interface",
  .short_help =
    "set sfdp nat external-interface <interface> tenant <tenant-id> [disable]",
  .function = sfdp_nat_external_interface_set_unset_fn,
};

static clib_error_t *
sfdp_nat_alloc_pool_add_del_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;

  clib_error_t *err = 0;
  u8 is_del = 0;
  u32 alloc_pool_id = ~0;
  ip4_address_t tmp;
  ip4_address_t *addr = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add %d", &alloc_pool_id))
	is_del = 0;
      else if (unformat (line_input, "del %d", &alloc_pool_id))
	is_del = 1;
      else if (unformat (line_input, "%U", unformat_ip4_address, &tmp))
	vec_add1 (addr, tmp);
      else
	{
	  err = unformat_parse_error (line_input);
	  goto done;
	}
    }
  nat_alloc_pool_add_del (&nat_main, alloc_pool_id, is_del, addr);
done:
  unformat_free (line_input);
  vec_free (addr);
  return err;
}

VLIB_CLI_COMMAND (sfdp_nat_alloc_pool_add_del, static) = {
  .path = "sfdp nat alloc-pool",
  .short_help = "sfdp nat alloc-pool [add|del] <alloc-pool-id> <ip-addr>+",
  .function = sfdp_nat_alloc_pool_add_del_fn,
};

static clib_error_t *
sfdp_nat_snat_set_unset_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;

  clib_error_t *err = 0;
  u32 tenant_id = ~0;
  u32 outside_tenant_id = ~0;
  u32 table_id = ~0;
  u32 alloc_pool_id = ~0;
  u8 unset = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "tenant %d", &tenant_id))
	;
      else if (unformat (line_input, "outside-tenant %d", &outside_tenant_id))
	;
      else if (unformat (line_input, "table %d", &table_id))
	;
      else if (unformat (line_input, "alloc-pool %d", &alloc_pool_id))
	;
      else if (unformat (line_input, "disable"))
	unset = 1;
      else
	{
	  err = unformat_parse_error (line_input);
	  goto done;
	}
    }
  err = nat_tenant_set_snat (&nat_main, tenant_id, outside_tenant_id, table_id,
			     alloc_pool_id, unset);
done:
  unformat_free (line_input);
  return err;
}

VLIB_CLI_COMMAND (sfdp_nat_snat_set_unset, static) = {
  .path = "set sfdp nat snat",
  .short_help =
    "set sfdp nat snat tenant <tenant-id> outside-tenant <tenant-id> table "
    "<table-id> alloc-pool <alloc-pool-id> [disable]",
  .function = sfdp_nat_snat_set_unset_fn,
};