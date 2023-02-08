/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>

#include <ena/ena.h>
#include <ena/ena_inlines.h>

static clib_error_t *
ena_create_command_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  ena_create_if_args_t args = {};
  u32 tmp;
  clib_error_t *err;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vlib_pci_addr, &args.addr))
	;
      else if (unformat (input, "rx-queue-size %u", &tmp))
	args.rxq_size = tmp;
      else if (unformat (input, "tx-queue-size %u", &tmp))
	args.txq_size = tmp;
      else if (unformat (input, "num-rx-queues %u", &tmp))
	args.rxq_num = tmp;
      else if (unformat (input, "num-tx-queues %u", &tmp))
	args.txq_num = tmp;
      else if (unformat (input, "name %s", &args.name))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  err = ena_create_if (vm, &args);

  vec_free (args.name);

  return err;
}

VLIB_CLI_COMMAND (ena_create_command, static) = {
  .path = "create interface ena",
  .short_help = "create interface ena <pci-address> "
		"[rx-queue-size <size>] [tx-queue-size <size>] "
		"[num-rx-queues <size>]",
  .function = ena_create_command_fn,
};

static clib_error_t *
ena_delete_command_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  u32 sw_if_index = ~0;
  vnet_hw_interface_t *hw;
  vnet_main_t *vnm = vnet_get_main ();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (input, "%U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (sw_if_index == ~0)
    return clib_error_return (0,
			      "please specify interface name or sw_if_index");

  hw = vnet_get_sup_hw_interface_api_visible_or_null (vnm, sw_if_index);
  if (hw == NULL || ena_device_class.index != hw->dev_class_index)
    return clib_error_return (0, "not an ENA interface");

  ena_delete_if (vm, hw->dev_instance);

  return 0;
}

VLIB_CLI_COMMAND (ena_delete_command, static) = {
  .path = "delete interface ena",
  .short_help = "delete interface ena "
		"{<interface> | sw_if_index <sw_idx>}",
  .function = ena_delete_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
ena_reset_command_fn (vlib_main_t *vm, unformat_input_t *input,
		      vlib_cli_command_t *cmd)
{
  u32 sw_if_index = ~0;
  vnet_hw_interface_t *hw;
  vnet_main_t *vnm = vnet_get_main ();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (input, "%U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (sw_if_index == ~0)
    return clib_error_return (0,
			      "please specify interface name or sw_if_index");

  hw = vnet_get_sup_hw_interface_api_visible_or_null (vnm, sw_if_index);
  if (hw == NULL || ena_device_class.index != hw->dev_class_index)
    return clib_error_return (0, "not an ENA interface");

  ena_reset_if (vm, hw->dev_instance);

  return 0;
}

VLIB_CLI_COMMAND (ena_reset_command, static) = {
  .path = "reset interface ena",
  .short_help = "reset interface ena "
		"{<interface> | sw_if_index <sw_idx>}",
  .function = ena_reset_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
ena_test_get_features_command_fn (vlib_main_t *vm, unformat_input_t *input,
				  vlib_cli_command_t *cmd)
{
  clib_error_t *err;
  u32 sw_if_index = ~0;
  vnet_hw_interface_t *hw;
  ena_device_t *ed;
  vnet_main_t *vnm = vnet_get_main ();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (input, "%U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (sw_if_index == ~0)
    return clib_error_return (0,
			      "please specify interface name or sw_if_index");

  hw = vnet_get_sup_hw_interface_api_visible_or_null (vnm, sw_if_index);
  if (hw == NULL || ena_device_class.index != hw->dev_class_index)
    return clib_error_return (0, "not a ENA interface");

  ed = ena_get_device (hw->dev_instance);

  struct
  {
    u8 sz;
    u8 get;
  } feat_data[] = {
#define _(v, ver, gt, st, n, s) [v] = { .sz = sizeof (s), .get = (gt) },
    foreach_ena_admin_feature_id
#undef _
  };
  u32 i;
  foreach_set_bit_index (i, ed->dev_attr.supported_features)
    {
      u8 buffer[feat_data[i].sz];
      if (feat_data[i].get == 0)
	continue;
      if (feat_data[i].sz < 2)
	{
	  vlib_cli_output (vm, "Skipping %U....", format_ena_admin_feat_name,
			   i);

	  continue;
	}
      if ((err = ena_admin_get_feature (vm, ed, i, buffer)))
	return err;

      vlib_cli_output (vm, "%U\n  %U\n", format_ena_admin_feat_name, i,
		       format_ena_admin_feat_desc, i, buffer);
    }

  return 0;
}

VLIB_CLI_COMMAND (ena_test_get_features_command, static) = {
  .path = "test ena get-features",
  .short_help = "test ena get-features [<interface> | sw_if_index <sw_idx>]",
  .function = ena_test_get_features_command_fn,
};

clib_error_t *
ena_cli_init (vlib_main_t *vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (ena_cli_init);
