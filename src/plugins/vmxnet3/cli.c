/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */
#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>

#include <vmxnet3/vmxnet3.h>

static clib_error_t *
vmxnet3_create_command_fn (vlib_main_t * vm, unformat_input_t * input,
			   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vmxnet3_create_if_args_t args = { 0 };

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vlib_pci_addr, &args.addr))
	;
      else if (unformat (line_input, "elog"))
	args.enable_elog = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);


  vmxnet3_create_if (vm, &args);

  return args.error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vmxnet3_create_command, static) = {
  .path = "create interface vmxnet3",
  .short_help = "create interface vmxnet3 <pci-address>",
  .function = vmxnet3_create_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
vmxnet3_delete_command_fn (vlib_main_t * vm, unformat_input_t * input,
			   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  vnet_hw_interface_t *hw;
  vmxnet3_main_t *vmxm = &vmxnet3_main;
  vmxnet3_device_t *vd;
  vnet_main_t *vnm = vnet_get_main ();

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (line_input, "%U", unformat_vnet_sw_interface,
			 vnm, &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  if (sw_if_index == ~0)
    return clib_error_return (0,
			      "please specify interface name or sw_if_index");

  hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (hw == NULL || vmxnet3_device_class.index != hw->dev_class_index)
    return clib_error_return (0, "not a vmxnet3 interface");

  vd = pool_elt_at_index (vmxm->devices, hw->dev_instance);

  vmxnet3_delete_if (vm, vd);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vmxnet3_delete_command, static) = {
  .path = "delete interface vmxnet3",
  .short_help = "delete interface vmxnet3 "
    "{<interface> | sw_if_index <sw_idx>}",
  .function = vmxnet3_delete_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
vmxnet3_test_command_fn (vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  vnet_hw_interface_t *hw;
  vmxnet3_main_t *vmxm = &vmxnet3_main;
  vmxnet3_device_t *vd;
  vnet_main_t *vnm = vnet_get_main ();
  int enable_elog = 0, disable_elog = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (line_input, "elog-on"))
	enable_elog = 1;
      else if (unformat (line_input, "elog-off"))
	disable_elog = 1;
      else if (unformat (line_input, "%U", unformat_vnet_sw_interface,
			 vnm, &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  if (sw_if_index == ~0)
    return clib_error_return (0,
			      "please specify interface name or sw_if_index");

  hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (hw == NULL || vmxnet3_device_class.index != hw->dev_class_index)
    return clib_error_return (0, "not a vmxnet3 interface");

  vd = pool_elt_at_index (vmxm->devices, hw->dev_instance);

  if (enable_elog)
    vd->flags |= VMXNET3_DEVICE_F_ELOG;

  if (disable_elog)
    vd->flags &= ~VMXNET3_DEVICE_F_ELOG;

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vmxnet3_test_command, static) = {
  .path = "test vmxnet3",
  .short_help = "test vmxnet3 <interface> | sw_if_index <sw_idx>} [irq] "
    "[elog-on] [elog-off]",
  .function = vmxnet3_test_command_fn,
};
/* *INDENT-ON* */

static void
show_vmxnet3 (vlib_main_t * vm, u32 * hw_if_indices)
{
  int i;
  vmxnet3_device_t *vd;
  vnet_main_t *vnm = &vnet_main;
  vmxnet3_main_t *vmxm = &vmxnet3_main;
  vnet_hw_interface_t *hi;

  if (!hw_if_indices)
    return;

  for (i = 0; i < vec_len (hw_if_indices); i++)
    {
      hi = vnet_get_hw_interface (vnm, hw_if_indices[i]);
      vd = vec_elt_at_index (vmxm->devices, hi->dev_instance);
      vlib_cli_output (vm, "Interface: %s (ifindex %d)",
		       hi->name, hw_if_indices[i]);
      vlib_cli_output (vm, "  Version: %u", vd->version);
      vlib_cli_output (vm, "  Number of interrupts: %u", vd->num_intrs);
      vlib_cli_output (vm, "  Mac Address: %U", format_ethernet_address,
		       vd->mac_addr);
      vlib_cli_output (vm, "  sw if index: %u", vd->sw_if_index);
      vlib_cli_output (vm, "  hw if index: %u", vd->hw_if_index);
      vlib_cli_output (vm, "  Device instance: %u", vd->dev_instance);
    }
}

static clib_error_t *
show_vmxnet3_fn (vlib_main_t * vm, unformat_input_t * input,
		 vlib_cli_command_t * cmd)
{
  vmxnet3_main_t *vmxm = &vmxnet3_main;
  vnet_main_t *vnm = &vnet_main;
  vmxnet3_device_t *vd;
  clib_error_t *error = 0;
  u32 hw_if_index, *hw_if_indices = 0;
  vnet_hw_interface_t *hi;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "%U", unformat_vnet_hw_interface, vnm, &hw_if_index))
	{
	  hi = vnet_get_hw_interface (vnm, hw_if_index);
	  if (vmxnet3_device_class.index != hi->dev_class_index)
	    {
	      error = clib_error_return (0, "unknown input `%U'",
					 format_unformat_error, input);
	      goto done;
	    }
	  vec_add1 (hw_if_indices, hw_if_index);
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  if (vec_len (hw_if_indices) == 0)
    {
      pool_foreach (vd, vmxm->devices,
		    vec_add1 (hw_if_indices, vd->hw_if_index);
		    );
    }

  show_vmxnet3 (vm, hw_if_indices);

done:
  vec_free (hw_if_indices);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_vmxnet3_command, static) = {
  .path = "show vmxnet3",
  .short_help = "show vmxnet3 [<interface>]",
  .function = show_vmxnet3_fn,
};
/* *INDENT-ON* */

clib_error_t *
vmxnet3_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (vmxnet3_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
