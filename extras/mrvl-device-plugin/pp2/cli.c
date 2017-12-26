/*
 *------------------------------------------------------------------
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#include <vnet/ethernet/ethernet.h>

#include <pp2/pp2.h>

static clib_error_t *
mrvl_pp2_create_command_fn (vlib_main_t * vm, unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  mrvl_pp2_create_if_args_t args = { 0 };

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "name %s", &args.name))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);


  mrvl_pp2_create_if (&args);

  vec_free (args.name);

  return args.error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (mrvl_pp2_create_command, static) = {
  .path = "create interface ppv2",
  .short_help = "create interface ppv2 [name <ifname>]",
  .function = mrvl_pp2_create_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
mrvl_pp2_delete_command_fn (vlib_main_t * vm, unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  vnet_hw_interface_t *hw;
  mrvl_pp2_main_t *mm = &mrvl_pp2_main;
  mrvl_pp2_if_t *dif;
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
  if (hw == NULL || mrvl_pp2_device_class.index != hw->dev_class_index)
    return clib_error_return (0, "not a ppv2 interface");

  dif = pool_elt_at_index (mm->interfaces, hw->dev_instance);

  mrvl_pp2_delete_if (dif);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (mrvl_pp2_delete_command, static) = {
  .path = "delete ppv2",
  .short_help = "delete ppv2 {<interface> | sw_if_index <sw_idx>}",
  .function = mrvl_pp2_delete_command_fn,
};
/* *INDENT-ON* */


static clib_error_t *
mrvl_pp2_show_command_fn (vlib_main_t * vm, unformat_input_t * input,
			  vlib_cli_command_t * cmd)
{
  mrvl_pp2_if_t *dif;
  mrvl_pp2_main_t *dm = &mrvl_pp2_main;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u32 hw_if_index, *hw_if_indices = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "%U", unformat_vnet_hw_interface, vnm, &hw_if_index))
	vec_add1 (hw_if_indices, hw_if_index);
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  if (vec_len (hw_if_indices) == 0)
    {
      /* *INDENT-OFF* */
      pool_foreach (dif, dm->interfaces,
	  vec_add1 (hw_if_indices, dif->hw_if_index);
      );
      /* *INDENT-ON* */
    }

  for (hw_if_index = 0; hw_if_index < vec_len (hw_if_indices); hw_if_index++)
    {
      vnet_hw_interface_t *hi =
	vnet_get_hw_interface (vnm, hw_if_indices[hw_if_index]);
      dif = pool_elt_at_index (dm->interfaces, hi->dev_instance);
      vlib_cli_output (vm, "interface %U", format_vnet_sw_if_index_name,
		       vnm, dif->sw_if_index);
    }
done:
  vec_free (hw_if_indices);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (mrvl_pp2_show_command, static) = {
  .path = "show ppv2",
  .short_help = "show ppv2 {<interface>]",
  .function = mrvl_pp2_show_command_fn,
};
/* *INDENT-ON* */

clib_error_t *
mrvl_pp2_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (mrvl_pp2_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
